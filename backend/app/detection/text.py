"""Analysis of SMS, WhatsApp and other submitted text: scam patterns, extraction, redaction.

English only for now. Ghanaian Pidgin and local languages need a properly labelled evaluation
set before we claim to understand them (see docs/detection.md).
"""

import hashlib
import re
from dataclasses import dataclass, field

from app.detection.brands import Brand, mentioned_brands
from app.detection.signals import Signal, info
from app.detection.urls import extract_urls

# --- Redaction ---------------------------------------------------------------------------------

_CODE_NEAR_WORD = re.compile(
    r"(?i)((?:otp|one[- ]time|verification|security|secret|confirmation|access|auth\w*|pin|"
    r"passcode|password|code)\D{0,25}?)(\b\d{4,8}\b)"
)
_WORD_AFTER_CODE = re.compile(
    r"(?i)(\b\d{4,8}\b)(\s*(?:is|as)\s+(?:your|the)\s+(?:otp|code|pin|verification))"
)
_PASSWORD_VALUE = re.compile(r"(?i)\b(password|passcode|pwd|pin)\s*[:=]\s*\S+")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def redact(text: str) -> tuple[str, list[str]]:
    """Remove OTPs, PINs, passwords and card numbers before anything is stored."""
    removed: list[str] = []

    def card(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            removed.append("card_number")
            return "[card number removed]"
        return m.group(0)

    out = _CARD.sub(card, text)
    if _PASSWORD_VALUE.search(out):
        removed.append("password")
        out = _PASSWORD_VALUE.sub(lambda m: f"{m.group(1)}: [removed]", out)
    if _CODE_NEAR_WORD.search(out) or _WORD_AFTER_CODE.search(out):
        removed.append("one_time_code")
        out = _CODE_NEAR_WORD.sub(lambda m: m.group(1) + "[code removed]", out)
        out = _WORD_AFTER_CODE.sub(lambda m: "[code removed]" + m.group(2), out)
    return out, sorted(set(removed))


# --- Extraction ----------------------------------------------------------------------------------

_PHONE = re.compile(r"(?<![\d+])(?:\+?233[\s-]?|0)(?:[235]\d)[\s-]?\d{3}[\s-]?\d{4}(?!\d)")
_SHORTCODE = re.compile(r"\*\d{2,4}(?:\*\d+)*#")
_AMOUNT = re.compile(
    r"(?i)(?:gh[s₵¢c]|ghc|cedis?|₵)\s?\d[\d,]*(?:\.\d{1,2})?|\d[\d,]*(?:\.\d{1,2})?\s?"
    r"(?:gh[s₵¢c]|cedis?)\b"
)
_TXN_ID = re.compile(
    r"(?i)\b(?:transaction|txn|trans|ref(?:erence)?)\s*(?:id|no\.?|number)?"
    r"\s*[:#]?\s*([A-Z0-9]{6,20})\b"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def normalise_phone(raw: str) -> str | None:
    digits = re.sub(r"\D", "", raw)
    if digits.startswith("233") and len(digits) == 12:
        return "+" + digits
    if digits.startswith("0") and len(digits) == 10:
        return "+233" + digits[1:]
    return None


def phone_hash(e164: str) -> str:
    return hashlib.sha256(("phone:" + e164).encode()).hexdigest()


def mask_phone(e164: str) -> str:
    local = "0" + e164[4:] if e164.startswith("+233") else e164
    return f"{local[:3]} *** {local[-4:]}"


@dataclass
class Extracted:
    urls: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)  # E.164
    shortcodes: list[str] = field(default_factory=list)
    amounts: list[str] = field(default_factory=list)
    transaction_ids: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)


def extract(text: str) -> Extracted:
    phones = []
    for m in _PHONE.finditer(text):
        e164 = normalise_phone(m.group(0))
        if e164 and e164 not in phones:
            phones.append(e164)
    return Extracted(
        urls=extract_urls(text),
        phones=phones[:10],
        shortcodes=sorted(set(_SHORTCODE.findall(text)))[:5],
        amounts=[a.strip() for a in _AMOUNT.findall(text)][:5],
        transaction_ids=sorted(set(_TXN_ID.findall(text)))[:5],
        emails=sorted(set(_EMAIL.findall(text)))[:5],
    )


# --- Scam pattern rules ----------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    code: str
    pattern: re.Pattern
    title: str
    description: str
    weight: int
    category: str | None = None


def _r(expr: str) -> re.Pattern:
    return re.compile(expr, re.IGNORECASE | re.DOTALL)


RULES: tuple[Rule, ...] = (
    Rule(
        "credential_request",
        _r(
            r"\b(send|share|give|tell|provide|enter|confirm|forward|reply\s+with|type)\b.{0,40}"
            r"\b(pin|otp|one[- ]time (pass|code)|verification code|password|secret code|"
            r"code (we|i) (sent|send)|code sent|cvv|card (number|details)|security code)"
        ),
        "Asks for your PIN, OTP or password",
        "Genuine banks, mobile money services and companies never ask you to send your PIN, "
        "one-time code or password by message or call. This is the single most common sign of "
        "a scam.",
        60,
        "social_engineering",
    ),
    Rule(
        "seed_phrase_request",
        _r(r"\b(seed|recovery|secret|backup)\s+(phrase|words)\b|\b12[- ]word\b|\bprivate key\b"),
        "Asks for a crypto wallet recovery phrase",
        "Anyone with your recovery phrase or private key can empty your wallet. No genuine "
        "exchange or support team will ever ask for it.",
        75,
        "crypto",
    ),
    Rule(
        "momo_reversal",
        _r(
            r"\b(sent|transferred|paid|deposited)\b.{0,40}\b(by mistake|mistakenly|wrongly|"
            r"in error|wrong number)\b|\brevers(e|al)\b.{0,40}\b(money|transaction|transfer|"
            r"payment|cash)\b|\brefund\b.{0,20}\b(the|my|it|back)\b"
        ),
        '"Money sent by mistake" or reversal story',
        "A classic mobile money scam: someone claims they sent you money by mistake and asks "
        "you to send it back, or a fake 'reversal' message tries to get your PIN. Check your "
        "actual balance in your MoMo menu or app, never through a link or a number in the "
        "message.",
        45,
        "momo",
    ),
    Rule(
        "approve_prompt",
        _r(
            r"dial\s*\*\d{2,4}[*#\d]*.{0,60}\b(pin|approve|confirm|receive|claim)\b|"
            r"\b(approve|authori[sz]e|accept)\b.{0,30}\b(transaction|payment|prompt|request)\b|"
            r"\benter (your )?(momo |mobile money )?pin\b.{0,30}\b(receive|claim|confirm|accept|"
            r"approve|reverse)\b"
        ),
        "Tells you to approve a payment prompt or dial a code",
        "Approving a payment prompt or entering your PIN sends money out of your wallet; you "
        "never need your PIN to receive money.",
        50,
        "momo",
    ),
    Rule(
        "account_threat",
        _r(
            r"\b(account|wallet|sim|line|number|card|momo)\b.{0,40}\b(suspend\w*|block\w*|"
            r"deactivat\w*|clos(e|ed|ure)|terminat\w*|restrict\w*|frozen|freez\w*|locked|"
            r"disabled|barred)\b"
        ),
        "Threatens to block or close your account",
        "Scammers create fear that your account, SIM or wallet will be blocked so you act "
        "without thinking.",
        30,
    ),
    Rule(
        "urgency",
        _r(
            r"\b(within|in)\s+\d+\s*(hours?|hrs?|minutes?|mins?)\b|\bimmediately\b|\burgent(ly)?\b|"
            r"\basap\b|\bfinal (notice|warning|reminder)\b|\blast chance\b|\btoday only\b|"
            r"\bexpires? (today|soon|tonight)\b|\bact now\b"
        ),
        "Pressures you to act quickly",
        "Deadlines and urgent language are used to stop you from checking whether a message is "
        "real.",
        20,
    ),
    Rule(
        "prize",
        _r(
            r"\byou (have |'ve )?won\b|\bwinner\b|\bcongratulations?\b.{0,40}\b(won|selected|"
            r"chosen|winner)\b|\blucky (draw|winner|customer)\b|\bclaim (your )?(prize|reward|"
            r"gift|bonus|cash)\b|\bpromo(tion)? winner\b"
        ),
        "Says you won a prize or reward",
        "Unexpected prizes, promotions and rewards — especially ones you must 'claim' or pay to "
        "receive — are a common scam.",
        40,
        "prize",
    ),
    Rule(
        "fee_request",
        _r(
            r"\b(registration|processing|clearance|customs|delivery|release|activation|"
            r"application|admission|acceptance|transfer|unlock(ing)?|verification|insurance|"
            r"handling)\s+(fee|charge|levy|cost)s?\b"
        ),
        "Asks you to pay a fee first",
        "Being asked to pay a 'processing', 'customs', 'registration' or 'release' fee before "
        "you get a job, parcel, loan or prize is a hallmark of advance-fee fraud.",
        35,
        "advance_fee",
    ),
    Rule(
        "delivery_problem",
        _r(
            r"\b(parcel|package|shipment|delivery|courier|consignment|item)\b.{0,60}\b(pending|"
            r"held|on hold|failed|unsuccessful|reschedul\w*|customs|incomplete address|"
            r"could not be delivered|awaiting)\b"
        ),
        "Claims there is a problem with a delivery",
        "Fake delivery messages ask you to pay a small fee or 'confirm your address' through a "
        "link. Check with the courier through its official app or website instead.",
        30,
        "delivery",
    ),
    Rule(
        "job_offer",
        _r(
            r"\b(job|vacancy|vacancies|recruit\w*|employment|hiring|work from home|part[- ]time|"
            r"online job|data entry)\b.{0,80}\b(offer|earn|salary|daily|per day|weekly pay|apply|"
            r"commission)\b"
        ),
        "Unsolicited job offer",
        "Job offers you didn't apply for — especially with high pay for little work, or that "
        "need a registration fee — are often recruitment scams.",
        20,
        "recruitment",
    ),
    Rule(
        "investment_promise",
        _r(
            r"\b(guaranteed|double|triple|multiply)\b.{0,30}\b(returns?|profits?|money|"
            r"investment|income)\b|\b\d{2,4}\s?%\s*(profit|returns?|interest|roi)\b|"
            r"\brisk[- ]free\b.{0,20}\b(investment|trading|profit)\b"
        ),
        "Promises guaranteed or very high returns",
        "No real investment can guarantee high returns. Promises to double your money are "
        "typical of investment and Ponzi scams.",
        45,
        "investment",
    ),
    Rule(
        "crypto_mention",
        _r(
            r"\b(usdt|bitcoin|btc|ethereum|crypto(currency)?|airdrop|giveaway|binance|"
            r"trust ?wallet|metamask)\b"
        ),
        "Mentions cryptocurrency",
        "Cryptocurrency payments are hard to trace or reverse, so scammers prefer them.",
        10,
        "crypto",
    ),
    Rule(
        "government_payment",
        _r(
            r"\b(gra|ssnit|dvla|nia|ghana card|ecg|immigration|ghana police|court|customs)\b"
            r".{0,80}\b(fine|penalty|arrest|pay(ment)?|tax|levy|arrears|outstanding|warrant|"
            r"refund|update)\b"
        ),
        "Claims to be a government agency asking for payment or details",
        "Government agencies don't demand payment or personal details through SMS links or "
        "WhatsApp. Use the agency's official website or office.",
        35,
        "government",
    ),
    Rule(
        "university_fee",
        _r(
            r"\b(admission|scholarship|bursary|school fees?|acceptance fee|study abroad|"
            r"student loan)\b.{0,80}\b(pay|fee|deadline|confirm|secure|guarantee\w*)\b"
        ),
        "Admission or scholarship with a payment request",
        "Fake admission and scholarship offers ask for 'acceptance' or 'processing' fees. "
        "Confirm directly with the school through its official website.",
        30,
        "university",
    ),
    Rule(
        "emergency_money",
        _r(
            r"\b(stuck|stranded|hospital|accident|emergency|detained|arrested|sick)\b.{0,80}"
            r"\b(send|transfer|momo|money|cash|help me)\b"
        ),
        "Emergency story asking for money",
        "Messages claiming a friend, relative or partner is in trouble and needs money urgently "
        "are a common scam. Call the person on a number you already know.",
        40,
        "romance",
    ),
    Rule(
        "secrecy",
        _r(
            r"\b(don'?t|do not)\s+tell\s+(anyone|anybody|your)\b|\bkeep (this|it) (secret|"
            r"confidential|between us)\b|\bbetween (us|you and me)\b"
        ),
        "Asks you to keep it secret",
        "Being told not to tell anyone is a manipulation tactic to stop you from getting advice.",
        25,
    ),
    Rule(
        "pay_to_number",
        _r(
            r"\b(send|pay|transfer|momo)\b.{0,30}\b(to|via|on)\b.{0,15}\b(this|the|my|our)?\s*"
            r"(momo|mobile money|number|account|wallet)\b"
        ),
        "Asks you to send money to a number or account",
        "Paying a personal mobile money number or account because a message told you to is "
        "how most of these scams end.",
        25,
    ),
    Rule(
        "verify_details",
        _r(
            r"\b(verify|update|confirm|validate|re-?activate|unlock)\b.{0,30}\b(your )?(account|"
            r"details|information|identity|kyc|bvn|ghana card|sim)\b"
        ),
        "Asks you to verify or update your details",
        "Requests to 'verify' or 'update' account details through a link are how phishing "
        "pages collect passwords and PINs.",
        25,
    ),
    Rule(
        "romance_terms",
        _r(r"\b(my dear|my love|sweetheart|darling|honey)\b"),
        "Uses affectionate language from someone you may not know",
        "Romance scammers build trust over time before asking for money.",
        10,
        "romance",
    ),
)

_GENUINE_OTP = re.compile(
    r"(?i)\b(do not|don'?t|never)\s+(share|disclose|give)\b.{0,40}\b(code|otp|pin|anyone)\b"
)


@dataclass
class TextAnalysis:
    signals: list[Signal]
    extracted: Extracted
    brands: list[Brand]
    redacted_text: str
    removed: list[str]


def analyse_text(
    text: str, brands: list[Brand] | tuple[Brand, ...], *, sender: str | None = None
) -> TextAnalysis:
    redacted, removed = redact(text)
    lowered = text.lower()
    signals: list[Signal] = []
    looks_like_genuine_otp = bool(_GENUINE_OTP.search(lowered))
    for rule in RULES:
        match = rule.pattern.search(lowered)
        if not match:
            continue
        if rule.code == "credential_request" and looks_like_genuine_otp:
            # "Your code is 1234. Do not share it with anyone" is how real one-time codes look.
            continue
        snippet = redact(text[max(0, match.start() - 10) : match.end() + 10])[0].strip()
        signals.append(
            Signal(
                "message",
                rule.code,
                rule.title,
                rule.description,
                rule.weight,
                category=rule.category,
                data={"matched": snippet[:120]},
            )
        )

    named = mentioned_brands(text, brands)
    extracted = extract(text)
    if named and sender:
        sender_clean = sender.strip()
        e164 = normalise_phone(sender_clean)
        official_ids = {s.lower() for b in named for s in b.sender_ids}
        if e164:
            signals.append(
                Signal(
                    "message",
                    "brand_from_personal_number",
                    f"Claims to be {named[0].name} but came from a personal number",
                    f"The message mentions {named[0].name}, but it was sent from an ordinary "
                    f"phone number ({mask_phone(e164)}). Official alerts come from registered "
                    "sender names, not personal numbers.",
                    40,
                    category=named[0].category,
                    data={"brand": named[0].name},
                )
            )
        elif official_ids and sender_clean.lower() not in official_ids:
            signals.append(
                Signal(
                    "message",
                    "unrecognised_sender_id",
                    "Sender name doesn't match the organisation it mentions",
                    f"It was sent as '{sender_clean[:40]}', which isn't a sender name we know "
                    f"{named[0].name} uses. Sender names can also be faked, so this is not "
                    "proof either way.",
                    15,
                    category=named[0].category,
                )
            )
    if looks_like_genuine_otp and not extracted.urls:
        signals.append(
            info(
                "message",
                "otp_message",
                "Looks like a normal one-time code message",
                "It warns you not to share the code, which is how genuine one-time code "
                "messages are written. Only use the code if you started the action yourself.",
            )
        )
    if extracted.shortcodes:
        signals.append(
            info(
                "message",
                "ussd_code",
                "Contains a dial code",
                f"The message includes {', '.join(extracted.shortcodes)}. Only dial codes you "
                "already know from your network's official menu.",
                codes=extracted.shortcodes,
            )
        )
    return TextAnalysis(signals, extracted, named, redacted, removed)
