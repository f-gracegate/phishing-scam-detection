"""Turn signals into a 0-100 risk score, a verdict, a confidence level and advice.

The score is an assessment, not a probability. It combines signals with diminishing returns:
each additional signal closes part of the remaining gap to 100, and further signals from the
same layer count for less (urgency and threats in one message are not independent evidence).

Two rules matter more than the arithmetic:

* A verified malicious indicator puts the result at critical, whatever else is seen.
* No warning signs is **not** "safe". Without positive evidence (such as a brand's own official
  domain) a quiet result is reported as "unknown / insufficient evidence".
"""

from collections import defaultdict
from dataclasses import dataclass

from app.detection.signals import Signal

BANDS = (
    (90, "critical", "Critical risk"),
    (70, "high", "High risk"),
    (40, "suspicious", "Suspicious"),
    (20, "caution", "Caution"),
    (0, "low", "Low risk"),
)

VERDICT_LABELS = {code: label for _, code, label in BANDS} | {"unknown": "Unknown"}


@dataclass
class Assessment:
    score: int
    verdict: str
    confidence: str
    headline: str
    summary: str
    category: str | None
    recommendations: list[str]


def combine(signals: list[Signal]) -> int:
    risky = sorted((s for s in signals if s.weight > 0), key=lambda s: -s.weight)
    remaining = 1.0
    seen_per_layer: dict[str, int] = defaultdict(int)
    for s in risky:
        n = seen_per_layer[s.layer]
        factor = 1.0 if n == 0 else (0.6 if n == 1 else 0.35)
        remaining *= 1 - min(s.weight, 99) / 100 * factor
        seen_per_layer[s.layer] += 1
    score = round((1 - remaining) * 100)
    if any(s.source_kind == "verified_intel" and s.weight >= 90 for s in signals):
        score = max(score, 92)
    elif any(s.source_kind == "external_provider" and s.weight >= 80 for s in signals):
        score = max(score, 85)
    if any(s.code == "official_domain" for s in signals) and not any(
        s.source_kind in {"verified_intel", "external_provider"} for s in risky
    ):
        # The brand's own domain: residual risk only (a compromised page is still possible).
        score = min(score, 25)
    return max(0, min(100, score))


def _confidence(signals: list[Signal], score: int) -> str:
    risky = [s for s in signals if s.weight > 0]
    layers = {s.layer for s in risky if s.weight >= 25}
    if any(s.source_kind == "verified_intel" and s.weight >= 90 for s in signals):
        return "high"
    if any(s.source_kind == "external_provider" for s in risky):
        return "high"
    if score >= 60 and len(layers) >= 2 and len(risky) >= 3:
        return "high"
    if any(s.code == "official_domain" for s in signals) and score < 20:
        return "medium"
    if len(risky) >= 2 or any(s.weight >= 45 for s in risky):
        return "medium"
    return "low"


_HEADLINES = {
    ("url", "critical"): "Dangerous website — verified threat",
    ("url", "high"): "Likely phishing or scam website",
    ("url", "suspicious"): "Suspicious website",
    ("url", "caution"): "Some unusual signs — be careful",
    ("url", "low"): "No warning signs on a known official site",
    ("url", "unknown"): "No warning signs found — not proof it's safe",
    ("message", "critical"): "Scam message — verified threat",
    ("message", "high"): "This message looks like a scam",
    ("message", "suspicious"): "Suspicious message",
    ("message", "caution"): "Some unusual signs — be careful",
    ("message", "low"): "No warning signs found",
    ("message", "unknown"): "No common scam signs found — not proof it's genuine",
    ("email", "critical"): "Phishing email — verified threat",
    ("email", "high"): "This email looks like phishing",
    ("email", "suspicious"): "Suspicious email",
    ("email", "caution"): "Some unusual signs — be careful",
    ("email", "low"): "No warning signs found",
    ("email", "unknown"): "No common phishing signs found — not proof it's genuine",
}


def _verdict(score: int, signals: list[Signal]) -> str:
    for floor, code, _ in BANDS:
        if score >= floor:
            if code == "low" and not any(s.layer == "positive" for s in signals):
                return "unknown"
            return code
    return "unknown"


GENERIC_CATEGORIES = {"social_engineering", "impersonation"}


def _category(signals: list[Signal]) -> str | None:
    """The most specific scam type: 'MoMo scam' beats the generic 'social engineering'."""
    candidates = [s for s in signals if s.category and s.weight > 0]
    specific = [s for s in candidates if s.category not in GENERIC_CATEGORIES]
    best = max(specific or candidates, key=lambda s: s.weight, default=None)
    return best.category if best else None


_CATEGORY_ADVICE = {
    "momo": "Check your balance and transactions only through your mobile money menu or the "
    "official app — never through a link or a number in a message.",
    "bank": "Call your bank on the number printed on your card or its official website, not a "
    "number in the message.",
    "government": "Use the agency's official website (ending in .gov.gh) or visit its office.",
    "delivery": "Track parcels in the courier's official app or website using your own "
    "tracking number.",
    "recruitment": "Real employers don't charge you to apply or start work.",
    "investment": "Check that an investment company is licensed by the Securities and "
    "Exchange Commission, Ghana, before sending any money.",
    "crypto": "Never share a wallet recovery phrase, and be wary of anyone promising crypto "
    "profits or giveaways.",
    "university": "Confirm admission and scholarship offers directly with the school.",
    "romance": "Call the person on a number you already know before sending any money.",
    "prize": "You can't win a promotion you didn't enter, and real prizes never require a fee.",
    "advance_fee": "Don't pay any fee to receive a job, loan, parcel or prize.",
}


def _recommendations(kind: str, verdict: str, signals: list[Signal], category: str | None):
    codes = {s.code for s in signals}
    recs: list[str] = []
    if verdict in {"critical", "high", "suspicious"}:
        if kind == "url":
            recs.append(
                "Don't open this website, and don't enter any passwords, PINs, OTPs or "
                "card details on it."
            )
            recs.append("Don't make payments or download apps through it.")
        elif kind == "email":
            recs.append("Don't click links, open attachments or reply to this email.")
        else:
            recs.append("Don't reply, click links or call numbers in this message.")
        recs.append("Never share your PIN, password or one-time code with anyone.")
        if "approve_prompt" in codes or "momo_reversal" in codes:
            recs.append("Don't approve any payment prompt you didn't start yourself.")
        if category in _CATEGORY_ADVICE:
            recs.append(_CATEGORY_ADVICE[category])
        else:
            recs.append(
                "Contact the organisation through its official website or a number you "
                "already trust."
            )
        recs.append(
            "If you already shared details or sent money, contact your bank or mobile "
            "money provider immediately, and report it to the Cyber Security Authority "
            "(call or text 292)."
        )
        recs.append("Report it here so we can warn others.")
    elif verdict == "caution":
        recs.append("Be careful. Verify through the organisation's official channel before acting.")
        recs.append("Don't enter passwords, PINs or OTPs unless you're sure the site is genuine.")
        if category in _CATEGORY_ADVICE:
            recs.append(_CATEGORY_ADVICE[category])
    elif verdict == "low":
        recs.append(
            "This looks like an official website, but always check the address bar "
            "before signing in."
        )
        recs.append(
            "Never share your PIN or one-time code, even on a genuine site's request "
            "by phone or message."
        )
    else:  # unknown
        recs.append(
            "We didn't find warning signs, but that doesn't prove it is safe — new scams "
            "appear every day."
        )
        recs.append(
            "If it asks for money, a PIN, a password or a code, stop and verify through "
            "an official channel first."
        )
    return recs


def assess(kind: str, signals: list[Signal]) -> Assessment:
    family = "url" if kind in {"url", "qr"} else kind
    score = combine(signals)
    verdict = _verdict(score, signals)
    confidence = _confidence(signals, score)
    category = _category(signals)
    headline = _HEADLINES.get((family, verdict), VERDICT_LABELS[verdict])
    risky = sorted((s for s in signals if s.weight > 0), key=lambda s: -s.weight)
    if verdict == "unknown":
        summary = (
            "We didn't find signs of phishing or fraud with the information available. That "
            "isn't the same as being safe: the site or message may simply be new to us."
        )
    elif verdict == "low":
        summary = next(
            (s.description for s in signals if s.layer == "positive"),
            "Only minor characteristics were noted.",
        )
    else:
        top = "; ".join(s.title.rstrip(".").lower() for s in risky[:3])
        verified = any(s.source_kind == "verified_intel" for s in risky)
        lead = (
            "It matches verified threat intelligence"
            if verified
            else f"We found {len(risky)} warning sign{'s' if len(risky) != 1 else ''}"
        )
        summary = f"{lead}: {top}."
    return Assessment(
        score=score,
        verdict=verdict,
        confidence=confidence,
        headline=headline,
        summary=summary,
        category=category,
        recommendations=_recommendations(family, verdict, signals, category),
    )
