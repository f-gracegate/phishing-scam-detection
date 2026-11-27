"""Email phishing analysis: headers, authentication results, links and attachments.

Attachments are never opened or executed; only their names, types and sizes are inspected.
SPF, DKIM and DMARC passing is reported but never treated as proof of legitimacy — attackers
send authenticated mail from domains they own.
"""

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

from app.detection.brands import Brand, match_host, mentioned_brands, official_brand
from app.detection.signals import Signal, info
from app.detection.urls import InvalidURL, parse_url

FREE_MAIL = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.co.uk",
    "ymail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "mail.com",
    "zoho.com",
    "yandex.com",
}

EXECUTABLE_EXT = {
    "exe",
    "scr",
    "com",
    "bat",
    "cmd",
    "pif",
    "msi",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "hta",
    "ps1",
    "jar",
    "apk",
    "dll",
    "lnk",
    "iso",
    "img",
    "vhd",
    "reg",
    "cpl",
    "msc",
    "app",
    "dmg",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppsm"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "ace", "cab"}
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg"}


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int


@dataclass
class ParsedEmail:
    from_name: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: list[str] = field(default_factory=list)
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received_count: int = 0
    auth: dict[str, str] = field(default_factory=dict)  # spf/dkim/dmarc -> pass|fail|...
    text: str = ""
    links: list[tuple[str, str]] = field(default_factory=list)  # (href, visible text)
    attachments: list[Attachment] = field(default_factory=list)
    has_headers: bool = False

    @property
    def from_domain(self) -> str:
        return self.from_address.rsplit("@", 1)[-1].lower() if "@" in self.from_address else ""


class _LinkHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._anchor: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self._skip += 1
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor = []
        if tag in {"br", "p", "div", "tr", "li"}:
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._anchor).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)


def html_to_text(html: str) -> tuple[str, list[tuple[str, str]]]:
    parser = _LinkHTML()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001, S110 - malformed HTML still yields what was parsed
        pass
    text = re.sub(r"[ \t]+", " ", "".join(parser.text))
    return re.sub(r"\n\s*\n+", "\n\n", text).strip(), parser.links


_AUTH = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


def _looks_like_headers(raw: str) -> bool:
    head = raw.lstrip()[:2000]
    return bool(re.search(r"(?im)^(from|subject|received|return-path|message-id):\s", head))


def parse_email(raw: bytes | str) -> ParsedEmail:
    data = raw.encode("utf-8", "replace") if isinstance(raw, str) else raw
    text_form = data[:4000].decode("utf-8", "replace")
    if not _looks_like_headers(text_form):
        body = data.decode("utf-8", "replace")
        if "<html" in body.lower() or "<a " in body.lower():
            text, links = html_to_text(body)
        else:
            text, links = body, []
        return ParsedEmail(text=text, links=links)

    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(data)  # type: ignore
    out = ParsedEmail(has_headers=True)
    name, addr = parseaddr(str(msg.get("From", "")))
    out.from_name, out.from_address = name.strip(), addr.strip().lower()
    out.reply_to = parseaddr(str(msg.get("Reply-To", "")))[1].strip().lower()
    out.return_path = parseaddr(str(msg.get("Return-Path", "")))[1].strip().lower()
    out.to = [a for _, a in getaddresses([str(v) for v in msg.get_all("To", [])])][:10]
    out.subject = str(msg.get("Subject", ""))[:300]
    out.date = str(msg.get("Date", ""))[:100]
    out.message_id = str(msg.get("Message-ID", ""))[:300]
    out.received_count = len(msg.get_all("Received", []) or [])
    for header in msg.get_all("Authentication-Results", []) or []:
        for mech, result in _AUTH.findall(str(header)):
            out.auth.setdefault(mech.lower(), result.lower())

    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        ctype = part.get_content_type()
        if disposition == "attachment" or (filename and disposition != "inline"):
            payload = part.get_payload(decode=True) or b""
            out.attachments.append(Attachment(filename or "(unnamed)", ctype, len(payload)))
            continue
        if ctype == "text/plain":
            try:
                plain.append(part.get_content())
            except (LookupError, UnicodeError):
                plain.append((part.get_payload(decode=True) or b"").decode("utf-8", "replace"))
        elif ctype == "text/html":
            try:
                html.append(part.get_content())
            except (LookupError, UnicodeError):
                html.append((part.get_payload(decode=True) or b"").decode("utf-8", "replace"))
    links: list[tuple[str, str]] = []
    if html:
        html_text, links = html_to_text("\n".join(html))
        out.text = "\n".join(plain).strip() or html_text
    else:
        out.text = "\n".join(plain).strip()
    out.links = links
    return out


def _ext(filename: str) -> list[str]:
    return [p.lower() for p in filename.split(".")[1:]]


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def analyse_email(email: ParsedEmail, brands: list[Brand] | tuple[Brand, ...]) -> list[Signal]:
    signals: list[Signal] = []
    from_domain = email.from_domain
    claimed = mentioned_brands(f"{email.from_name} {email.subject}", brands)

    if from_domain:
        own = official_brand(from_domain, brands)
        lookalike = None if own else match_host(from_domain, brands)
        if lookalike:
            signals.append(
                Signal(
                    "email",
                    "lookalike_sender_domain",
                    f"Sender's domain imitates {lookalike.brand.name}",
                    f"The email comes from '{from_domain}', which is not one of "
                    f"{lookalike.brand.name}'s domains "
                    f"({', '.join(lookalike.brand.official_domains)}).",
                    65,
                    category=lookalike.brand.category,
                    data={"brand": lookalike.brand.name},
                )
            )
        elif claimed and not own:
            brand = claimed[0]
            free = from_domain in FREE_MAIL
            signals.append(
                Signal(
                    "email",
                    "display_name_impersonation",
                    f"Claims to be {brand.name}, but sent from "
                    + ("a free email account" if free else "another domain"),
                    f"The sender name or subject mentions {brand.name}, but the address is "
                    f"'{email.from_address}'. {brand.name} sends email from "
                    f"{', '.join(brand.official_domains)}.",
                    55 if free else 45,
                    category=brand.category,
                    data={"brand": brand.name},
                )
            )
        elif own:
            signals.append(
                info(
                    "email",
                    "official_sender_domain",
                    f"Sent from {own.name}'s domain",
                    f"'{from_domain}' is one of {own.name}'s domains. Check the authentication "
                    "results below: sender addresses can be forged.",
                )
            )

    reply_domain = _domain_of(email.reply_to)
    if reply_domain and from_domain and reply_domain != from_domain:
        signals.append(
            Signal(
                "email",
                "reply_to_mismatch",
                "Replies go to a different address",
                f"Replies would go to '{email.reply_to}', not the sender's domain "
                f"({from_domain}). Scammers do this to receive your answers.",
                35 if reply_domain in FREE_MAIL else 25,
            )
        )
    rp_domain = _domain_of(email.return_path)
    if (
        rp_domain
        and from_domain
        and not (
            rp_domain == from_domain
            or rp_domain.endswith("." + from_domain)
            or from_domain.endswith("." + rp_domain)
        )
    ):
        signals.append(
            Signal(
                "email",
                "return_path_mismatch",
                "Bounce address is on another domain",
                f"The technical sender ({rp_domain}) differs from the visible sender. Mailing "
                "services do this legitimately, so it is a weak sign.",
                8,
            )
        )

    weights = {
        ("spf", "fail"): 25,
        ("spf", "softfail"): 10,
        ("dkim", "fail"): 20,
        ("dmarc", "fail"): 35,
    }
    failed = []
    for mech, result in email.auth.items():
        w = weights.get((mech, result))
        if w:
            failed.append(mech.upper())
            signals.append(
                Signal(
                    "email",
                    f"{mech}_{result}",
                    f"{mech.upper()} check {result}ed",
                    f"The receiving mail server reported {mech.upper()}={result}. The message "
                    f"may not really come from {from_domain or 'the domain it shows'}.",
                    w,
                    source_kind="observed",
                    reliability="high",
                )
            )
    if email.auth and not failed:
        passed = ", ".join(f"{k.upper()}={v}" for k, v in sorted(email.auth.items()))
        signals.append(
            info(
                "email",
                "auth_results",
                "Email authentication results",
                f"{passed}. Passing only shows the mail came from the domain it names — "
                "scammers can pass these checks with domains they own.",
            )
        )
    elif email.has_headers and not email.auth:
        signals.append(
            info(
                "email",
                "no_auth_results",
                "No authentication results in the headers",
                'Paste the full original email ("Show original" / "View source") to include '
                "SPF, DKIM and DMARC results.",
            )
        )

    for href, visible in email.links[:50]:
        shown = re.search(r"(?i)\b((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,})", visible or "")
        if not shown or not href.lower().startswith(("http://", "https://")):
            continue
        try:
            real = parse_url(href)
            display = parse_url(shown.group(1))
        except InvalidURL:
            continue
        if real.registrable and display.registrable and real.registrable != display.registrable:
            signals.append(
                Signal(
                    "email",
                    "link_text_mismatch",
                    "A link shows one address but opens another",
                    f"The text says '{display.registrable}' but the link really goes to "
                    f"'{real.registrable}'. This is a classic phishing trick.",
                    50,
                    reliability="high",
                    data={"shown": display.registrable, "actual": real.registrable},
                )
            )
            break

    for att in email.attachments[:20]:
        exts = _ext(att.filename)
        last = exts[-1] if exts else ""
        double = len(exts) >= 2 and exts[-2] in {
            "pdf",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "jpg",
            "png",
            "txt",
            "invoice",
        }
        if last in EXECUTABLE_EXT:
            weight, why = (65 if double else 60), "a program or script that can install malware"
        elif last in MACRO_EXT:
            weight, why = 35, "an Office file that can contain macros"
        elif last in HTML_EXT:
            weight, why = 40, "a web page, often used to show a fake sign-in form offline"
        elif last in ARCHIVE_EXT:
            weight, why = 15, "a compressed archive that can hide other files"
        else:
            continue
        signals.append(
            Signal(
                "email",
                "risky_attachment",
                f"Risky attachment: {att.filename[:60]}",
                f"'{att.filename[:80]}' is {why}."
                + (" Its name uses a double extension to look harmless." if double else "")
                + " Don't open it.",
                weight,
                data={"filename": att.filename[:120], "content_type": att.content_type},
            )
        )
    return signals
