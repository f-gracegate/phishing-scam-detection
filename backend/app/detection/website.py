"""Signals from a fetched web page: redirects, forms, impersonation, certificates.

The page is parsed as text; no JavaScript is executed. (A disposable headless-browser sandbox
for script-heavy pages is planned; see docs/threat-model.md.)
"""

import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from app.detection.brands import Brand, mentioned_brands, official_brand
from app.detection.signals import Signal, info
from app.detection.urls import InvalidURL, parse_url

SENSITIVE_FIELD = re.compile(
    r"(?i)\b(pin|otp|one.?time|cvv|cvc|card.?(number|no)|security.?code|momo|wallet|"
    r"mobile.?money|ssn|ghana.?card|seed|recovery.?phrase|mnemonic|passcode)\b"
)
OBFUSCATION = re.compile(
    r"(?i)eval\s*\(\s*(atob|unescape|decodeURIComponent|function\s*\(p,a,c,k,e)|"
    r"document\.write\s*\(\s*unescape|String\.fromCharCode\(\s*\d+\s*(,\s*\d+\s*){40,}"
)
JS_REDIRECT = re.compile(
    r"(?i)(window|document|top|self)\.location(\.href)?\s*=\s*['\"]([^'\"]+)['\"]|"
    r"location\.replace\(\s*['\"]([^'\"]+)['\"]"
)
APP_DOWNLOAD = re.compile(r"(?i)\.(apk|exe|msi|scr|dmg|ipa)(\?|$)")


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self.inputs: list[dict[str, str]] = []
        self.meta_refresh: str | None = None
        self.iframes: list[str] = []
        self.links: list[str] = []
        self.scripts = 0
        self.text: list[str] = []
        self._skip = 0
        self.icons: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag in {"script", "style"}:
            self._skip += 1
            if tag == "script":
                self.scripts += 1
        elif tag == "form":
            self._form = {
                "action": a.get("action", ""),
                "method": a.get("method", "get").lower(),
                "fields": [],
            }
            self.forms.append(self._form)
        elif tag in {"input", "select", "textarea"}:
            field = {
                "type": a.get("type", "text").lower(),
                "name": " ".join(
                    filter(
                        None,
                        (
                            a.get("name"),
                            a.get("id"),
                            a.get("placeholder"),
                            a.get("aria-label"),
                            a.get("autocomplete"),
                        ),
                    )
                ),
            }
            self.inputs.append(field)
            if self._form is not None:
                self._form["fields"].append(field)
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")
        elif tag == "iframe" and a.get("src"):
            self.iframes.append(a["src"])
        elif tag == "a" and a.get("href"):
            if len(self.links) < 300:
                self.links.append(a["href"])
        elif tag == "link" and "icon" in a.get("rel", "").lower() and a.get("href"):
            self.icons.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag in {"script", "style"} and self._skip:
            self._skip -= 1
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self._skip and len(self.text) < 2000:
            self.text.append(data)


def parse_page(html: str) -> _PageParser:
    parser = _PageParser()
    try:
        parser.feed(html[:1_000_000])
        parser.close()
    except Exception:  # noqa: BLE001, S110 - a partial parse of broken HTML is still useful
        pass
    return parser


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _registrable(url: str) -> str:
    try:
        return parse_url(url).registrable
    except InvalidURL:
        return ""


def analyse_fetch(
    fetch: dict, brands: list[Brand] | tuple[Brand, ...]
) -> tuple[list[Signal], dict]:
    """Signals and display facts from the fetcher's result."""
    signals: list[Signal] = []
    facts: dict[str, Any] = {
        "reachable": bool(fetch.get("ok")),
        "final_url": fetch.get("final_url"),
        "status": fetch.get("status"),
        "redirects": [
            {"url": h["url"], "status": h["status"], "to": h.get("location")}
            for h in fetch.get("hops", [])
        ],
    }
    if fetch.get("unsafe"):
        signals.append(
            Signal(
                "website",
                "points_to_private_network",
                "Link points to a private network",
                "This link (or one of its redirects) leads to a private, internal or reserved "
                "network address. We refused to follow it. Links in messages shouldn't point "
                "there.",
                40,
                source_kind="observed",
                reliability="high",
            )
        )
        facts["error"] = fetch.get("error")
        return signals, facts
    if not fetch.get("ok"):
        facts["error"] = fetch.get("error")
        signals.append(
            info(
                "website",
                "unreachable",
                "We couldn't load the website",
                f"{fetch.get('error') or 'The site did not respond'}. Scam sites are often taken "
                "down quickly, but an unreachable site isn't proof either way.",
            )
        )
        return signals, facts

    requested_reg = _registrable(fetch.get("requested_url", ""))
    final_url = fetch.get("final_url") or ""
    final_reg = _registrable(final_url)
    hops = fetch.get("hops", [])
    hop_domains = []
    for h in hops:
        reg = _registrable(h["url"])
        if reg and reg not in hop_domains:
            hop_domains.append(reg)
    if final_reg and requested_reg and final_reg != requested_reg:
        signals.append(
            Signal(
                "website",
                "cross_domain_redirect",
                "Redirects to a different website",
                f"The link starts at {requested_reg} but ends up at {final_reg}"
                + (
                    f" after passing through {len(hop_domains) - 2} other site(s)"
                    if len(hop_domains) > 2
                    else ""
                )
                + ". Phishing links often bounce through several addresses to hide where "
                "they go.",
                20 if len(hop_domains) > 2 else 12,
                source_kind="observed",
                data={"chain": hop_domains},
            )
        )

    headers = fetch.get("headers") or {}
    if fetch.get("download") or APP_DOWNLOAD.search(final_url):
        ctype = fetch.get("content_type") or "a file"
        weight = 50 if APP_DOWNLOAD.search(final_url) or "android" in ctype else 30
        signals.append(
            Signal(
                "website",
                "file_download",
                "The link downloads a file or app",
                f"Instead of a web page, this link delivers {ctype.split(';')[0]}. Fake "
                "banking and mobile money apps (.apk files) are a common way to steal "
                "accounts. Only install apps from Google Play or the App Store.",
                weight,
                source_kind="observed",
            )
        )
        return signals, facts

    page = parse_page(fetch.get("body") or "")
    title = " ".join(page.title.split())[:200]
    facts["title"] = title
    page_text = " ".join(" ".join(page.text).split())[:20000]
    final_host = _host(final_url)
    own = official_brand(final_host, brands)

    password_fields = [f for f in page.inputs if f["type"] == "password"]
    sensitive_fields = [f for f in page.inputs if SENSITIVE_FIELD.search(f["name"])]
    facts["forms"] = len(page.forms)
    facts["password_fields"] = len(password_fields)
    facts["sensitive_fields"] = sorted(
        {SENSITIVE_FIELD.search(f["name"]).group(0).lower() for f in sensitive_fields}
    )[:6]
    asks_secrets = bool(password_fields or sensitive_fields)

    claimed = [] if own else mentioned_brands(f"{title} {page_text[:3000]}", brands)
    if claimed:
        brand = claimed[0]
        if asks_secrets:
            signals.append(
                Signal(
                    "website",
                    "credential_harvest",
                    f"Fake {brand.name} sign-in or payment page",
                    f"The page presents itself as {brand.name} and asks for "
                    + ("a password" if password_fields else "sensitive details")
                    + (
                        f" ({', '.join(facts['sensitive_fields'])})"
                        if facts["sensitive_fields"]
                        else ""
                    )
                    + f", but it is hosted on {final_reg}, not "
                    f"{', '.join(brand.official_domains)}.",
                    75,
                    category=brand.category,
                    source_kind="observed",
                    data={"brand": brand.name},
                )
            )
        elif brand.name.lower() in title.lower() or any(
            k in title.lower() for k in brand.keywords if len(k) > 3
        ):
            signals.append(
                Signal(
                    "website",
                    "brand_in_title",
                    f"Page uses {brand.name}'s name",
                    f"The page title mentions {brand.name}, but the site is {final_reg}. "
                    "That doesn't prove it's fake, but check carefully.",
                    25,
                    category=brand.category,
                    source_kind="observed",
                    data={"brand": brand.name},
                )
            )
    if asks_secrets and not claimed and not own:
        signals.append(
            Signal(
                "website",
                "asks_for_secrets",
                "Page asks for a password, PIN or card details",
                "The page has fields for "
                + (", ".join(facts["sensitive_fields"]) or "a password")
                + ". Only enter these on a site you reached yourself and fully trust.",
                30 if sensitive_fields else 15,
                source_kind="observed",
            )
        )

    for form in page.forms:
        action = (form.get("action") or "").strip()
        if not action or action.startswith(("#", "javascript:")):
            continue
        target = urljoin(final_url, action)
        target_reg = _registrable(target)
        has_secret = any(
            f["type"] == "password" or SENSITIVE_FIELD.search(f["name"]) for f in form["fields"]
        )
        if target_reg and final_reg and target_reg != final_reg and has_secret:
            signals.append(
                Signal(
                    "website",
                    "form_posts_elsewhere",
                    "Sign-in form sends your details to another website",
                    f"The form on this page submits to {target_reg}, a different site from "
                    f"{final_reg}. Phishing kits often send stolen details elsewhere.",
                    40,
                    source_kind="observed",
                    data={"form_target": target_reg},
                )
            )
            break
        if target.startswith("http://") and has_secret:
            signals.append(
                Signal(
                    "website",
                    "form_insecure",
                    "Form sends sensitive details unencrypted",
                    "This form submits passwords or PINs over plain http.",
                    25,
                    source_kind="observed",
                )
            )
            break

    redirects = []
    if page.meta_refresh and "url=" in page.meta_refresh.lower():
        redirects.append(page.meta_refresh.lower().split("url=", 1)[1].strip(" '\""))
    for m in JS_REDIRECT.finditer((fetch.get("body") or "")[:200_000]):
        redirects.append(m.group(3) or m.group(4) or "")
    for target in redirects[:3]:
        target_reg = _registrable(urljoin(final_url, target))
        if target_reg and target_reg != final_reg:
            signals.append(
                Signal(
                    "website",
                    "scripted_redirect",
                    "Page quietly forwards you elsewhere",
                    f"The page contains code that sends visitors on to {target_reg}.",
                    20,
                    source_kind="observed",
                    data={"target": target_reg},
                )
            )
            break

    if OBFUSCATION.search((fetch.get("body") or "")[:500_000]):
        signals.append(
            Signal(
                "website",
                "obfuscated_code",
                "Contains deliberately hidden code",
                "The page's code is scrambled in a way commonly used to hide phishing kits "
                "from scanners.",
                20,
                source_kind="observed",
            )
        )
    if page.iframes and not page.text and len(page.iframes) == 1:
        frame_reg = _registrable(urljoin(final_url, page.iframes[0]))
        if frame_reg and frame_reg != final_reg:
            signals.append(
                Signal(
                    "website",
                    "full_page_frame",
                    "Shows another website inside a frame",
                    f"The whole page is a frame loading {frame_reg}, which hides the real "
                    "address from you.",
                    25,
                    source_kind="observed",
                )
            )

    tls = fetch.get("tls")
    if final_url.startswith("http://") and asks_secrets:
        signals.append(
            Signal(
                "website",
                "secrets_over_http",
                "Asks for sensitive details without https",
                "The page asks for passwords or PINs on an unencrypted connection.",
                30,
                source_kind="observed",
            )
        )
    if tls:
        cert = tls.get("certificate") or {}
        facts["tls"] = {
            "trusted": tls.get("trusted"),
            "issuer": cert.get("issuer"),
            "valid_from": cert.get("not_before"),
            "valid_to": cert.get("not_after"),
            "error": tls.get("error"),
        }
        if not tls.get("trusted"):
            signals.append(
                Signal(
                    "website",
                    "untrusted_certificate",
                    "Security certificate isn't trusted",
                    "Browsers would show a warning for this site "
                    f"({tls.get('error') or 'certificate not trusted'}).",
                    25,
                    source_kind="observed",
                )
            )
        elif cert.get("not_before"):
            try:
                issued = datetime.fromisoformat(cert["not_before"])
                age_days = (datetime.now(UTC) - issued).days
                facts["tls"]["age_days"] = age_days
                if age_days <= 3 and claimed:
                    signals.append(
                        Signal(
                            "website",
                            "brand_new_certificate",
                            "Security certificate was issued in the last few days",
                            f"The certificate is only {age_days} day(s) old. New sites "
                            "imitating a brand often have brand-new certificates. A padlock "
                            "only means the connection is encrypted, not that the site is "
                            "honest.",
                            15,
                            source_kind="observed",
                        )
                    )
            except ValueError:
                pass
    if fetch.get("status") and fetch["status"] >= 400:
        signals.append(
            info(
                "website",
                "error_page",
                f"Website returned an error ({fetch['status']})",
                "The page may have been removed or blocked.",
            )
        )
    if own and not signals:
        facts["official_brand"] = own.name
    facts["server"] = headers.get("server")
    return signals, facts
