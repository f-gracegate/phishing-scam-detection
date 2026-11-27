"""URL parsing, canonicalisation and static (no network) URL signals."""

import ipaddress
import re
import socket
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

import tldextract

from app.detection.brands import Brand, match_host, official_brand
from app.detection.signals import Signal, info

_extract = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)

# Query parameters that commonly carry secrets (session links, password resets, OTPs). Their
# values are redacted before storing or displaying a URL, and such URLs are never sent to
# external intelligence providers with the query intact.
SENSITIVE_PARAMS = {
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "auth",
    "authorization",
    "session",
    "sessionid",
    "sid",
    "key",
    "apikey",
    "api_key",
    "code",
    "otp",
    "pin",
    "password",
    "pass",
    "pwd",
    "sig",
    "signature",
    "secret",
    "ticket",
    "jwt",
    "reset",
    "hash",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "rb.gy",
    "tiny.cc",
    "t.ly",
    "s.id",
    "v.gd",
    "bl.ink",
    "lnkd.in",
    "shorte.st",
    "adf.ly",
    "qrco.de",
    "short.io",
    "urlz.fr",
    "ux.nu",
}

# Hosting and site-builder platforms where anyone can publish a page in minutes. Legitimate
# sites live here too, so this only adds weight next to other signs.
FREE_HOSTING = {
    "web.app",
    "firebaseapp.com",
    "000webhostapp.com",
    "weebly.com",
    "wixsite.com",
    "netlify.app",
    "vercel.app",
    "github.io",
    "pages.dev",
    "glitch.me",
    "herokuapp.com",
    "blogspot.com",
    "wordpress.com",
    "sites.google.com",
    "framer.website",
    "webflow.io",
    "carrd.co",
    "square.site",
    "godaddysites.com",
    "mystrikingly.com",
    "replit.app",
    "ngrok-free.app",
    "ngrok.io",
    "trycloudflare.com",
    "workers.dev",
    "duckdns.org",
    "forms.gle",
    "jotform.com",
    "typeform.com",
}

# TLDs disproportionately used for throwaway phishing domains (weak signal on its own).
RISKY_TLDS = {
    "xyz",
    "top",
    "icu",
    "click",
    "link",
    "work",
    "support",
    "buzz",
    "rest",
    "fit",
    "cfd",
    "sbs",
    "monster",
    "quest",
    "cam",
    "live",
    "online",
    "site",
    "shop",
    "store",
    "info",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "zip",
    "mov",
    "lat",
    "bond",
}

LURE_WORDS = {
    "login",
    "logon",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "update",
    "account",
    "wallet",
    "reversal",
    "reverse",
    "refund",
    "claim",
    "bonus",
    "reward",
    "promo",
    "unlock",
    "suspend",
    "suspended",
    "confirm",
    "support",
    "helpdesk",
    "kyc",
    "validate",
    "recovery",
    "billing",
    "payment",
    "invoice",
    "gift",
    "free",
    "winner",
    "prize",
    "otp",
}

_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_TOKENS = re.compile(r"[^a-z0-9]+")


class InvalidURL(ValueError):
    pass


@dataclass
class ParsedURL:
    original: str
    canonical: str  # normalised, fragment removed, sensitive query values redacted
    scheme: str
    host: str  # ascii (punycode) hostname, lowercase
    unicode_host: str
    port: int | None
    path: str
    query: str
    registrable: str  # e.g. example.com.gh
    suffix: str
    subdomain: str
    is_ip: bool
    has_userinfo: bool
    sensitive_params: list[str] = field(default_factory=list)

    @property
    def lookup_url(self) -> str:
        """The URL as sent to external providers: no secrets, no fragment."""
        if self.sensitive_params:
            return urlunsplit((self.scheme, self._netloc(), self.path or "/", "", ""))
        return urlunsplit((self.scheme, self._netloc(), self.path or "/", self.query, ""))

    def _netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}" if self.port else host


def parse_url(raw: str) -> ParsedURL:
    text = raw.strip().strip("<>\"'")
    if not text:
        raise InvalidURL("Enter a link to check.")
    if len(text) > 4096:
        raise InvalidURL("That link is too long to check.")
    lowered = text.lower()
    if lowered.startswith(("javascript:", "data:", "vbscript:", "file:")):
        scheme = lowered.split(":", 1)[0]
        return ParsedURL(text, f"{scheme}:", scheme, "", "", None, "", "", "", "", "", False, False)
    if not _SCHEME.match(text) or text.lower().startswith(("www.",)):
        # Browsers try https first for a bare address; so do we.
        text = "https://" + text
    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise InvalidURL("That doesn't look like a valid link.") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InvalidURL("Only web links (http and https) can be checked.")
    hostname = parts.hostname
    if not hostname:
        raise InvalidURL("That link has no website address in it.")
    unicode_host = unquote(hostname).rstrip(".").lower()
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidURL("That link has an invalid port number.") from exc
    is_ip = _is_ip(unicode_host)
    if is_ip:
        host = _normalise_ip(unicode_host)
    else:
        try:
            host = unicode_host.encode("idna").decode("ascii")
        except UnicodeError:
            host = unicode_host
        try:
            unicode_host = host.encode("ascii").decode("idna")
        except UnicodeError:
            pass
        if not re.fullmatch(r"[a-z0-9.-]+", host) or ".." in host or "." not in host:
            raise InvalidURL("That link's website address isn't valid.")
    if scheme == "http" and port == 80 or scheme == "https" and port == 443:
        port = None

    pairs = parse_qsl(parts.query, keep_blank_values=True)
    sensitive = sorted({k for k, _ in pairs if k.lower() in SENSITIVE_PARAMS})
    if sensitive:
        query = urlencode(
            [(k, "REDACTED" if k.lower() in SENSITIVE_PARAMS else v) for k, v in pairs]
        )
    else:
        query = parts.query
    path = quote(unquote(parts.path), safe="/%:@!$&'()*+,;=-._~") if parts.path else "/"

    if is_ip:
        registrable, suffix, subdomain = host, "", ""
    else:
        ext = _extract(host)
        if ext.suffix:
            registrable = f"{ext.domain}.{ext.suffix}" if ext.domain else ext.suffix
            suffix, subdomain = ext.suffix, ext.subdomain
        else:  # reserved or unknown TLDs (.example, .test, .local)
            labels = host.split(".")
            registrable = ".".join(labels[-2:])
            suffix, subdomain = labels[-1], ".".join(labels[:-2])

    netloc = (f"[{host}]" if ":" in host else host) + (f":{port}" if port else "")
    canonical = urlunsplit((scheme, netloc, path, query, ""))
    return ParsedURL(
        original=raw.strip()[:2048],
        canonical=canonical,
        scheme=scheme,
        host=host,
        unicode_host=unicode_host,
        port=port,
        path=path,
        query=query,
        registrable=registrable,
        suffix=suffix,
        subdomain=subdomain,
        is_ip=is_ip,
        has_userinfo=bool(parts.username),
        sensitive_params=sensitive,
    )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # Decimal / hex / octal IPv4 forms ("http://3232235777/") are an evasion trick.
    return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host))


def _normalise_ip(host: str) -> str:
    host = host.strip("[]")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        # inet_aton understands the legacy forms browsers accept (3232235777, 0x7f.1, 0177.1).
        return socket.inet_ntoa(socket.inet_aton(host))
    except OSError:
        return host


def _mixed_scripts(text: str) -> bool:
    scripts = set()
    for ch in text:
        if ch in ".-" or ch.isdigit():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        scripts.add(name.split(" ")[0])
    return len(scripts) > 1


def host_label(host: str) -> str:
    return host.split(".")[0] if host else host


def analyse_url(url: ParsedURL, brands: list[Brand] | tuple[Brand, ...]) -> list[Signal]:
    """Signals visible in the link itself, before visiting it."""
    if url.scheme in {"javascript", "data", "vbscript", "file"}:
        return [
            Signal(
                "domain",
                "dangerous_scheme",
                "Not a normal web link",
                f"This is a '{url.scheme}:' link. These can run code or open hidden content "
                "instead of a website, and are a common way to hide a phishing page.",
                75,
                reliability="high",
            )
        ]
    signals: list[Signal] = []
    official = None if url.is_ip else official_brand(url.host, brands)
    if official:
        signals.append(
            Signal(
                "positive",
                "official_domain",
                f"Official {official.name} website",
                f"{url.registrable} is on our list of domains that {official.name} uses. "
                "Still check the full address carefully before signing in.",
                0,
                reliability="medium",
                category=official.category,
                data={"brand": official.name},
            )
        )

    host_tokens = set(_TOKENS.split(url.host.lower()))
    path_tokens = set(_TOKENS.split(url.path.lower()))
    lures = sorted((host_tokens | path_tokens) & LURE_WORDS)

    if not official and not url.is_ip:
        match = match_host(url.host, brands)
        if match:
            lookalike = match.how == "lookalike"
            weight = 70 if lookalike else (60 if lures else 50)
            title = (
                f"Looks like {match.brand.name}'s address, but isn't"
                if lookalike
                else f"Uses the name {match.brand.name} on another website"
            )
            desc = (
                f"The address '{url.unicode_host}' imitates {match.brand.name}"
                f" ({', '.join(match.brand.official_domains)}) with a small spelling change"
                f" ({match.detail}). Scammers register lookalike domains to trick people."
                if lookalike
                else f"'{match.detail}' appears in '{url.unicode_host}', but {match.brand.name}"
                f" uses {', '.join(match.brand.official_domains)}. Anyone can put a brand name "
                "into a web address."
            )
            if lures and not lookalike:
                desc += f" The address also contains words like '{', '.join(lures[:3])}'."
            signals.append(
                Signal(
                    "domain",
                    "brand_impersonation_domain",
                    title,
                    desc,
                    weight,
                    category=match.brand.category,
                    data={"brand": match.brand.name, "how": match.how, "detail": match.detail},
                )
            )
        elif len(lures) >= 2:
            signals.append(
                Signal(
                    "domain",
                    "lure_words",
                    "Address uses words common in phishing links",
                    f"The link contains '{', '.join(lures[:4])}'. These words are often used "
                    "to make a fake page look official.",
                    15,
                )
            )

    if url.is_ip:
        signals.append(
            Signal(
                "domain",
                "ip_address_host",
                "Uses a raw IP address instead of a name",
                "Real organisations almost always use a domain name. Links that point to a "
                "bare number like this are often used for phishing or malware.",
                35,
            )
        )
    if url.has_userinfo:
        signals.append(
            Signal(
                "domain",
                "userinfo_trick",
                "Hides the real address behind an '@'",
                "Everything before the '@' in this link is ignored by your browser. It is a "
                "known trick to make a link look like it goes somewhere it doesn't.",
                45,
                reliability="high",
            )
        )
    if url.host.startswith("xn--") or ".xn--" in url.host:
        mixed = _mixed_scripts(url.unicode_host)
        signals.append(
            Signal(
                "domain",
                "idn_homograph" if mixed else "punycode_domain",
                "Uses look-alike international characters"
                if mixed
                else "Uses international characters in the address",
                f"The address displays as '{url.unicode_host}' but is really '{url.host}'. "
                + (
                    "It mixes alphabets, which is used to imitate real addresses."
                    if mixed
                    else "Check that it is the site you expect."
                ),
                60 if mixed else 15,
            )
        )
    if url.registrable in SHORTENERS or url.host in SHORTENERS:
        signals.append(
            Signal(
                "domain",
                "url_shortener",
                "Shortened link hides the destination",
                f"{url.registrable} is a link-shortening service, so you can't see where it "
                "really leads. Scammers use them to disguise phishing pages.",
                15,
                data={"shortener": url.registrable},
            )
        )
    hosting = next((h for h in FREE_HOSTING if url.host == h or url.host.endswith("." + h)), None)
    if hosting and not official:
        signals.append(
            Signal(
                "domain",
                "free_hosting",
                "Hosted on a free website-building service",
                f"This page is published on {hosting}, where anyone can create a site in "
                "minutes. Real banks and mobile money services don't use these for sign-in "
                "pages.",
                30 if lures else 15,
                data={"platform": hosting},
            )
        )
    if url.suffix and url.suffix.split(".")[-1] in RISKY_TLDS and not official:
        signals.append(
            Signal(
                "domain",
                "risky_tld",
                f"Uses a '.{url.suffix}' address",
                f"'.{url.suffix}' addresses are cheap and frequently used for short-lived "
                "scam sites. Many legitimate sites use them too, so this is a weak sign.",
                10,
            )
        )
    if url.subdomain.count(".") >= 3:
        signals.append(
            Signal(
                "domain",
                "deep_subdomains",
                "Unusually long chain of subdomains",
                f"'{url.subdomain}' pushes the real domain ({url.registrable}) far to the "
                "right, where people are less likely to notice it.",
                15,
            )
        )
    if url.port and url.port not in {80, 443, 8080, 8443}:
        signals.append(
            Signal(
                "domain",
                "unusual_port",
                f"Uses an unusual port ({url.port})",
                "Websites normally don't need a port number in the address.",
                15,
            )
        )
    if url.scheme == "http":
        signals.append(
            info(
                "domain",
                "no_https",
                "Not encrypted (http)",
                "The link uses http, not https. Never enter passwords, PINs or card details on "
                "an unencrypted page.",
            )
        )
    if len(url.canonical) > 200:
        signals.append(
            Signal(
                "domain",
                "very_long_url",
                "Very long, complicated link",
                "Extremely long links are sometimes used to hide the real destination.",
                5,
            )
        )
    if url.sensitive_params:
        signals.append(
            info(
                "domain",
                "sensitive_link",
                "Link contains a private token",
                "This link carries a code or session token. We hid it from our records and did "
                "not send it to outside services. Don't share links like this.",
                params=url.sensitive_params,
            )
        )
    return signals


URL_IN_TEXT = re.compile(
    r"""(?ix)
    \b(
      (?:https?://|www\.)[^\s<>"'()]+
      |
      (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
      (?:com|net|org|gh|info|xyz|top|icu|click|link|live|online|site|shop|store|app|io|co|me|
         ly|gl|gd|cc|tk|ml|ga|cf|gq|biz|us|uk|ng|ke|za|support|buzz|cfd|sbs|lat|bond|rest)
      (?::\d{2,5})?(?:/[^\s<>"'()]*)?
    )""",
)


def extract_urls(text: str, limit: int = 10) -> list[str]:
    found: list[str] = []
    for match in URL_IN_TEXT.finditer(text):
        candidate = match.group(1).rstrip(".,;:!?)]}'\"")
        if "@" in candidate.split("/")[0] and not candidate.lower().startswith("http"):
            continue  # an email address, not a link
        if candidate.lower() not in (c.lower() for c in found):
            found.append(candidate)
        if len(found) >= limit:
            break
    return found
