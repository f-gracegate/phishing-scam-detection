"""Brands commonly impersonated in Ghanaian scams, and helpers to spot impersonation.

The built-in catalogue seeds the ``brand_profiles`` table. Entries start unverified: an analyst
should confirm each official domain list before relying on it in production, and can add
domains, keywords and SMS sender IDs from the console without a code change.
"""

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Brand:
    name: str
    category: str
    official_domains: tuple[str, ...]
    keywords: tuple[str, ...]
    sender_ids: tuple[str, ...] = ()
    official_contact: str | None = None
    id: str | None = field(default=None, compare=False)


CATALOGUE: tuple[Brand, ...] = (
    Brand(
        "MTN Mobile Money",
        "momo",
        ("mtn.com.gh", "mtn.com"),
        ("mtn", "momo", "mobilemoney"),
        ("MobileMoney", "MTN"),
    ),
    Brand(
        "Telecel Cash",
        "momo",
        ("telecel.com.gh", "vodafone.com.gh"),
        ("telecel", "telecelcash", "vodafonecash"),
    ),
    Brand("AT Money", "momo", ("airteltigo.com.gh",), ("airteltigo", "atmoney")),
    Brand("GCB Bank", "bank", ("gcbbank.com.gh",), ("gcb", "gcbbank", "gmoney")),
    Brand("Ecobank Ghana", "bank", ("ecobank.com",), ("ecobank",)),
    Brand("Stanbic Bank Ghana", "bank", ("stanbicbank.com.gh",), ("stanbic",)),
    Brand("Absa Bank Ghana", "bank", ("absa.com.gh",), ("absa",)),
    Brand("Standard Chartered Ghana", "bank", ("sc.com",), ("standardchartered", "stanchart")),
    Brand("Fidelity Bank Ghana", "bank", ("myfidelitybank.net",), ("fidelitybank",)),
    Brand("CalBank", "bank", ("calbank.net",), ("calbank",)),
    Brand("Zenith Bank Ghana", "bank", ("zenithbank.com.gh",), ("zenithbank",)),
    Brand("Access Bank Ghana", "bank", ("accessbankplc.com",), ("accessbank",)),
    Brand("Bank of Ghana", "government", ("bog.gov.gh",), ("bankofghana",)),
    Brand("Ghana Revenue Authority", "government", ("gra.gov.gh",), ("gra",)),
    Brand("SSNIT", "government", ("ssnit.org.gh",), ("ssnit",)),
    Brand("DVLA Ghana", "government", ("dvla.gov.gh",), ("dvla",)),
    Brand("National Identification Authority", "government", ("nia.gov.gh",), ("nia", "ghanacard")),
    Brand("Government of Ghana", "government", ("ghana.gov.gh", "gov.gh"), ("ghanagov",)),
    Brand("Electricity Company of Ghana", "government", ("ecg.com.gh",), ("ecg",)),
    Brand("Cyber Security Authority", "government", ("csa.gov.gh",), ("cybersecurityauthority",)),
    Brand("Ghana Post", "delivery", ("ghanapost.com.gh",), ("ghanapost",)),
    Brand("DHL", "delivery", ("dhl.com",), ("dhl",)),
    Brand("Jumia Ghana", "ecommerce", ("jumia.com.gh", "jumia.com"), ("jumia",)),
    Brand("Hubtel", "ecommerce", ("hubtel.com",), ("hubtel",)),
    Brand("Paystack", "ecommerce", ("paystack.com", "paystack.co"), ("paystack",)),
    Brand("University of Ghana", "education", ("ug.edu.gh",), ("universityofghana",)),
    Brand("KNUST", "education", ("knust.edu.gh",), ("knust",)),
    Brand("PayPal", "ecommerce", ("paypal.com",), ("paypal",)),
    Brand(
        "Microsoft",
        "other",
        ("microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"),
        ("microsoft", "office365", "outlook"),
    ),
    Brand("WhatsApp", "other", ("whatsapp.com", "whatsapp.net"), ("whatsapp",)),
    Brand("Facebook", "other", ("facebook.com", "fb.com", "meta.com"), ("facebook",)),
    Brand("Binance", "crypto", ("binance.com",), ("binance",)),
)

_SPLIT = re.compile(r"[^a-z0-9]+|(?<=[a-z])(?=\d)|(?<=\d)(?=[a-z])")

# Visually confusable substitutions used in lookalike domains.
_HOMOGLYPHS = (
    ("rn", "m"),
    ("vv", "w"),
    ("0", "o"),
    ("1", "l"),
    ("3", "e"),
    ("5", "s"),
    ("@", "a"),
    ("!", "i"),
)


def tokens(text: str) -> list[str]:
    return [t for t in _SPLIT.split(text.lower()) if t]


def deconfuse(label: str) -> str:
    out = label.lower()
    for a, b in _HOMOGLYPHS:
        out = out.replace(a, b)
    return out.replace("-", "")


def levenshtein(a: str, b: str, limit: int = 3) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_official(host: str, brand: Brand) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in brand.official_domains)


def official_brand(host: str, brands: tuple[Brand, ...] | list[Brand]) -> Brand | None:
    for brand in brands:
        if is_official(host, brand):
            return brand
    return None


def _keyword_in(keyword: str, labels: list[str], host_tokens: list[str]) -> bool:
    if len(keyword) <= 4:
        return keyword in host_tokens
    return any(keyword in label.replace("-", "") for label in labels)


@dataclass
class BrandMatch:
    brand: Brand
    # keyword | lookalike
    how: str
    detail: str


def _lookalike_limit(label: str) -> int:
    # Short names are easily one or two letters from another real name ("ecobank"/"gcbbank"),
    # so they only count as lookalikes at a distance of one.
    return 1 if len(label) < 8 else 2


def match_host(host: str, brands: tuple[Brand, ...] | list[Brand]) -> BrandMatch | None:
    """Does a hostname that is *not* a brand's own claim or imitate a known brand?"""
    host = host.lower().rstrip(".")
    if official_brand(host, brands):
        return None  # another real brand's own domain is never an impersonation
    labels = host.split(".")
    host_tokens = tokens(host)
    all_keywords = {k for b in brands for k in b.keywords}
    for brand in brands:
        for kw in brand.keywords:
            if _keyword_in(kw, labels, host_tokens):
                return BrandMatch(brand, "keyword", kw)
    for brand in brands:
        for official in brand.official_domains:
            official_label = official.split(".")[0]
            if len(official_label) < 5:
                continue
            # Whole labels and their hyphenated parts ("gcbbamk-secure" -> "gcbbamk").
            parts = labels + [p for label in labels for p in label.split("-") if p != label]
            for label in parts:
                if label == official_label:
                    return BrandMatch(brand, "keyword", official_label)
                if label in all_keywords:
                    continue
                plain = deconfuse(label)
                if plain == official_label or (
                    len(label) >= 5
                    and 0 < levenshtein(label, official_label, 2) <= _lookalike_limit(label)
                ):
                    return BrandMatch(brand, "lookalike", f"{label} ≈ {official_label}")
    return None


def mentioned_brands(text: str, brands: tuple[Brand, ...] | list[Brand]) -> list[Brand]:
    """Brands named in free text ("MTN MoMo", "GRA", "Ghana Card")."""
    lowered = text.lower()
    found = []
    for brand in brands:
        words = {brand.name.lower(), *brand.keywords}
        for word in words:
            pattern = r"(?<![a-z0-9])" + re.escape(word).replace(r"\ ", r"\s*") + r"(?![a-z0-9])"
            if re.search(pattern, lowered):
                found.append(brand)
                break
    return found
