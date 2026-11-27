"""Commercial plans. Prices are the proposed launch prices (GH₵), pending market validation.

Personal plans (Free, Personal Plus) belong to a person; business plans to an organisation.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Plan:
    code: str
    name: str
    monthly_price_ghs: int | None
    member_limit: int | None
    # Scans per calendar month for the whole organisation (None = custom / unlimited).
    monthly_scans: int | None
    features: tuple[str, ...]
    api_access: bool = False
    webhooks: bool = False
    # The longest raw submitted content may be kept.
    max_retention_days: int = 30
    personal: bool = False


PERSONAL_PLANS: dict[str, Plan] = {
    "free": Plan(
        "free",
        "Free",
        0,
        1,
        None,
        (
            "20 checks a day",
            "Link, message and email checks",
            "Plain-language explanations",
            "30-day scan history",
            "Community scam reporting",
        ),
        personal=True,
    ),
    "plus": Plan(
        "plus",
        "Personal Plus",
        25,
        1,
        None,
        (
            "300 checks a day",
            "Website deep scans",
            "QR code checks",
            "1-year scan history",
            "Browser extension and mobile protection features",
        ),
        personal=True,
        max_retention_days=365,
    ),
}

PLANS: dict[str, Plan] = {
    "sme": Plan(
        "sme",
        "SME",
        250,
        10,
        2_000,
        (
            "Business dashboard",
            "Up to 10 team members",
            "2,000 scans a month",
            "Bulk link and message checks",
            "Investigation records",
            "Monthly security report",
            "Basic API allowance",
        ),
        api_access=True,
        max_retention_days=90,
    ),
    "professional": Plan(
        "professional",
        "Business Professional",
        750,
        50,
        10_000,
        (
            "Up to 50 team members",
            "10,000 scans a month",
            "Full API access",
            "Webhooks",
            "Advanced reporting",
            "Investigation workflows",
            "Priority support",
        ),
        api_access=True,
        webhooks=True,
        max_retention_days=180,
    ),
    "enterprise": Plan(
        "enterprise",
        "Enterprise",
        None,
        None,
        None,
        (
            "Custom API volume",
            "Dedicated integrations",
            "Bulk analysis",
            "Custom retention",
            "Enterprise support and service levels",
        ),
        api_access=True,
        webhooks=True,
        max_retention_days=365,
    ),
}


def get_plan(code: str) -> Plan:
    return PLANS.get(code, PLANS["sme"])
