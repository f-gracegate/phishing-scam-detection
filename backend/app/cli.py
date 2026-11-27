"""Operational commands.

python -m app.cli seed          administrator, intelligence sources and brand catalogue
python -m app.cli seed --demo   also a demo organisation and clearly fake demo threats
"""

import argparse
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select

from app.core.config import settings
from app.core.db import SessionLocal, system_context
from app.detection.brands import CATALOGUE
from app.intelligence.service import change_status, upsert_indicator
from app.models import (
    BrandProfile,
    Department,
    IntelligenceSource,
    Membership,
    Organisation,
    Subscription,
    ThreatCampaign,
    User,
)
from app.security.passwords import hash_password, password_policy_errors
from app.security.rbac import Role
from app.services import audit

DEMO_ORG_NAME = "Demo Business Ltd"

SOURCES = [
    dict(
        code="internal",
        name="GraceGate analysts",
        kind="internal",
        licence="Internal",
        permitted_use="All platform uses",
        default_confidence="high",
        recheck_days=90,
    ),
    dict(
        code="community",
        name="Community reports",
        kind="community",
        licence="Submitted by users under the reporting terms",
        permitted_use="Unverified until an analyst review",
        sharing_restrictions="Never publish reporter details or private message content",
        default_confidence="low",
        recheck_days=30,
    ),
    dict(
        code="customer",
        name="Customer submissions",
        kind="internal",
        licence="Business customer agreements",
        permitted_use="Detection for all customers once verified",
        sharing_restrictions="Customer content stays private; only verified indicators are shared",
        default_confidence="medium",
        recheck_days=60,
    ),
    dict(
        code="google_web_risk",
        name="Google Web Risk",
        kind="commercial",
        licence="Google Cloud Web Risk API terms (commercial)",
        permitted_use="Real-time URL checks; no resale of raw data",
        sharing_restrictions="Do not cache or redistribute results beyond the terms",
        default_confidence="high",
        recheck_days=1,
        enabled=False,
    ),
    dict(
        code="urlhaus",
        name="URLhaus (abuse.ch)",
        kind="feed",
        licence="abuse.ch terms of use (check commercial use before enabling)",
        permitted_use="Malware URL checks",
        default_confidence="high",
        recheck_days=7,
        enabled=False,
    ),
    dict(
        code="phishtank",
        name="PhishTank",
        kind="feed",
        licence="PhishTank terms (check eligibility for commercial use)",
        permitted_use="Phishing URL checks",
        default_confidence="medium",
        recheck_days=7,
        enabled=False,
    ),
]

# Demo threats use reserved domains (.example and .test never exist on the internet), so the
# demo can never label a real business or person.
DEMO_INDICATORS = [
    ("domain", "mtn-momo-reversal.example", "momo", "verified", "high"),
    ("domain", "gra-tax-refund.example", "government", "verified", "high"),
    ("url", "http://ghanapost-parcel.test/pay-customs", "delivery", "verified", "medium"),
    ("domain", "quick-cash-investment.test", "investment", "unverified", "low"),
]


def seed_platform(db) -> None:
    for spec in SOURCES:
        if db.scalar(select(IntelligenceSource).where(IntelligenceSource.code == spec["code"])):
            continue
        db.add(IntelligenceSource(**spec))
    if not db.scalar(select(BrandProfile.id).where(BrandProfile.organisation_id.is_(None))):
        for brand in CATALOGUE:
            db.add(
                BrandProfile(
                    name=brand.name,
                    category=brand.category,
                    official_domains=list(brand.official_domains),
                    keywords=list(brand.keywords),
                    sender_ids=list(brand.sender_ids),
                    verified=False,
                )
            )
        print(f"Added {len(CATALOGUE)} brands to the catalogue (unverified).")
    db.flush()


def seed_demo_intel(db, admin: User) -> None:
    if db.scalar(select(ThreatCampaign).where(ThreatCampaign.name == "Demo: MoMo reversal wave")):
        return
    campaign = ThreatCampaign(
        name="Demo: MoMo reversal wave",
        category="momo",
        status="active",
        published=True,
        public_title='Fake "money sent by mistake" messages',
        public_summary="Messages claim money was sent to you by mistake and ask you to reverse "
        "it or approve a prompt. Check your balance only in your MoMo menu. (Demo warning.)",
        published_at=datetime.now(UTC),
        created_by=admin.id,
        description="Demonstration campaign seeded for development. Not real intelligence.",
    )
    db.add(campaign)
    db.flush()
    for kind, value, category, status, confidence in DEMO_INDICATORS:
        ind = upsert_indicator(db, kind, value, source_code="internal", category=category)
        ind.campaign_id = campaign.id if category == "momo" else None
        ind.evidence_summary = "Demo indicator on a reserved test domain."
        if status == "verified":
            change_status(
                db,
                ind,
                status="verified",
                confidence=confidence,
                actor=admin,
                reason="Development demo data",
                expires_in_days=365,
            )
        else:
            ind.report_count = 3
    print("Added demo threat intelligence (reserved .example/.test domains only).")


def seed(demo: bool) -> None:
    password = settings.seed_admin_password
    db = SessionLocal()
    db.info["rls"] = {}
    with system_context(db):
        seed_platform(db)
        if not password:
            print("SEED_ADMIN_PASSWORD is not set; skipping administrator seed.")
            db.commit()
            db.close()
            return
        if not settings.is_development and password_policy_errors(password):
            sys.exit("Refusing to seed: SEED_ADMIN_PASSWORD is too weak for this environment.")
        admin = db.scalar(
            select(User).where(
                or_(
                    func.lower(User.username) == settings.seed_admin_username.lower(),
                    User.email == settings.seed_admin_email.lower(),
                )
            )
        )
        if admin is None:
            admin = User(
                email=settings.seed_admin_email.lower(),
                username=settings.seed_admin_username,
                full_name="Platform Administrator",
                password_hash=hash_password(password),
                is_platform_admin=True,
                must_change_password=True,
                password_changed_at=datetime.now(UTC),
                email_verified_at=datetime.now(UTC),
            )
            db.add(admin)
            db.flush()
            audit.record(
                db,
                "user.seeded",
                actor=admin,
                resource_type="user",
                resource_id=admin.id,
                actor_label="system",
            )
            print(f"Created administrator '{admin.username}' (password change required).")
        else:
            print(f"Administrator '{admin.username}' already exists; left unchanged.")

        if demo:
            seed_demo_intel(db, admin)
            org = db.scalar(
                select(Organisation)
                .join(Membership, Membership.organisation_id == Organisation.id)
                .where(Organisation.name == DEMO_ORG_NAME, Membership.user_id == admin.id)
            )
            if org is None:
                org = Organisation(
                    name=DEMO_ORG_NAME,
                    industry="retail",
                    size="11-50",
                    phone="+233 30 000 0000",
                    address="Accra, Ghana",
                    created_by=admin.id,
                )
                db.add(org)
                db.flush()
                db.add(Membership(organisation_id=org.id, user_id=admin.id, role=Role.OWNER))
                db.add(
                    Subscription(
                        organisation_id=org.id,
                        plan_code="professional",
                        status="trialing",
                        current_period_end=datetime.now(UTC) + timedelta(days=30),
                    )
                )
                for name in ("Operations", "Finance", "Customer service"):
                    db.add(Department(organisation_id=org.id, name=name))
                audit.record(
                    db,
                    "organisation.created",
                    actor=admin,
                    organisation_id=org.id,
                    resource_type="organisation",
                    resource_id=org.id,
                    details={"name": org.name, "seeded": True},
                )
                print(f"Created demo organisation '{DEMO_ORG_NAME}'.")
        db.commit()
    db.close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    seed_cmd = sub.add_parser("seed")
    seed_cmd.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    if args.command == "seed":
        seed(args.demo)


if __name__ == "__main__":
    main()
