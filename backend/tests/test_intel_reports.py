"""Scam reports and the analyst workflow: unverified until reviewed, audited, private."""

import pytest
from sqlalchemy import select

from app.cli import seed_platform
from app.core.db import SessionLocal
from app.models import Indicator, Notification, ScamReport, User
from tests.conftest import register

REPORT = {
    "category": "momo",
    "channel": "sms",
    "url": "http://momo-refund.xyz/claim",
    "phone": "024 412 3456",
    "message": "Send your PIN 1234 to receive the refund",
    "description": "They said money was sent by mistake and asked for my PIN.",
    "consent": True,
}


@pytest.fixture
def system_db():
    db = SessionLocal()
    db.info["rls"] = {"bypass": True}
    seed_platform(db)
    db.commit()
    yield db
    db.close()


def make_staff(db, email, role="", admin=False):
    api = register(email)
    user = db.scalar(select(User).where(User.email == email))
    user.platform_role, user.is_platform_admin = role, admin
    db.commit()
    return api


def test_report_starts_unverified_with_private_details_protected(system_db):
    person = register("ama@example.com")
    r = person.post("/api/v1/reports", REPORT, headers={"idempotency-key": "abc-1"})
    assert r.status_code == 201, r.text
    report = r.json()
    assert report["status"] == "unverified" and report["phone"] == "024 *** 3456"
    # Idempotent retries don't create duplicates.
    again = person.post("/api/v1/reports", REPORT, headers={"idempotency-key": "abc-1"})
    assert again.json()["id"] == report["id"]
    row = system_db.scalar(select(ScamReport))
    assert "0244123456" not in (row.phone_encrypted or "") and "1234" not in row.description
    indicators = system_db.scalars(select(Indicator)).all()
    assert {i.status for i in indicators} == {"unverified"}
    phone = next(i for i in indicators if i.type == "phone")
    assert phone.value is None and phone.display_value == "024 *** 3456"


def test_reports_need_consent_and_something_to_report():
    person = register("ama@example.com")
    assert person.post("/api/v1/reports", {**REPORT, "consent": False}).status_code == 422
    r = person.post(
        "/api/v1/reports",
        {
            "category": "other",
            "channel": "sms",
            "description": "Something odd happened",
            "consent": True,
        },
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "nothing_reported"


def test_people_see_only_their_own_reports(system_db):
    a = register("a@example.com")
    report = a.post("/api/v1/reports", REPORT).json()
    b = register("b@example.com")
    assert b.get(f"/api/v1/reports/{report['id']}").status_code == 404
    assert b.get("/api/v1/reports").json() == []


def test_console_is_staff_only(system_db):
    person = register("ama@example.com")
    assert person.get("/api/v1/intelligence/overview").status_code == 403
    reviewer = make_staff(system_db, "rev@gracegate.example", role="reviewer")
    assert reviewer.get("/api/v1/intelligence/overview").status_code == 200
    assert reviewer.get("/api/v1/intelligence/sources").status_code == 200
    assert (
        reviewer.patch("/api/v1/intelligence/sources/urlhaus", {"enabled": True}).status_code == 403
    )


def test_reviewers_triage_but_only_analysts_verify(system_db):
    person = register("ama@example.com")
    report = person.post("/api/v1/reports", REPORT).json()
    reviewer = make_staff(system_db, "rev@gracegate.example", role="reviewer")
    analyst = make_staff(system_db, "ana@gracegate.example", role="analyst")
    base = f"/api/v1/intelligence/reports/{report['id']}"

    queue = reviewer.get("/api/v1/intelligence/reports").json()
    assert queue["total"] == 1 and queue["items"][0]["phone"] == "024 *** 3456"
    assert reviewer.post(f"{base}/review", {"decision": "start_review"}).status_code == 200
    r = reviewer.post(f"{base}/review", {"decision": "verify", "notes": "Looks real enough"})
    assert r.status_code == 403
    detail = analyst.get(base).json()
    assert detail["report"]["full_phone"] is None  # hidden unless deliberately revealed
    assert (
        "[code removed]" in detail["report"]["message"] or "1234" not in detail["report"]["message"]
    )
    r = analyst.post(
        f"{base}/review",
        {
            "decision": "verify",
            "confidence": "high",
            "notes": "Domain hosts a fake MoMo refund page; phone matches 3 reports.",
            "public_note": "Thanks — we confirmed this scam and now warn others.",
        },
    )
    assert r.status_code == 200 and r.json()["status"] == "verified"
    statuses = {i.type: i.status for i in system_db.scalars(select(Indicator))}
    assert statuses["url"] == "verified" and statuses["phone"] == "verified"
    note = system_db.scalar(select(Notification).where(Notification.kind == "report_update"))
    assert note is not None
    mine = person.get(f"/api/v1/reports/{report['id']}").json()
    assert mine["status"] == "verified" and mine["public_note"].startswith("Thanks")
    history = analyst.get(f"/api/v1/intelligence/indicators/{detail['indicators'][0]['id']}")
    assert history.json()["history"][0]["to_status"] == "verified"


def test_revealing_a_phone_number_is_audited(system_db):
    from app.models import AuditLog

    person = register("ama@example.com")
    report = person.post("/api/v1/reports", REPORT).json()
    analyst = make_staff(system_db, "ana@gracegate.example", role="analyst")
    detail = analyst.get(f"/api/v1/intelligence/reports/{report['id']}?reveal=true").json()
    assert detail["report"]["full_phone"] == "+233244123456"
    assert system_db.scalar(select(AuditLog).where(AuditLog.action == "report.phone_revealed"))


def test_verified_indicators_can_be_revoked_and_stop_matching(system_db):
    analyst = make_staff(system_db, "ana@gracegate.example", role="analyst")
    r = analyst.post(
        "/api/v1/intelligence/indicators",
        {
            "type": "domain",
            "value": "fake-gra-portal.example",
            "category": "government",
            "status": "verified",
            "confidence": "high",
            "evidence_summary": "Phishing kit collecting TIN and Ghana Card numbers.",
        },
    )
    assert r.status_code == 201, r.text
    ind = r.json()
    person = register("ama@example.com")
    scan = person.post(
        "/api/v1/scans/url",
        {"url": "https://fake-gra-portal.example/", "scan_options": {"check_website": False}},
    ).json()
    assert scan["verdict"] == "critical"
    r = analyst.post(
        f"/api/v1/intelligence/indicators/{ind['id']}/review",
        {
            "decision": "revoke",
            "reason": "Domain taken down and re-registered by a legitimate business.",
        },
    )
    assert r.json()["status"] == "revoked"
    scan = person.post(
        "/api/v1/scans/url",
        {"url": "https://fake-gra-portal.example/", "scan_options": {"check_website": False}},
    ).json()
    assert scan["verdict"] != "critical"


def test_false_positive_feedback_queue(system_db):
    person = register("ama@example.com")
    scan = person.post("/api/v1/scans/message", {"text": "You have won! Claim your prize"}).json()
    person.post(
        f"/api/v1/scans/{scan['id']}/feedback",
        {"kind": "false_positive", "comment": "It's my bank's promo"},
    )
    reviewer = make_staff(system_db, "rev@gracegate.example", role="reviewer")
    queue = reviewer.get("/api/v1/intelligence/feedback").json()
    assert len(queue) == 1 and queue[0]["comment"] == "It's my bank's promo"
    r = reviewer.post(
        f"/api/v1/intelligence/feedback/{queue[0]['id']}/resolve",
        {"status": "accepted", "resolution": "Genuine promotion; rule tuned."},
    )
    assert r.status_code == 200
    assert reviewer.get("/api/v1/intelligence/feedback").json() == []


def test_campaigns_need_public_text_before_publishing(system_db):
    analyst = make_staff(system_db, "ana@gracegate.example", role="analyst")
    body = {"name": "Fake GRA refunds", "category": "government", "published": True}
    assert analyst.post("/api/v1/intelligence/campaigns", body).status_code == 422
    body |= {
        "public_title": "Fake tax refund texts",
        "public_summary": "GRA doesn't send refund links by SMS.",
    }
    assert analyst.post("/api/v1/intelligence/campaigns", body).status_code == 201


def test_sources_need_a_licence_and_admin_to_enable(system_db):
    admin = make_staff(system_db, "boss@gracegate.example", admin=True)
    r = admin.patch("/api/v1/intelligence/sources/urlhaus", {"licence": "", "enabled": True})
    assert r.status_code == 422
    r = admin.patch("/api/v1/intelligence/sources/urlhaus", {"enabled": True})
    assert r.status_code == 200 and r.json()["enabled"] is True
    r = admin.post("/api/v1/intelligence/staff", {"email": "ama@example.com", "role": "analyst"})
    assert r.status_code == 404
    register("ama@example.com")
    r = admin.post("/api/v1/intelligence/staff", {"email": "ama@example.com", "role": "reviewer"})
    assert r.json()["role"] == "reviewer"


def test_account_deletion_keeps_reports_but_removes_the_link(system_db):
    from tests.conftest import PASSWORD

    person = register("ama@example.com")
    person.post("/api/v1/scans/message", {"text": "hello"})
    report = person.post("/api/v1/reports", {**REPORT, "contact_email": "ama@example.com"})
    export = person.get("/api/v1/me/export").json()
    assert len(export["scans"]) == 1 and len(export["reports"]) == 1
    assert "password_hash" not in export["profile"]
    assert person.post("/api/v1/me/delete-account", {"password": PASSWORD}).status_code == 200
    row = system_db.get(ScamReport, __import__("uuid").UUID(report.json()["id"]))
    assert row.reporter_id is None and row.contact_email is None
    from app.models import Scan

    assert system_db.scalars(select(Scan)).all() == []
