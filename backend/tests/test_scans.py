"""Scanning API: end-to-end scans with the website fetcher mocked, quotas, privacy, API keys."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.cli import seed_demo_intel, seed_platform
from app.core.db import SessionLocal
from app.main import app
from app.models import Scan, User
from app.scanning import service
from tests.conftest import register


@pytest.fixture
def system_db():
    db = SessionLocal()
    db.info["rls"] = {"bypass": True}
    yield db
    db.close()


@pytest.fixture(autouse=True)
def platform(system_db):
    seed_platform(system_db)
    system_db.commit()


@pytest.fixture
def fetched(monkeypatch):
    """Replace the isolated fetcher with canned pages."""
    pages: dict[str, dict] = {}
    calls: list[str] = []

    def fake(url):
        calls.append(url)
        return pages.get(
            url, {"requested_url": url, "ok": False, "error": "No DNS record", "hops": []}
        )

    monkeypatch.setattr(service, "fetch_website", fake)
    return pages, calls


@pytest.fixture
def person():
    return register("ama@example.com", "Ama Mensah")


def test_unknown_link_is_unknown_not_safe(person, fetched):
    r = person.post("/api/v1/scans/url", {"url": "https://new-bakery.example.com/menu"})
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["status"] == "completed" and scan["verdict"] == "unknown"
    assert scan["verdict_label"] == "Unknown"
    assert any(e["code"] == "unreachable" for e in scan["evidence"])
    assert scan["artifacts"]["link"]["domain"] == "example.com"


def test_phishing_page_end_to_end(person, fetched):
    pages, calls = fetched
    final = "https://mtn-momo-verify.xyz/login"
    pages["https://bit.ly/abc"] = {
        "requested_url": "https://bit.ly/abc",
        "ok": True,
        "final_url": final,
        "status": 200,
        "content_type": "text/html",
        "headers": {},
        "body": "<title>MTN MoMo Login</title><form><input type=password name=pin></form>",
        "hops": [
            {"url": "https://bit.ly/abc", "status": 301, "location": final},
            {"url": final, "status": 200, "location": None},
        ],
        "tls": None,
    }
    scan = person.post("/api/v1/scans/url", {"url": "bit.ly/abc"}).json()
    assert calls == ["https://bit.ly/abc"]
    assert scan["verdict"] in {"high", "critical"}, scan
    found = {e["code"] for e in scan["evidence"]}
    assert {"credential_harvest", "url_shortener", "cross_domain_redirect"} <= found
    # Signals about where the link really lands are judged too.
    assert any(e["title"].startswith("Final destination") for e in scan["evidence"])
    assert scan["artifacts"]["link"]["website"]["final_url"] == final
    sources = {e["source_label"] for e in scan["evidence"]}
    assert "Verified threat intelligence" not in sources  # our rules, not a confirmed match


def test_verified_indicator_makes_it_critical(person, fetched, system_db):
    admin = User(email="analyst@example.com", password_hash="x", is_platform_admin=True)
    system_db.add(admin)
    system_db.flush()
    seed_demo_intel(system_db, admin)
    system_db.commit()
    scan = person.post(
        "/api/v1/scans/url", {"url": "http://login.mtn-momo-reversal.example/pin"}
    ).json()
    assert scan["verdict"] == "critical" and scan["confidence"] == "high"
    top = scan["evidence"][0]
    assert top["source_kind"] == "verified_intel" and "verified" in top["title"]
    assert top["data"]["matched"] == "mtn-momo-reversal.example"
    # Unverified community reports only ever give a weak, labelled signal.
    scan = person.post("/api/v1/scans/url", {"url": "https://quick-cash-investment.test/"}).json()
    community = next(e for e in scan["evidence"] if e["code"] == "community_reports")
    assert community["source_label"] == "Community reports (unverified)"
    assert community["weight"] <= 30 and scan["verdict"] != "critical"


def test_secret_tokens_are_never_stored_or_visited(person, fetched, system_db):
    _, calls = fetched
    person.post("/api/v1/scans/url", {"url": "https://bank.example.com/reset?token=SECRET123"})
    assert calls and "SECRET123" not in calls[0]
    scan = system_db.scalar(select(Scan))
    assert "SECRET123" not in scan.title and "SECRET123" not in str(scan.artifacts)


def test_message_scan_with_links_and_phone_numbers(person, fetched):
    r = person.post(
        "/api/v1/scans/message",
        {
            "text": "MTN MoMo: your wallet is blocked. Verify at mtn-momo-help.xyz/kyc within 24 "
            "hours or call 0244123456. Your OTP 551234",
            "sender": "0201234567",
        },
    )
    scan = r.json()
    assert scan["verdict"] in {"high", "critical"}
    found = {e["code"] for e in scan["evidence"]}
    assert {"brand_link_mismatch", "brand_impersonation_domain", "account_threat"} <= found
    ex = scan["artifacts"]["extracted"]
    assert ex["phones"] == ["024 *** 3456"] and "one_time_code" in ex["removed_secrets"]
    assert "551234" not in scan["title"]


def test_email_scan_from_raw_source(person, fetched):
    from tests.test_detection import RAW_EMAIL

    scan = person.post("/api/v1/scans/email", {"raw": RAW_EMAIL}).json()
    assert scan["kind"] == "email" and scan["title"] == "Urgent: verify your account"
    assert scan["verdict"] in {"high", "critical"}
    assert scan["artifacts"]["email"]["authentication"]["dmarc"] == "fail"
    assert scan["artifacts"]["email"]["attachments"][0]["filename"] == "statement.pdf.exe"


def test_email_file_upload(person, fetched):
    r = person.client.post(
        "/api/v1/scans/email/file",
        files={
            "file": ("message.eml", b"From: a@b.example\nSubject: Hi\n\nHello", "message/rfc822")
        },
        headers=person._headers(),
    )
    assert r.status_code == 201 and r.json()["kind"] == "email"


def test_qr_payload_with_url_and_with_text(person, fetched):
    url_scan = person.post("/api/v1/scans/qr", {"payload": "https://bit.ly/pay-now"}).json()
    assert url_scan["kind"] == "qr" and url_scan["artifacts"]["qr"]["decoded_as"] == "url"
    text_scan = person.post(
        "/api/v1/scans/qr", {"payload": "Send GHS 50 registration fee to 0244000111"}
    ).json()
    assert text_scan["artifacts"]["qr"]["decoded_as"] == "text"
    assert any(e["code"] == "fee_request" for e in text_scan["evidence"])


def test_history_feedback_delete_and_clear(person, fetched):
    a = person.post("/api/v1/scans/message", {"text": "Hello there"}).json()
    person.post("/api/v1/scans/message", {"text": "You have won a prize, claim your reward"})
    page = person.get("/api/v1/scans").json()
    assert page["total"] == 2
    assert person.get("/api/v1/scans?verdict=unknown").json()["total"] == 1
    r = person.post(
        f"/api/v1/scans/{a['id']}/feedback", {"kind": "false_negative", "comment": "It was a scam"}
    )
    assert r.status_code == 200
    assert person.get(f"/api/v1/scans/{a['id']}").json()["feedback"] == "false_negative"
    assert person.delete(f"/api/v1/scans/{a['id']}").status_code == 200
    assert person.get(f"/api/v1/scans/{a['id']}").status_code == 404
    assert "1 scan" in person.delete("/api/v1/scans").json()["message"]


def test_people_cannot_see_each_others_scans(person, fetched):
    scan = person.post("/api/v1/scans/message", {"text": "Hello"}).json()
    other = register("kwame@example.com")
    assert other.get(f"/api/v1/scans/{scan['id']}").status_code == 404
    assert (
        other.post(f"/api/v1/scans/{scan['id']}/feedback", {"kind": "correct"}).status_code == 404
    )


def test_free_daily_quota(person, fetched, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "free_daily_scans", 2)
    assert person.post("/api/v1/scans/message", {"text": "one"}).status_code == 201
    assert person.post("/api/v1/scans/message", {"text": "two"}).status_code == 201
    r = person.post("/api/v1/scans/message", {"text": "three"})
    assert r.status_code == 429 and r.json()["error"]["code"] == "daily_limit_reached"
    assert person.get("/api/v1/scans/quota").json() == {
        "scope": "personal",
        "limit": 2,
        "used": 2,
        "period": "day",
    }


def test_external_lookups_respect_the_privacy_choice(person, fetched, monkeypatch, system_db):
    from app.intelligence import providers
    from app.models import IntelligenceSource

    seen = []

    class Fake(providers.Provider):
        code, name = "google_web_risk", "Google Web Risk"

        def enabled(self):
            return True

        def check(self, url):
            seen.append(url.lookup_url)
            return providers.ProviderResult(self.code, True, "SOCIAL_ENGINEERING")

    monkeypatch.setattr(providers, "PROVIDERS", [Fake()])
    src = system_db.scalar(
        select(IntelligenceSource).where(IntelligenceSource.code == "google_web_risk")
    )
    src.enabled = True
    system_db.commit()

    off = person.post(
        "/api/v1/scans/url",
        {
            "url": "https://phish.example.net/?session=abc",
            "privacy": {"allow_external_intelligence_lookup": False},
        },
    ).json()
    assert seen == [] and any(e["code"] == "external_lookup_off" for e in off["evidence"])
    on = person.post("/api/v1/scans/url", {"url": "https://phish.example.net/?session=abc"}).json()
    assert seen == ["https://phish.example.net/"]  # the private token was stripped
    assert on["verdict"] in {"high", "critical"} and on["confidence"] == "high"
    assert any(e["source_kind"] == "external_provider" for e in on["evidence"])


def test_queued_mode_returns_immediately_and_worker_completes(
    person, monkeypatch, fetched, system_db
):
    from app.core.config import settings
    from app.core.redis import redis_client

    monkeypatch.setattr(settings, "scan_inline", False)
    scan = person.post("/api/v1/scans/message", {"text": "Pay the customs fee now"}).json()
    assert scan["status"] == "queued"
    assert redis_client.lpop(service.QUEUE) == scan["id"]
    import uuid

    service.run_scan(system_db, uuid.UUID(scan["id"]))
    done = person.get(f"/api/v1/scans/{scan['id']}").json()
    assert done["status"] == "completed" and done["verdict"]


def test_failed_scans_retry_then_fail(person, monkeypatch, fetched, system_db):
    import uuid

    from app.core.config import settings

    monkeypatch.setattr(settings, "scan_inline", False)
    scan = person.post("/api/v1/scans/message", {"text": "x"}).json()

    def boom(*a, **k):
        raise RuntimeError("analyser crashed")

    monkeypatch.setattr(service, "_execute", boom)
    service.run_scan(system_db, uuid.UUID(scan["id"]))
    assert person.get(f"/api/v1/scans/{scan['id']}").json()["status"] == "queued"
    service.run_scan(system_db, uuid.UUID(scan["id"]))
    failed = person.get(f"/api/v1/scans/{scan['id']}").json()
    assert failed["status"] == "failed" and "try again" in failed["error"]


def test_extension_token_scans_into_personal_history(person, fetched):
    r = person.post("/api/v1/me/extension-tokens", {"name": "Chrome"})
    token = r.json()["token"]
    assert token.startswith("pse_")
    ext = TestClient(app)
    res = ext.post(
        "/api/v1/scans/url",
        json={"url": "https://bit.ly/x"},
        headers={"authorization": f"Bearer {token}"},
    )
    assert res.status_code == 201 and res.json()["source"] == "extension"
    assert person.get("/api/v1/scans").json()["total"] == 1
    tid = person.get("/api/v1/me/extension-tokens").json()[0]["id"]
    person.delete(f"/api/v1/me/extension-tokens/{tid}")
    res = ext.get("/api/v1/scans", headers={"authorization": f"Bearer {token}"})
    assert res.status_code == 401


def test_public_warnings_show_only_published_campaigns(system_db):
    admin = User(email="analyst@example.com", password_hash="x", is_platform_admin=True)
    system_db.add(admin)
    system_db.flush()
    seed_demo_intel(system_db, admin)
    system_db.commit()
    warnings = TestClient(app).get("/api/v1/public/warnings").json()
    assert len(warnings) == 1 and warnings[0]["category"] == "momo"
    assert "name" not in warnings[0]  # internal campaign names stay internal


def test_reputation_endpoint_for_the_extension(person, system_db):
    admin = User(email="analyst@example.com", password_hash="x", is_platform_admin=True)
    system_db.add(admin)
    system_db.flush()
    seed_demo_intel(system_db, admin)
    system_db.commit()
    token = person.post("/api/v1/me/extension-tokens", {"name": "Firefox"}).json()["token"]
    ext = TestClient(app)
    h = {"authorization": f"Bearer {token}"}
    bad = ext.get("/api/v1/scans/reputation?domain=mtn-momo-reversal.example", headers=h).json()
    assert bad["status"] == "verified_malicious" and bad["category"] == "momo"
    ok = ext.get("/api/v1/scans/reputation?domain=example.org", headers=h).json()
    assert ok["status"] == "no_record" and "doesn't make it safe" in ok["message"]
    # Nothing is stored: browsing is never recorded as scans.
    assert person.get("/api/v1/scans").json()["total"] == 0
