"""Business workspace: analytics, cases, bulk scans, API keys, usage, webhooks, brands."""

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.cli import seed_platform
from app.core.db import SessionLocal
from app.main import app
from app.models import Subscription, WebhookDelivery
from app.services import webhooks
from tests.conftest import invite_and_join


@pytest.fixture
def system_db():
    db = SessionLocal()
    db.info["rls"] = {"bypass": True}
    seed_platform(db)
    db.commit()
    yield db
    db.close()


def set_plan(db, code):
    sub = db.scalar(select(Subscription))
    sub.plan_code = code
    db.commit()


def test_analytics_and_monthly_report(owner, system_db):
    owner.post("/api/v1/scans/message", {"text": "Pay the customs clearance fee now, urgent"})
    owner.post("/api/v1/scans/message", {"text": "Hello team"})
    a = owner.get("/api/v1/business/analytics").json()
    assert a["total_scans"] == 2 and a["by_kind"] == {"message": 2}
    assert a["trend"] and a["trend"][0]["scans"] == 2
    r = owner.get("/api/v1/business/report.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert b"Helvetica" not in r.content and b"Poppins" in r.content


def test_case_workflow(owner, system_db):
    analyst = invite_and_join(owner, "esi@acme.example.com", "security_analyst")
    scan = owner.post("/api/v1/scans/message", {"text": "Verify your account now"}).json()
    r = analyst.post(
        "/api/v1/business/cases",
        {"title": "Payroll phishing", "severity": "high", "scan_ids": [scan["id"]]},
    )
    case = r.json()
    assert r.status_code == 201 and case["reference"] == "CASE-0001"
    assert case["scan_ids"] == [scan["id"]]
    base = f"/api/v1/business/cases/{case['id']}"
    assert (
        analyst.post(f"{base}/notes", {"message": "Blocked sender at gateway"}).status_code == 201
    )
    r = analyst.patch(base, {"status": "closed"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "outcome_required"
    r = analyst.patch(base, {"status": "closed", "outcome": "true_positive"})
    assert r.json()["status"] == "closed" and r.json()["closed_at"]
    detail = analyst.get(base).json()
    assert [e["kind"] for e in detail["events"]] == ["created", "note", "status"]
    assert detail["scans"][0]["id"] == scan["id"]
    employee = invite_and_join(owner, "kofi@acme.example.com", "employee")
    assert employee.get("/api/v1/business/cases").status_code == 403


def test_cases_cannot_link_another_organisations_scans(owner, system_db):
    from tests.conftest import create_org, register

    other = register("x@other.example.com")
    create_org(other, "Other Ltd")
    foreign = other.post("/api/v1/scans/message", {"text": "hello"}).json()
    case = owner.post(
        "/api/v1/business/cases", {"title": "Test", "scan_ids": [foreign["id"]]}
    ).json()
    assert case["scan_ids"] == []


def test_bulk_scanning(owner, system_db):
    r = owner.post(
        "/api/v1/scans/bulk",
        {
            "items": [
                {"kind": "url", "content": "https://bit.ly/x"},
                {"kind": "message", "content": "You have won a prize! Claim your reward"},
                {"kind": "url", "content": "not a url"},
            ]
        },
    )
    assert r.status_code == 202
    batch = owner.get(f"/api/v1/scans/batches/{r.json()['batch_id']}").json()
    assert batch["total"] == 2 and batch["completed"] == 2


def test_api_keys_usage_and_rate_of_plan(owner, system_db):
    r = owner.post("/api/v1/business/api-keys", {"name": "Fraud engine"})
    assert r.status_code == 201
    key = r.json()["secret"]
    assert (
        key.startswith("psk_")
        and owner.get("/api/v1/business/api-keys").json()[0]["prefix"] == key[:12]
    )
    api = TestClient(app)
    h = {"authorization": f"Bearer {key}"}
    res = api.post("/api/v1/scans/message", json={"text": "Send your OTP"}, headers=h)
    assert res.status_code == 201 and res.json()["source"] == "api"
    assert res.json()["organisation_id"] == owner.org_id
    assert api.get("/api/v1/scans", headers=h).json()["total"] == 1
    # API keys can't manage the workspace.
    assert api.get("/api/v1/business/api-keys", headers=h).status_code == 401
    usage = owner.get("/api/v1/business/usage").json()
    assert usage["api_total"] == 1 and usage["api"][0]["endpoint"] == "scans.message"
    kid = owner.get("/api/v1/business/api-keys").json()[0]["id"]
    owner.delete(f"/api/v1/business/api-keys/{kid}")
    assert api.get("/api/v1/scans", headers=h).status_code == 401


def test_monthly_quota_for_organisations(owner, system_db, monkeypatch):
    from app.services import plans

    monkeypatch.setitem(plans.PLANS, "sme", plans.Plan("sme", "SME", 250, 10, 1, ()))
    set_plan(system_db, "sme")
    assert owner.post("/api/v1/scans/message", {"text": "one"}).status_code == 201
    r = owner.post("/api/v1/scans/message", {"text": "two"})
    assert r.status_code == 402 and r.json()["error"]["code"] == "quota_exceeded"


def test_webhooks_are_signed_and_need_the_plan(owner, system_db, monkeypatch):
    set_plan(system_db, "sme")
    r = owner.post(
        "/api/v1/business/webhooks",
        {"url": "https://hooks.example.com/psd", "events": ["scan.high_risk"]},
    )
    assert r.status_code == 402
    set_plan(system_db, "professional")
    monkeypatch.setattr(webhooks, "check_target", lambda url: None)
    r = owner.post(
        "/api/v1/business/webhooks",
        {"url": "https://hooks.example.com/psd", "events": ["scan.high_risk"]},
    )
    assert r.status_code == 201
    secret = r.json()["secret"]

    owner.post(
        "/api/v1/scans/message",
        {
            "text": "MTN MoMo: money sent by mistake, reverse it now. Dial *170# and enter "
            "your PIN to approve or your wallet will be blocked within 24 hours"
        },
    )
    delivery = system_db.scalar(select(WebhookDelivery))
    assert delivery and delivery.event == "scan.high_risk"

    sent = {}

    class Resp:
        status_code = 200

    def fake_post(url, content, headers, **kw):
        sent.update(url=url, body=content, headers=headers)
        return Resp()

    monkeypatch.setattr(webhooks.httpx, "post", fake_post)
    assert webhooks.deliver_due(system_db) == 1
    system_db.commit()
    ts, sig = (p.split("=", 1)[1] for p in sent["headers"]["X-PSD-Signature"].split(","))
    expected = hmac.new(
        secret.encode(), f"{ts}.".encode() + sent["body"], hashlib.sha256
    ).hexdigest()
    assert hmac.compare_digest(sig, expected)
    assert json.loads(sent["body"])["data"]["verdict"] in {"high", "critical"}


def test_webhook_urls_cannot_point_inside(owner, system_db):
    set_plan(system_db, "professional")
    r = owner.post(
        "/api/v1/business/webhooks",
        {"url": "http://169.254.169.254/latest", "events": ["scan.completed"]},
    )
    assert r.status_code == 422


def test_organisation_brand_protection(owner, system_db):
    r = owner.post(
        "/api/v1/business/brands",
        {
            "name": "Kwik Pay",
            "category": "ecommerce",
            "official_domains": ["kwikpay.com.gh"],
            "keywords": ["kwikpay"],
        },
    )
    assert r.status_code == 201
    scan = owner.post(
        "/api/v1/scans/url",
        {"url": "https://kwikpay-login.xyz/", "scan_options": {"check_website": False}},
    ).json()
    assert any(e["code"] == "brand_impersonation_domain" for e in scan["evidence"])
    # Other organisations (and consumers) don't get this private brand.
    from tests.conftest import register

    person = register("ama@example.com")
    scan = person.post(
        "/api/v1/scans/url",
        {"url": "https://kwikpay-login.xyz/", "scan_options": {"check_website": False}},
    ).json()
    assert not any(e["code"] == "brand_impersonation_domain" for e in scan["evidence"])
