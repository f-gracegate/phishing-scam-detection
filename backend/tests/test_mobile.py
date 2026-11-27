import time
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import SessionLocal
from app.main import app
from app.models import Notification, PushDevice
from app.services import push
from tests.conftest import PASSWORD, enable_mfa, invite_and_join, register


@pytest.fixture
def system_db():
    db = SessionLocal()
    db.info["rls"] = {"bypass": True}
    yield db
    db.close()


class Phone:
    """The mobile app: bearer tokens, no cookies, no CSRF header."""

    def __init__(self) -> None:
        self.client = TestClient(app)
        self.tokens: dict | None = None
        self.org_id: str | None = None

    def headers(self) -> dict:
        h = {"user-agent": "PSD-Mobile/1.0 (iOS 19)"}
        if self.tokens:
            h["authorization"] = f"Bearer {self.tokens['access_token']}"
        if self.org_id:
            h["x-organisation-id"] = self.org_id
        return h

    def login(self, identifier: str, password: str = PASSWORD) -> dict:
        r = self.client.post(
            "/api/v1/auth/login",
            json={"identifier": identifier, "password": password, "client": "mobile"},
            headers=self.headers(),
        )
        assert r.status_code == 200, r.text
        body = r.json()
        if body["tokens"]:
            self.tokens = body["tokens"]
        self.client.cookies.clear()
        return body

    def get(self, url, **kw):
        return self.client.get(url, headers=self.headers(), **kw)

    def post(self, url, json=None):
        return self.client.post(url, json=json, headers=self.headers())

    def put(self, url, json=None):
        return self.client.put(url, json=json, headers=self.headers())

    def delete(self, url):
        return self.client.delete(url, headers=self.headers())

    def register_device(self, token="fcm-token-0123456789abcdef", platform="ios"):  # noqa: S107
        r = self.post(
            "/api/v1/me/push-devices",
            {
                "platform": platform,
                "token": token,
                "device_name": "Ama's iPhone",
                "app_version": "1.0.0",
            },
        )
        assert r.status_code == 201, r.text
        return r.json()


@pytest.fixture
def phone(owner):
    p = Phone()
    body = p.login("owner@acme.example.com")
    p.org_id = body["me"]["memberships"][0]["organisation_id"]
    return p


def test_mobile_login_returns_tokens_and_sets_no_cookies(owner):
    p = Phone()
    r = p.client.post(
        "/api/v1/auth/login",
        json={"identifier": "owner@acme.example.com", "password": PASSWORD, "client": "mobile"},
    )
    body = r.json()
    assert body["status"] == "ok" and body["tokens"]["token_type"] == "bearer"
    assert body["tokens"]["expires_in"] == 15 * 60
    assert "set-cookie" not in r.headers
    # Web sign-in is unchanged: cookies, no tokens in the body.
    web = TestClient(app).post(
        "/api/v1/auth/login", json={"identifier": "owner@acme.example.com", "password": PASSWORD}
    )
    assert web.json()["tokens"] is None and "psd_access" in web.cookies


def test_bearer_requests_work_without_csrf(phone):
    assert phone.get("/api/v1/scans").status_code == 200
    r = phone.post("/api/v1/scans/message", {"text": "Your parcel is held at customs"})
    assert r.status_code == 201 and r.json()["source"] == "mobile"


def test_mobile_refresh_rotates_and_detects_reuse(phone):
    old = phone.tokens
    r = phone.client.post("/api/v1/auth/refresh", json={"refresh_token": old["refresh_token"]})
    assert r.status_code == 200, r.text
    new = r.json()["tokens"]
    assert new["refresh_token"] != old["refresh_token"]
    phone.tokens = new
    assert phone.get("/api/v1/auth/me").status_code == 200

    # Presenting the old token again ends the session: someone copied it.
    r = phone.client.post("/api/v1/auth/refresh", json={"refresh_token": old["refresh_token"]})
    assert r.status_code == 401
    assert phone.get("/api/v1/auth/me").status_code == 401


def test_a_web_refresh_token_cannot_be_used_as_a_mobile_one(owner):
    web_refresh = owner.client.cookies.get("psd_refresh")
    r = TestClient(app).post("/api/v1/auth/refresh", json={"refresh_token": web_refresh})
    assert r.status_code == 401


def test_mobile_mfa_sign_in(owner):
    totp = enable_mfa(owner)
    p = Phone()
    body = p.login("owner@acme.example.com")
    assert body["status"] == "mfa_required" and body["tokens"] is None
    r = p.client.post(
        "/api/v1/auth/mfa/verify",
        # The next 30-second code: the current one was just used to turn MFA on.
        json={
            "mfa_token": body["mfa_token"],
            "code": totp.at(time.time() + 30),
            "client": "mobile",
        },
    )
    assert r.status_code == 200 and r.json()["tokens"]["access_token"]


def test_device_registration_is_private_to_its_owner(phone, owner):
    device = phone.register_device()
    assert device["this_device"] and device["platform"] == "ios"
    # Re-registering the same token refreshes the same row.
    assert phone.register_device()["id"] == device["id"]
    assert len(phone.get("/api/v1/me/push-devices").json()) == 1

    analyst = invite_and_join(owner, "analyst@acme.example.com", "security_analyst")
    assert analyst.get("/api/v1/me/push-devices").json() == []
    assert analyst.delete(f"/api/v1/me/push-devices/{device['id']}").status_code == 404

    # Someone else can't claim a token while its owner is still signed in on that phone...
    p2 = Phone()
    p2.login("analyst@acme.example.com")
    r = p2.post(
        "/api/v1/me/push-devices",
        {"platform": "ios", "token": "fcm-token-0123456789abcdef"},
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "device_in_use"
    # ...but once the owner signs out, the next person on the phone takes it over.
    phone.post("/api/v1/auth/logout")
    p2.register_device()
    assert len(p2.get("/api/v1/me/push-devices").json()) == 1


def test_push_token_is_encrypted_at_rest(phone, system_db):
    phone.register_device(token="fcm-secret-token-abcdefghijkl")
    row = system_db.scalar(select(PushDevice))
    assert "fcm-secret-token" not in row.token_encrypted and len(row.token_hash) == 64


def _notify(phone, db, severity="critical", kind="scan_completed", age_minutes=0):
    me = phone.get("/api/v1/auth/me").json()
    db.add(
        Notification(
            user_id=me["user"]["id"],
            organisation_id=phone.org_id,
            kind=kind,
            severity=severity,
            title="High-risk link submitted",
            body="Fake MTN MoMo page at mtn-momo-reversal.example",
            link="/business/scans/abc",
            created_at=datetime.now(UTC) - timedelta(minutes=age_minutes),
        )
    )
    db.commit()


def test_only_high_risk_and_requested_updates_are_pushed(phone, system_db):
    phone.register_device()
    _notify(phone, system_db, severity="medium")
    assert push.dispatch_pending(system_db) == 0
    assert system_db.scalar(select(Notification).where(Notification.pushed_at.is_(None))) is None
    _notify(phone, system_db, severity="critical")
    _notify(phone, system_db, severity="info", kind="report_update")
    assert push.dispatch_pending(system_db) == 2
    sent = push.read_dev_pushes()
    assert any(p["title"].startswith("Critical · Acme Ltd") for p in sent)
    # Lock-screen privacy: the body names the result but not the details.
    assert all("mtn-momo-reversal" not in p["body"] for p in sent)


def test_old_notifications_are_not_pushed(phone, system_db):
    phone.register_device()
    _notify(phone, system_db, age_minutes=120)
    assert push.dispatch_pending(system_db) == 0


def test_signing_out_stops_pushes_to_that_phone(phone, system_db):
    phone.register_device()
    _notify(phone, system_db)
    assert phone.post("/api/v1/auth/logout").status_code == 200
    assert push.dispatch_pending(system_db) == 0


def test_invalid_tokens_are_disabled(phone, owner, monkeypatch, system_db):
    phone.register_device()

    def gone(*a, **kw):
        raise push.InvalidToken("UNREGISTERED")

    monkeypatch.setattr(push.LogProvider, "send", gone)
    r = phone.post("/api/v1/me/push-devices/test")
    assert r.status_code == 502
    device = phone.get("/api/v1/me/push-devices").json()[0]
    assert device["enabled"] is False and "uninstalled" in device["last_error"]


def test_test_push(phone):
    assert phone.post("/api/v1/me/push-devices/test").status_code == 404
    phone.register_device()
    r = phone.post("/api/v1/me/push-devices/test")
    assert r.status_code == 200 and "1 device" in r.json()["message"]
    assert "Test notification" in push.read_dev_pushes()[0]["body"]


def test_dev_push_outbox(phone):
    phone.register_device()
    phone.post("/api/v1/me/push-devices/test")
    assert len(register("x@y.example.com").get("/api/v1/dev/push").json()) == 1
