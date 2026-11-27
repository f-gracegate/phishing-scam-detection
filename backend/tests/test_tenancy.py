"""Tenant isolation and authorisation: the scenarios the release rule depends on."""

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import ProgrammingError

from app.core.db import SessionLocal, set_tenant_context
from app.models import AuditLog, Scan
from tests.conftest import create_org, invite_and_join, register

MSG = {"text": "Hello, are we still meeting at 3pm?"}


@pytest.fixture
def two_tenants():
    a = register("a@alpha.example.com")
    create_org(a, "Alpha Ltd")
    b = register("b@beta.example.com")
    create_org(b, "Beta Ltd")
    scan_b = b.post("/api/v1/scans/message", MSG).json()
    return a, b, scan_b


def test_user_cannot_read_another_organisations_scan(two_tenants):
    a, b, scan_b = two_tenants
    assert a.get(f"/api/v1/scans/{scan_b['id']}").status_code == 404
    assert a.delete(f"/api/v1/scans/{scan_b['id']}").status_code == 404
    r = a.get(f"/api/v1/scans/{scan_b['id']}", headers={"x-organisation-id": b.org_id})
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "organisation_not_found"
    assert a.get(f"/api/v1/organisations/{b.org_id}/members").status_code == 404
    assert a.get("/api/v1/scans").json()["total"] == 0


def test_employer_never_sees_personal_scans(owner):
    employee = invite_and_join(owner, "kofi@acme.example.com", "employee")
    employee.org_id = None
    personal = employee.post("/api/v1/scans/message", MSG).json()
    assert personal["organisation_id"] is None
    owner_scans = owner.get("/api/v1/scans").json()
    assert owner_scans["total"] == 0
    assert owner.get(f"/api/v1/scans/{personal['id']}").status_code == 404
    # And the person's own personal history doesn't include workspace scans.
    employee.org_id = owner.org_id
    work = employee.post("/api/v1/scans/message", MSG).json()
    employee.org_id = None
    ids = [s["id"] for s in employee.get("/api/v1/scans").json()["items"]]
    assert personal["id"] in ids and work["id"] not in ids
    assert owner.get(f"/api/v1/scans/{work['id']}").status_code == 200


def test_employees_see_only_their_own_workspace_scans(owner):
    a = invite_and_join(owner, "ama@acme.example.com", "employee")
    b = invite_and_join(owner, "yaw@acme.example.com", "employee")
    scan_a = a.post("/api/v1/scans/message", MSG).json()
    assert b.get(f"/api/v1/scans/{scan_a['id']}").status_code == 404
    assert b.get("/api/v1/scans").json()["total"] == 0
    analyst = invite_and_join(owner, "esi@acme.example.com", "security_analyst")
    assert analyst.get(f"/api/v1/scans/{scan_a['id']}").json()["submitted_by"]


def test_row_level_security_blocks_cross_tenant_rows_in_the_database(two_tenants):
    a, b, _ = two_tenants
    a.post("/api/v1/scans/message", MSG)
    db = SessionLocal()
    db.info["rls"] = {}
    assert db.scalars(select(Scan)).all() == []
    db.rollback()
    set_tenant_context(db, org=a.org_id)
    rows = db.scalars(select(Scan)).all()
    assert rows and {str(r.organisation_id) for r in rows} == {a.org_id}
    db.close()


def test_audit_log_is_append_only_for_the_application(owner):
    owner.post("/api/v1/scans/message", MSG)
    db = SessionLocal()
    db.info["rls"] = {}
    set_tenant_context(db, org=owner.org_id)
    assert db.scalars(select(AuditLog)).first() is not None
    with pytest.raises(ProgrammingError):
        db.execute(text("UPDATE audit_logs SET action = 'tampered'"))
    db.rollback()
    set_tenant_context(db, org=owner.org_id)
    with pytest.raises(ProgrammingError):
        db.execute(text("DELETE FROM audit_logs"))
    db.close()


def test_removed_member_loses_access_immediately(owner):
    member = invite_and_join(owner, "tech@acme.example.com", "security_analyst")
    assert member.get("/api/v1/scans").status_code == 200
    members = owner.get(f"/api/v1/organisations/{owner.org_id}/members").json()
    tech = next(m for m in members if m["email"] == "tech@acme.example.com")
    assert (
        owner.delete(f"/api/v1/organisations/{owner.org_id}/members/{tech['id']}").status_code
        == 204
    )
    assert member.get("/api/v1/scans").status_code == 404


def test_suspended_member_loses_access(owner):
    member = invite_and_join(owner, "temp@acme.example.com", "security_analyst")
    mid = next(
        m["id"]
        for m in owner.get(f"/api/v1/organisations/{owner.org_id}/members").json()
        if m["email"] == "temp@acme.example.com"
    )
    owner.patch(f"/api/v1/organisations/{owner.org_id}/members/{mid}", {"status": "suspended"})
    assert member.get("/api/v1/scans").status_code == 404


def test_privilege_escalation_is_refused(owner):
    admin = invite_and_join(owner, "admin@acme.example.com", "admin")
    members = admin.get(f"/api/v1/organisations/{owner.org_id}/members").json()
    me = next(m for m in members if m["is_you"])
    the_owner = next(m for m in members if m["role"] == "owner")
    base = f"/api/v1/organisations/{owner.org_id}/members"
    assert admin.patch(f"{base}/{me['id']}", {"role": "owner"}).status_code == 409
    assert admin.patch(f"{base}/{the_owner['id']}", {"role": "employee"}).status_code == 403
    assert admin.delete(f"{base}/{the_owner['id']}").status_code == 403
    r = admin.post(
        f"/api/v1/organisations/{owner.org_id}/invitations",
        {"email": "boss@acme.example.com", "role": "owner"},
    )
    assert r.status_code == 403


def test_last_owner_cannot_be_removed_or_demoted(owner):
    second = invite_and_join(owner, "co@acme.example.com", "owner")
    members = second.get(f"/api/v1/organisations/{owner.org_id}/members").json()
    first = next(m for m in members if m["email"] == "owner@acme.example.com")
    base = f"/api/v1/organisations/{owner.org_id}/members"
    assert second.patch(f"{base}/{first['id']}", {"role": "admin"}).status_code == 200
    me = next(m for m in members if m["is_you"])
    owner_now_admin = owner
    assert owner_now_admin.patch(f"{base}/{me['id']}", {"role": "admin"}).status_code == 403


@pytest.mark.parametrize(
    ("role", "can_read_all", "can_read_audit", "can_manage_members", "can_manage_cases"),
    [
        ("admin", True, True, True, True),
        ("security_analyst", True, False, False, True),
        ("reviewer", True, False, False, False),
        ("employee", False, False, False, False),
    ],
)
def test_role_permissions_are_enforced_by_the_api(
    owner, role, can_read_all, can_read_audit, can_manage_members, can_manage_cases
):
    owner_scan = owner.post("/api/v1/scans/message", MSG).json()
    member = invite_and_join(owner, f"{role}@acme.example.com", role)
    assert member.post("/api/v1/scans/message", MSG).status_code == 201
    r = member.get(f"/api/v1/scans/{owner_scan['id']}")
    assert (r.status_code == 200) is can_read_all
    assert (member.get("/api/v1/audit-logs").status_code == 200) is can_read_audit
    r = member.post(
        f"/api/v1/organisations/{owner.org_id}/invitations",
        {"email": "x@acme.example.com", "role": "employee"},
    )
    assert (r.status_code == 201) is can_manage_members
    r = member.post("/api/v1/business/cases", {"title": "Phishing wave"})
    assert (r.status_code == 201) is can_manage_cases


def test_invitation_only_works_for_the_invited_email(owner):
    r = owner.post(
        f"/api/v1/organisations/{owner.org_id}/invitations",
        {"email": "right@acme.example.com", "role": "employee"},
    )
    token = r.json()["invite_url"].rsplit("/", 1)[1]
    wrong = register("wrong@elsewhere.example.com")
    r = wrong.post("/api/v1/auth/invitations/accept", {"token": token})
    assert r.status_code == 403
    assert wrong.get("/api/v1/organisations").json() == []


def test_organisation_mfa_requirement(owner):
    from tests.conftest import enable_mfa

    member = invite_and_join(owner, "nomfa@acme.example.com", "security_analyst")
    # The owner must use MFA before requiring it for everyone.
    r = owner.patch(f"/api/v1/organisations/{owner.org_id}", {"require_mfa": True})
    assert r.status_code == 409
    enable_mfa(owner)
    assert (
        owner.patch(f"/api/v1/organisations/{owner.org_id}", {"require_mfa": True}).status_code
        == 200
    )
    r = member.get("/api/v1/scans")
    assert r.status_code == 403 and r.json()["error"]["code"] == "mfa_enrolment_required"
    enable_mfa(member)
    assert member.get("/api/v1/scans").status_code == 200


def test_platform_console_requires_platform_admin(owner):
    assert owner.get("/api/v1/platform/organisations").status_code == 403
