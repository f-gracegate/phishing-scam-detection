"""Business workspace: analytics, investigation cases, API keys, usage, webhooks, brands."""

import secrets
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import OrgContext, org_scope
from app.api.v1.intelligence import BrandIn, brand_out, clean_brand
from app.billing.service import ensure_can_grow
from app.core.db import get_db
from app.core.errors import APIError, not_found
from app.core.redis import rate_limit
from app.fetcher.net import UnsafeTarget
from app.intelligence.service import CATEGORY_LABELS
from app.models import (
    ApiKey,
    ApiUsage,
    BrandProfile,
    Case,
    CaseEvent,
    Membership,
    Notification,
    ScamReport,
    Scan,
    User,
    WebhookDelivery,
    WebhookEndpoint,
)
from app.scanning.service import _org_plan_code
from app.security.rbac import Perm
from app.security.tokens import encrypt_secret, hash_token
from app.services import audit, webhooks
from app.services.plans import get_plan

router = APIRouter(prefix="/business", tags=["Business"])


# --- Analytics -------------------------------------------------------------------------------


@router.get("/analytics")
def analytics(
    days: int = Query(default=30, ge=1, le=365),
    ctx: OrgContext = Depends(org_scope(Perm.ANALYTICS_READ)),
    db: Session = Depends(get_db),
) -> dict:
    since = datetime.now(UTC) - timedelta(days=days)
    base = select(Scan).where(Scan.organisation_id == ctx.org_id, Scan.created_at >= since)
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    by_verdict = dict(
        db.execute(
            select(Scan.verdict, func.count())
            .where(Scan.organisation_id == ctx.org_id, Scan.created_at >= since)
            .group_by(Scan.verdict)
        ).all()
    )
    by_kind = dict(
        db.execute(
            select(Scan.kind, func.count())
            .where(Scan.organisation_id == ctx.org_id, Scan.created_at >= since)
            .group_by(Scan.kind)
        ).all()
    )
    by_category = db.execute(
        select(Scan.category, func.count())
        .where(
            Scan.organisation_id == ctx.org_id,
            Scan.created_at >= since,
            Scan.category.is_not(None),
            Scan.verdict.in_(("suspicious", "high", "critical")),
        )
        .group_by(Scan.category)
        .order_by(func.count().desc())
        .limit(8)
    ).all()
    day = func.date_trunc("day", Scan.created_at)
    trend_rows = db.execute(
        select(day, func.count(), func.count().filter(Scan.verdict.in_(("high", "critical"))))
        .where(Scan.organisation_id == ctx.org_id, Scan.created_at >= since)
        .group_by(day)
        .order_by(day)
    ).all()
    domains: dict[str, int] = {}
    for (artifacts,) in db.execute(
        select(Scan.artifacts)
        .where(
            Scan.organisation_id == ctx.org_id,
            Scan.created_at >= since,
            Scan.verdict.in_(("suspicious", "high", "critical")),
        )
        .limit(2000)
    ):
        link = (artifacts or {}).get("link") or {}
        d = link.get("domain")
        email = (artifacts or {}).get("email") or {}
        sender = (email.get("from") or "").rsplit("@", 1)[-1].strip("> ") if email else ""
        for value in filter(None, (d, sender)):
            domains[value] = domains.get(value, 0) + 1
    reports = (
        db.scalar(
            select(func.count()).where(
                ScamReport.organisation_id == ctx.org_id, ScamReport.created_at >= since
            )
        )
        or 0
    )
    open_cases = (
        db.scalar(
            select(func.count()).where(Case.organisation_id == ctx.org_id, Case.status != "closed")
        )
        or 0
    )
    api_calls = (
        db.scalar(
            select(func.coalesce(func.sum(ApiUsage.quantity), 0)).where(
                ApiUsage.organisation_id == ctx.org_id, ApiUsage.day >= since.date()
            )
        )
        or 0
    )
    high = by_verdict.get("high", 0) + by_verdict.get("critical", 0)
    return {
        "days": days,
        "total_scans": total,
        "high_risk": high,
        "suspicious": by_verdict.get("suspicious", 0),
        "phishing_detections": high + by_verdict.get("suspicious", 0),
        "by_verdict": {k or "pending": v for k, v in by_verdict.items()},
        "by_kind": by_kind,
        "categories": [
            {"category": c, "label": CATEGORY_LABELS.get(c, c), "count": n} for c, n in by_category
        ],
        "trend": [
            {"day": d.date().isoformat(), "scans": n, "high_risk": h} for d, n, h in trend_rows
        ],
        "suspicious_domains": [
            {"domain": k, "count": v}
            for k, v in sorted(domains.items(), key=lambda kv: -kv[1])[:10]
        ],
        "employee_reports": reports,
        "active_investigations": open_cases,
        "api_calls": int(api_calls),
    }


@router.get("/report.pdf")
def monthly_report(
    month: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}$"),
    ctx: OrgContext = Depends(org_scope(Perm.ANALYTICS_READ)),
    db: Session = Depends(get_db),
) -> Response:
    """Monthly security report (PDF) for the organisation."""
    from app.reports.business import monthly_pdf

    today = date.today()
    year, mon = (int(month[:4]), int(month[5:])) if month else (today.year, today.month)
    data = monthly_pdf(db, ctx.organisation, year, mon)
    return Response(
        data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="security-report-{year}-{mon:02d}.pdf"'
        },
    )


# --- Cases ---------------------------------------------------------------------------------------


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=10_000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    category: str | None = Field(default=None, max_length=32)
    assignee_id: uuid.UUID | None = None
    scan_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    report_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)


class CasePatch(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    status: Literal["open", "investigating", "closed"] | None = None
    outcome: Literal["true_positive", "false_positive", "benign", "inconclusive"] | None = None
    assignee_id: uuid.UUID | None = None
    add_scan_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)


class NoteIn(BaseModel):
    message: str = Field(min_length=1, max_length=10_000)


def _name(db: Session, user_id) -> str | None:
    if not user_id:
        return None
    u = db.get(User, user_id)
    return (u.full_name or u.email) if u else None


def _case_out(db: Session, c: Case) -> dict:
    return {
        "id": c.id,
        "reference": c.reference,
        "title": c.title,
        "description": c.description,
        "status": c.status,
        "severity": c.severity,
        "category": c.category,
        "category_label": CATEGORY_LABELS.get(c.category or ""),
        "assignee_id": c.assignee_id,
        "assignee": _name(db, c.assignee_id),
        "created_by": _name(db, c.created_by),
        "scan_ids": c.scan_ids,
        "report_ids": c.report_ids,
        "outcome": c.outcome,
        "closed_at": c.closed_at,
        "created_at": c.created_at,
        "updated_at": c.updated_at,
    }


def _check_assignee(db: Session, ctx: OrgContext, user_id: uuid.UUID | None) -> None:
    if user_id is None:
        return
    m = db.scalar(
        select(Membership).where(
            Membership.organisation_id == ctx.org_id,
            Membership.user_id == user_id,
            Membership.status == "active",
        )
    )
    if m is None:
        raise APIError(422, "invalid_assignee", "The assignee must be a member of this workspace.")


def _own_scans(db: Session, ctx: OrgContext, ids: list[uuid.UUID]) -> list[str]:
    if not ids:
        return []
    found = db.scalars(
        select(Scan.id).where(Scan.id.in_(ids), Scan.organisation_id == ctx.org_id)
    ).all()
    return [str(i) for i in found]


@router.get("/cases")
def list_cases(
    status: str | None = None,
    ctx: OrgContext = Depends(org_scope(Perm.CASES_READ)),
    db: Session = Depends(get_db),
) -> list[dict]:
    q = select(Case).where(Case.organisation_id == ctx.org_id)
    if status == "open":
        q = q.where(Case.status != "closed")
    elif status:
        q = q.where(Case.status == status)
    return [_case_out(db, c) for c in db.scalars(q.order_by(Case.updated_at.desc()).limit(500))]


@router.post("/cases", status_code=201)
def create_case(
    body: CaseIn,
    request: Request,
    ctx: OrgContext = Depends(org_scope(Perm.CASES_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    _check_assignee(db, ctx, body.assignee_id)
    n = (db.scalar(select(func.count()).where(Case.organisation_id == ctx.org_id)) or 0) + 1
    c = Case(
        organisation_id=ctx.org_id,
        reference=f"CASE-{n:04d}",
        title=body.title,
        description=body.description,
        severity=body.severity,
        category=body.category,
        assignee_id=body.assignee_id,
        created_by=ctx.user.id,
        scan_ids=_own_scans(db, ctx, body.scan_ids),
        report_ids=[str(r) for r in body.report_ids],
    )
    db.add(c)
    db.flush()
    db.add(
        CaseEvent(
            case_id=c.id,
            organisation_id=ctx.org_id,
            actor_id=ctx.user.id,
            actor_label=ctx.user.full_name or ctx.user.email,
            kind="created",
            message=f"Case opened: {c.title}",
        )
    )
    if c.assignee_id and c.assignee_id != ctx.user.id:
        db.add(
            Notification(
                user_id=c.assignee_id,
                organisation_id=ctx.org_id,
                kind="case_assigned",
                severity=c.severity,
                title=f"{c.reference} assigned to you",
                body=c.title,
                link=f"/business/cases/{c.id}",
            )
        )
    webhooks.emit(
        db,
        ctx.org_id,
        "case.created",
        {"case_id": str(c.id), "reference": c.reference, "severity": c.severity},
    )
    audit.record(
        db,
        "case.created",
        actor=ctx.user,
        organisation_id=ctx.org_id,
        resource_type="case",
        resource_id=c.id,
        request=request,
    )
    db.commit()
    return _case_out(db, c)


def _get_case(db: Session, ctx: OrgContext, case_id: uuid.UUID) -> Case:
    c = db.scalar(select(Case).where(Case.id == case_id, Case.organisation_id == ctx.org_id))
    if c is None:
        raise not_found("Case")
    return c


@router.get("/cases/{case_id}")
def get_case(
    case_id: uuid.UUID,
    ctx: OrgContext = Depends(org_scope(Perm.CASES_READ)),
    db: Session = Depends(get_db),
) -> dict:
    from app.api.v1.scans import scan_out

    c = _get_case(db, ctx, case_id)
    events = db.scalars(
        select(CaseEvent).where(CaseEvent.case_id == c.id).order_by(CaseEvent.created_at)
    ).all()
    scans = (
        db.scalars(
            select(Scan).where(
                Scan.id.in_([uuid.UUID(s) for s in c.scan_ids]), Scan.organisation_id == ctx.org_id
            )
        ).all()
        if c.scan_ids
        else []
    )
    return {
        **_case_out(db, c),
        "events": [
            {
                "id": e.id,
                "kind": e.kind,
                "message": e.message,
                "actor": e.actor_label,
                "created_at": e.created_at,
            }
            for e in events
        ],
        "scans": [scan_out(s) for s in scans],
    }


@router.patch("/cases/{case_id}")
def update_case(
    case_id: uuid.UUID,
    body: CasePatch,
    request: Request,
    ctx: OrgContext = Depends(org_scope(Perm.CASES_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    c = _get_case(db, ctx, case_id)
    label = ctx.user.full_name or ctx.user.email
    changes = body.model_dump(exclude_unset=True, exclude={"add_scan_ids"})
    if "assignee_id" in changes:
        _check_assignee(db, ctx, body.assignee_id)
        if body.assignee_id != c.assignee_id:
            db.add(
                CaseEvent(
                    case_id=c.id,
                    organisation_id=ctx.org_id,
                    actor_id=ctx.user.id,
                    actor_label=label,
                    kind="assigned",
                    message=f"Assigned to {_name(db, body.assignee_id) or 'nobody'}",
                )
            )
            if body.assignee_id and body.assignee_id != ctx.user.id:
                db.add(
                    Notification(
                        user_id=body.assignee_id,
                        organisation_id=ctx.org_id,
                        kind="case_assigned",
                        severity=c.severity,
                        title=f"{c.reference} assigned to you",
                        body=c.title,
                        link=f"/business/cases/{c.id}",
                    )
                )
    if body.status and body.status != c.status:
        if body.status == "closed" and not (body.outcome or c.outcome):
            raise APIError(422, "outcome_required", "Choose an outcome before closing the case.")
        db.add(
            CaseEvent(
                case_id=c.id,
                organisation_id=ctx.org_id,
                actor_id=ctx.user.id,
                actor_label=label,
                kind="status",
                message=f"Status changed from {c.status} to {body.status}",
            )
        )
        c.closed_at = datetime.now(UTC) if body.status == "closed" else None
        if body.status == "closed":
            webhooks.emit(
                db,
                ctx.org_id,
                "case.closed",
                {
                    "case_id": str(c.id),
                    "reference": c.reference,
                    "outcome": body.outcome or c.outcome,
                },
            )
    for k, v in changes.items():
        setattr(c, k, v)
    if body.add_scan_ids:
        added = [s for s in _own_scans(db, ctx, body.add_scan_ids) if s not in c.scan_ids]
        if added:
            c.scan_ids = [*c.scan_ids, *added]
            db.add(
                CaseEvent(
                    case_id=c.id,
                    organisation_id=ctx.org_id,
                    actor_id=ctx.user.id,
                    actor_label=label,
                    kind="linked",
                    message=f"Linked {len(added)} scan(s)",
                )
            )
    audit.record(
        db,
        "case.updated",
        actor=ctx.user,
        organisation_id=ctx.org_id,
        resource_type="case",
        resource_id=c.id,
        details={"fields": sorted(changes)},
        request=request,
    )
    db.commit()
    return _case_out(db, c)


@router.post("/cases/{case_id}/notes", status_code=201)
def add_note(
    case_id: uuid.UUID,
    body: NoteIn,
    ctx: OrgContext = Depends(org_scope(Perm.CASES_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    c = _get_case(db, ctx, case_id)
    e = CaseEvent(
        case_id=c.id,
        organisation_id=ctx.org_id,
        actor_id=ctx.user.id,
        actor_label=ctx.user.full_name or ctx.user.email,
        kind="note",
        message=body.message,
    )
    db.add(e)
    c.updated_at = datetime.now(UTC)
    db.commit()
    return {
        "id": e.id,
        "kind": e.kind,
        "message": e.message,
        "actor": e.actor_label,
        "created_at": e.created_at,
    }


# --- API keys and usage ------------------------------------------------------------------------


class ApiKeyIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    expires_in_days: int | None = Field(default=365, ge=1, le=730)


def _key_out(k: ApiKey) -> dict:
    return {
        "id": k.id,
        "name": k.name,
        "prefix": k.prefix,
        "status": k.status,
        "created_at": k.created_at,
        "last_used_at": k.last_used_at,
        "expires_at": k.expires_at,
        "revoked_at": k.revoked_at,
    }


def _require_api_plan(db: Session, ctx: OrgContext, feature: str = "api") -> None:
    plan = get_plan(_org_plan_code(db, ctx.organisation))
    if feature == "api" and not plan.api_access:
        raise APIError(402, "plan_required", "API access isn't included in your plan.")
    if feature == "webhooks" and not plan.webhooks:
        raise APIError(
            402, "plan_required", "Webhooks are included from the Business Professional plan."
        )


@router.get("/api-keys")
def list_keys(
    ctx: OrgContext = Depends(org_scope(Perm.API_MANAGE)), db: Session = Depends(get_db)
) -> list[dict]:
    return [
        _key_out(k)
        for k in db.scalars(
            select(ApiKey)
            .where(ApiKey.organisation_id == ctx.org_id, ApiKey.kind == "business")
            .order_by(ApiKey.created_at.desc())
        )
    ]


@router.post("/api-keys", status_code=201)
def create_key(
    body: ApiKeyIn,
    request: Request,
    ctx: OrgContext = Depends(org_scope(Perm.API_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    _require_api_plan(db, ctx)
    ensure_can_grow(db, ctx.org_id)
    rate_limit(f"apikey-create:{ctx.org_id}", limit=20, window_seconds=3600)
    secret = "psk_" + secrets.token_urlsafe(32)
    key = ApiKey(
        organisation_id=ctx.org_id,
        kind="business",
        name=body.name,
        prefix=secret[:12],
        key_hash=hash_token(secret),
        scopes=["scans"],
        created_by=ctx.user.id,
        expires_at=datetime.now(UTC) + timedelta(days=body.expires_in_days)
        if body.expires_in_days
        else None,
    )
    db.add(key)
    db.flush()
    audit.record(
        db,
        "api_key.created",
        actor=ctx.user,
        organisation_id=ctx.org_id,
        resource_type="api_key",
        resource_id=key.id,
        details={"name": body.name},
        request=request,
    )
    db.commit()
    return {**_key_out(key), "secret": secret}


@router.delete("/api-keys/{key_id}")
def revoke_key(
    key_id: uuid.UUID,
    request: Request,
    ctx: OrgContext = Depends(org_scope(Perm.API_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    key = db.scalar(select(ApiKey).where(ApiKey.id == key_id, ApiKey.organisation_id == ctx.org_id))
    if key is None:
        raise not_found("API key")
    key.status, key.revoked_at = "revoked", datetime.now(UTC)
    audit.record(
        db,
        "api_key.revoked",
        actor=ctx.user,
        organisation_id=ctx.org_id,
        resource_type="api_key",
        resource_id=key.id,
        request=request,
    )
    db.commit()
    return _key_out(key)


@router.get("/usage")
def api_usage(
    days: int = Query(default=30, ge=1, le=366),
    ctx: OrgContext = Depends(org_scope(Perm.API_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    from app.billing.service import usage

    since = date.today() - timedelta(days=days)
    rows = db.execute(
        select(ApiUsage.day, ApiUsage.endpoint, ApiUsage.quantity)
        .where(ApiUsage.organisation_id == ctx.org_id, ApiUsage.day >= since)
        .order_by(ApiUsage.day)
    ).all()
    plan = get_plan(_org_plan_code(db, ctx.organisation))
    return {
        "plan": plan.name,
        "monthly_scans": plan.monthly_scans,
        "scans_this_month": usage(db, ctx.org_id).scans_this_month,
        "api": [{"day": d.isoformat(), "endpoint": e, "quantity": q} for d, e, q in rows],
        "api_total": sum(q for _, _, q in rows),
    }


# --- Webhooks ----------------------------------------------------------------------------------


class WebhookIn(BaseModel):
    url: HttpUrl
    description: str = Field(default="", max_length=200)
    events: list[
        Literal[
            "scan.completed",
            "scan.high_risk",
            "case.created",
            "case.closed",
            "report.status_changed",
        ]
    ] = Field(min_length=1)


def _hook_out(db: Session, w: WebhookEndpoint) -> dict:
    last = db.scalar(
        select(WebhookDelivery)
        .where(WebhookDelivery.endpoint_id == w.id)
        .order_by(WebhookDelivery.created_at.desc())
        .limit(1)
    )
    return {
        "id": w.id,
        "url": w.url,
        "description": w.description,
        "events": w.events,
        "active": w.active,
        "consecutive_failures": w.consecutive_failures,
        "created_at": w.created_at,
        "last_delivery": {
            "status": last.status,
            "response_status": last.response_status,
            "error": last.last_error,
            "at": last.created_at,
        }
        if last
        else None,
    }


@router.get("/webhooks")
def list_webhooks(
    ctx: OrgContext = Depends(org_scope(Perm.WEBHOOKS_MANAGE)), db: Session = Depends(get_db)
) -> list[dict]:
    return [
        _hook_out(db, w)
        for w in db.scalars(
            select(WebhookEndpoint).where(WebhookEndpoint.organisation_id == ctx.org_id)
        )
    ]


@router.post("/webhooks", status_code=201)
def create_webhook(
    body: WebhookIn,
    request: Request,
    ctx: OrgContext = Depends(org_scope(Perm.WEBHOOKS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    _require_api_plan(db, ctx, "webhooks")
    ensure_can_grow(db, ctx.org_id)
    url = str(body.url)
    try:
        webhooks.check_target(url)
    except (UnsafeTarget, LookupError) as exc:
        raise APIError(422, "invalid_webhook_url", str(exc)) from exc
    secret = "whsec_" + secrets.token_urlsafe(32)
    w = WebhookEndpoint(
        organisation_id=ctx.org_id,
        url=url,
        description=body.description,
        events=sorted(set(body.events)),
        secret_encrypted=encrypt_secret(secret),
        created_by=ctx.user.id,
    )
    db.add(w)
    db.flush()
    audit.record(
        db,
        "webhook.created",
        actor=ctx.user,
        organisation_id=ctx.org_id,
        resource_type="webhook",
        resource_id=w.id,
        details={"url": url},
        request=request,
    )
    db.commit()
    return {**_hook_out(db, w), "secret": secret}


@router.post("/webhooks/{webhook_id}/test")
def test_webhook(
    webhook_id: uuid.UUID,
    ctx: OrgContext = Depends(org_scope(Perm.WEBHOOKS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    w = db.scalar(
        select(WebhookEndpoint).where(
            WebhookEndpoint.id == webhook_id, WebhookEndpoint.organisation_id == ctx.org_id
        )
    )
    if w is None:
        raise not_found("Webhook")
    rate_limit(f"webhook-test:{w.id}", limit=10, window_seconds=600)
    d = WebhookDelivery(
        endpoint_id=w.id,
        organisation_id=ctx.org_id,
        event="ping",
        payload={
            "id": uuid.uuid4().hex,
            "event": "ping",
            "created_at": datetime.now(UTC).isoformat(),
            "data": {"message": "Test delivery"},
        },
    )
    db.add(d)
    db.flush()
    ok = webhooks.deliver(db, d)
    db.commit()
    return {"delivered": ok, "response_status": d.response_status, "error": d.last_error}


@router.delete("/webhooks/{webhook_id}")
def delete_webhook(
    webhook_id: uuid.UUID,
    request: Request,
    ctx: OrgContext = Depends(org_scope(Perm.WEBHOOKS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    w = db.scalar(
        select(WebhookEndpoint).where(
            WebhookEndpoint.id == webhook_id, WebhookEndpoint.organisation_id == ctx.org_id
        )
    )
    if w is None:
        raise not_found("Webhook")
    db.delete(w)
    audit.record(
        db,
        "webhook.deleted",
        actor=ctx.user,
        organisation_id=ctx.org_id,
        resource_type="webhook",
        resource_id=webhook_id,
        request=request,
    )
    db.commit()
    return {"deleted": True}


# --- The organisation's own brands -------------------------------------------------------------


@router.get("/brands")
def list_org_brands(
    ctx: OrgContext = Depends(org_scope(Perm.ANALYTICS_READ)), db: Session = Depends(get_db)
) -> list[dict]:
    return [
        brand_out(b)
        for b in db.scalars(select(BrandProfile).where(BrandProfile.organisation_id == ctx.org_id))
    ]


@router.post("/brands", status_code=201)
def add_org_brand(
    body: BrandIn,
    request: Request,
    ctx: OrgContext = Depends(org_scope(Perm.BRANDS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    count = db.scalar(select(func.count()).where(BrandProfile.organisation_id == ctx.org_id)) or 0
    if count >= 20:
        raise APIError(409, "too_many_brands", "A workspace can protect up to 20 brands.")
    data = clean_brand(body) | {"verified": False}
    b = BrandProfile(organisation_id=ctx.org_id, **data)
    db.add(b)
    db.flush()
    audit.record(
        db,
        "brand.created",
        actor=ctx.user,
        organisation_id=ctx.org_id,
        resource_type="brand",
        resource_id=b.id,
        request=request,
    )
    db.commit()
    return brand_out(b)


@router.delete("/brands/{brand_id}")
def delete_org_brand(
    brand_id: uuid.UUID,
    ctx: OrgContext = Depends(org_scope(Perm.BRANDS_MANAGE)),
    db: Session = Depends(get_db),
) -> dict:
    b = db.scalar(
        select(BrandProfile).where(
            BrandProfile.id == brand_id, BrandProfile.organisation_id == ctx.org_id
        )
    )
    if b is None:
        raise not_found("Brand")
    db.delete(b)
    db.commit()
    return {"deleted": True}
