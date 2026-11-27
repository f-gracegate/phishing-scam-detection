"""Threat-intelligence analyst console (platform staff only).

Reviewers triage community reports and false-positive feedback. Analysts verify, publish,
downgrade and revoke indicators and manage campaigns. Platform administrators also manage
intelligence sources, the brand catalogue and staff roles. Every decision is audited and
recorded in the indicator's history.
"""

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, intel_scope
from app.core.db import get_db
from app.core.errors import APIError, not_found
from app.intelligence import service as intel
from app.models import (
    AnalystReview,
    BrandProfile,
    Indicator,
    IndicatorHistory,
    IndicatorObservation,
    IntelligenceSource,
    Notification,
    ScamReport,
    Scan,
    ScanFeedback,
    ThreatCampaign,
    User,
)
from app.security.rbac import IntelPerm, PlatformRole
from app.security.tokens import decrypt_secret
from app.services import audit

router = APIRouter(prefix="/intelligence", tags=["Threat intelligence"])

READ = intel_scope(IntelPerm.READ)
REVIEW = intel_scope(IntelPerm.REVIEW)
PUBLISH = intel_scope(IntelPerm.PUBLISH)
ADMIN = intel_scope(IntelPerm.ADMIN)
CONFIDENCE = Literal["low", "medium", "high"]


def _sys(db: Session) -> Session:
    from app.core.db import set_tenant_context

    set_tenant_context(db, bypass=True)
    return db


# --- Overview ------------------------------------------------------------------------------------


@router.get("/overview")
def overview(auth: AuthContext = Depends(READ), db: Session = Depends(get_db)) -> dict:
    _sys(db)
    by_status = dict(
        db.execute(select(Indicator.status, func.count()).group_by(Indicator.status)).all()
    )
    queue = db.scalar(
        select(func.count()).where(ScamReport.status.in_(("unverified", "under_review")))
    )
    feedback = db.scalar(
        select(func.count()).where(ScanFeedback.status == "open", ScanFeedback.kind != "correct")
    )
    since = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    today = dict(
        db.execute(
            select(Scan.verdict, func.count())
            .where(Scan.created_at >= since)
            .group_by(Scan.verdict)
        ).all()
    )
    categories = db.execute(
        select(ScamReport.category, func.count())
        .group_by(ScamReport.category)
        .order_by(func.count().desc())
        .limit(8)
    ).all()
    return {
        "indicators": by_status,
        "report_queue": queue or 0,
        "open_feedback": feedback or 0,
        "scans_today": today,
        "report_categories": [
            {"category": c, "label": intel.CATEGORY_LABELS.get(c, c), "count": n}
            for c, n in categories
        ],
        "active_campaigns": db.scalar(select(func.count()).where(ThreatCampaign.status == "active"))
        or 0,
    }


# --- Indicators ----------------------------------------------------------------------------------


class IndicatorOut(BaseModel):
    id: uuid.UUID
    type: str
    display_value: str
    status: str
    confidence: str
    disposition: str
    category: str | None
    category_label: str | None
    report_count: int
    campaign_id: uuid.UUID | None
    source: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    last_verified_at: datetime | None
    expires_at: datetime | None
    evidence_summary: str | None
    references: list[str]
    notes: str | None


def _ind_out(db: Session, i: Indicator) -> IndicatorOut:
    source = db.get(IntelligenceSource, i.source_id) if i.source_id else None
    return IndicatorOut(
        id=i.id,
        type=i.type,
        display_value=i.display_value,
        status=i.status,
        confidence=i.confidence,
        disposition=i.disposition,
        category=i.category,
        category_label=intel.CATEGORY_LABELS.get(i.category or ""),
        report_count=i.report_count,
        campaign_id=i.campaign_id,
        source=source.name if source else None,
        first_seen_at=i.first_seen_at,
        last_seen_at=i.last_seen_at,
        last_verified_at=i.last_verified_at,
        expires_at=i.expires_at,
        evidence_summary=i.evidence_summary,
        references=i.references or [],
        notes=i.notes,
    )


@router.get("/indicators")
def list_indicators(
    q: str | None = Query(default=None, max_length=200),
    type: str | None = None,
    status: str | None = None,
    category: str | None = None,
    campaign_id: uuid.UUID | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    auth: AuthContext = Depends(READ),
    db: Session = Depends(get_db),
) -> dict:
    _sys(db)
    query = select(Indicator)
    if q:
        term = q.strip()
        conds = [Indicator.display_value.ilike(f"%{term.replace('%', '')}%")]
        for kind in ("url", "domain", "phone", "email"):
            try:
                _, digest, _ = intel.normalise(kind, term)
                conds.append(
                    (Indicator.type == ("phone" if kind == "phone" else kind))
                    & (Indicator.value_hash == digest)
                )
            except intel.InvalidIndicator:
                pass
        query = query.where(or_(*conds))
    if type:
        query = query.where(Indicator.type == type)
    if status:
        query = query.where(Indicator.status == status)
    if category:
        query = query.where(Indicator.category == category)
    if campaign_id:
        query = query.where(Indicator.campaign_id == campaign_id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(
        query.order_by(Indicator.last_seen_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {
        "items": [_ind_out(db, i) for i in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


class IndicatorIn(BaseModel):
    type: Literal["url", "domain", "ip", "phone", "email", "sender_id", "wallet"]
    value: str = Field(min_length=1, max_length=2048)
    category: str | None = Field(default=None, max_length=32)
    status: Literal["unverified", "verified"] = "unverified"
    confidence: CONFIDENCE = "medium"
    disposition: Literal["malicious", "suspicious"] = "malicious"
    evidence_summary: str = Field(min_length=10, max_length=5000)
    references: list[str] = Field(default_factory=list, max_length=20)
    campaign_id: uuid.UUID | None = None
    expires_in_days: int | None = Field(default=180, ge=1, le=730)


@router.post("/indicators", response_model=IndicatorOut, status_code=201)
def create_indicator(
    body: IndicatorIn,
    request: Request,
    auth: AuthContext = Depends(REVIEW),
    db: Session = Depends(get_db),
) -> IndicatorOut:
    from app.security.rbac import intel_permissions

    _sys(db)
    can_publish = IntelPerm.PUBLISH in intel_permissions(
        auth.user.is_platform_admin, auth.user.platform_role
    )
    if body.status == "verified" and not can_publish:
        raise APIError(403, "forbidden", "Only analysts can publish verified indicators.")
    try:
        ind = intel.upsert_indicator(
            db, body.type, body.value, source_code="internal", category=body.category
        )
    except intel.InvalidIndicator as exc:
        raise APIError(422, "invalid_indicator", str(exc)) from exc
    ind.evidence_summary = body.evidence_summary
    ind.references = body.references
    ind.disposition = body.disposition
    ind.campaign_id = body.campaign_id
    if body.status == "verified":
        intel.change_status(
            db,
            ind,
            status="verified",
            confidence=body.confidence,
            actor=auth.user,
            reason=body.evidence_summary,
            expires_in_days=body.expires_in_days,
        )
    audit.record(
        db,
        "indicator.created",
        actor=auth.user,
        resource_type="indicator",
        resource_id=ind.id,
        details={"type": ind.type, "status": ind.status},
        request=request,
    )
    db.commit()
    return _ind_out(db, ind)


@router.get("/indicators/{indicator_id}")
def get_indicator(
    indicator_id: uuid.UUID, auth: AuthContext = Depends(READ), db: Session = Depends(get_db)
) -> dict:
    _sys(db)
    ind = db.get(Indicator, indicator_id)
    if ind is None:
        raise not_found("Indicator")
    history = db.scalars(
        select(IndicatorHistory)
        .where(IndicatorHistory.indicator_id == ind.id)
        .order_by(IndicatorHistory.created_at.desc())
    ).all()
    observations = (
        db.scalar(select(func.count()).where(IndicatorObservation.indicator_id == ind.id)) or 0
    )
    scan_hits = (
        db.scalar(
            select(func.count()).where(
                IndicatorObservation.indicator_id == ind.id,
                IndicatorObservation.scan_id.is_not(None),
            )
        )
        or 0
    )
    reports = db.scalars(
        select(ScamReport)
        .join(IndicatorObservation, IndicatorObservation.report_id == ScamReport.id)
        .where(IndicatorObservation.indicator_id == ind.id)
        .order_by(ScamReport.created_at.desc())
        .limit(20)
    ).all()
    return {
        "indicator": _ind_out(db, ind),
        "history": [
            {
                "from_status": h.from_status,
                "to_status": h.to_status,
                "from_confidence": h.from_confidence,
                "to_confidence": h.to_confidence,
                "reason": h.reason,
                "actor": h.actor_label,
                "created_at": h.created_at,
            }
            for h in history
        ],
        "observations": observations,
        "scan_matches": scan_hits,
        "reports": [
            {"id": r.id, "category": r.category, "status": r.status, "created_at": r.created_at}
            for r in reports
        ],
    }


class IndicatorPatch(BaseModel):
    category: str | None = Field(default=None, max_length=32)
    campaign_id: uuid.UUID | None = None
    notes: str | None = Field(default=None, max_length=5000)
    evidence_summary: str | None = Field(default=None, max_length=5000)
    references: list[str] | None = Field(default=None, max_length=20)


@router.patch("/indicators/{indicator_id}", response_model=IndicatorOut)
def update_indicator(
    indicator_id: uuid.UUID,
    body: IndicatorPatch,
    request: Request,
    auth: AuthContext = Depends(REVIEW),
    db: Session = Depends(get_db),
):
    _sys(db)
    ind = db.get(Indicator, indicator_id)
    if ind is None:
        raise not_found("Indicator")
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(ind, k, v)
    audit.record(
        db,
        "indicator.updated",
        actor=auth.user,
        resource_type="indicator",
        resource_id=ind.id,
        details={"fields": sorted(changes)},
        request=request,
    )
    db.commit()
    return _ind_out(db, ind)


class IndicatorReview(BaseModel):
    decision: Literal["verify", "reject", "revoke", "downgrade", "reactivate"]
    confidence: CONFIDENCE = "medium"
    disposition: Literal["malicious", "suspicious"] | None = None
    reason: str = Field(min_length=5, max_length=2000)
    expires_in_days: int | None = Field(default=180, ge=1, le=730)


@router.post("/indicators/{indicator_id}/review", response_model=IndicatorOut)
def review_indicator(
    indicator_id: uuid.UUID,
    body: IndicatorReview,
    request: Request,
    auth: AuthContext = Depends(PUBLISH),
    db: Session = Depends(get_db),
):
    _sys(db)
    ind = db.get(Indicator, indicator_id)
    if ind is None:
        raise not_found("Indicator")
    target = {
        "verify": "verified",
        "reject": "rejected",
        "revoke": "revoked",
        "downgrade": "unverified",
        "reactivate": "verified",
    }[body.decision]
    if body.disposition:
        ind.disposition = body.disposition
    intel.change_status(
        db,
        ind,
        status=target,
        confidence=body.confidence,
        actor=auth.user,
        reason=body.reason,
        expires_in_days=body.expires_in_days if target == "verified" else None,
    )
    db.add(
        AnalystReview(
            indicator_id=ind.id, reviewer_id=auth.user.id, decision=body.decision, notes=body.reason
        )
    )
    audit.record(
        db,
        f"indicator.{body.decision}",
        actor=auth.user,
        resource_type="indicator",
        resource_id=ind.id,
        details={"status": target, "confidence": body.confidence},
        request=request,
    )
    db.commit()
    return _ind_out(db, ind)


# --- Community report queue ----------------------------------------------------------------------


def _report_row(r: ScamReport) -> dict:
    return {
        "id": r.id,
        "category": r.category,
        "category_label": intel.CATEGORY_LABELS.get(r.category, r.category),
        "channel": r.channel,
        "url": r.url,
        "phone": r.phone_display,
        "sender": r.sender,
        "description": r.description[:300],
        "status": r.status,
        "money_lost": r.money_lost,
        "organisation_report": r.organisation_id is not None,
        "created_at": r.created_at,
    }


@router.get("/reports")
def report_queue(
    status: str = Query(default="open"),
    category: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    auth: AuthContext = Depends(READ),
    db: Session = Depends(get_db),
) -> dict:
    _sys(db)
    q = select(ScamReport)
    if status == "open":
        q = q.where(ScamReport.status.in_(("unverified", "under_review")))
    elif status != "all":
        q = q.where(ScamReport.status == status)
    if category:
        q = q.where(ScamReport.category == category)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    rows = db.scalars(
        q.order_by(ScamReport.created_at).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return {
        "items": [_report_row(r) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/reports/{report_id}")
def report_detail(
    report_id: uuid.UUID,
    request: Request,
    reveal: bool = False,
    auth: AuthContext = Depends(REVIEW),
    db: Session = Depends(get_db),
) -> dict:
    _sys(db)
    r = db.get(ScamReport, report_id)
    if r is None:
        raise not_found("Report")
    similar_q = []
    if r.phone_hash:
        similar_q.append(ScamReport.phone_hash == r.phone_hash)
    if r.url:
        similar_q.append(ScamReport.url == r.url)
    similar = []
    if similar_q:
        similar = db.scalars(
            select(ScamReport)
            .where(or_(*similar_q), ScamReport.id != r.id)
            .order_by(ScamReport.created_at.desc())
            .limit(10)
        ).all()
    indicators = [db.get(Indicator, uuid.UUID(i)) for i in (r.indicator_ids or [])]
    message = decrypt_secret(r.message_encrypted) if r.message_encrypted else None
    phone = None
    if reveal and r.phone_encrypted:
        phone = decrypt_secret(r.phone_encrypted)
        audit.record(
            db,
            "report.phone_revealed",
            actor=auth.user,
            resource_type="scam_report",
            resource_id=r.id,
            request=request,
        )
        db.commit()
    reviews = db.scalars(
        select(AnalystReview)
        .where(AnalystReview.report_id == r.id)
        .order_by(AnalystReview.created_at.desc())
    ).all()
    return {
        "report": _report_row(r)
        | {
            "description": r.description,
            "message": message,
            "occurred_on": r.occurred_on,
            "public_note": r.public_note,
            "full_phone": phone,
            "contact_email": r.contact_email,
            "duplicate_of": r.duplicate_of,
        },
        "indicators": [_ind_out(db, i) for i in indicators if i],
        "similar": [_report_row(s) for s in similar],
        "reviews": [
            {"decision": v.decision, "notes": v.notes, "created_at": v.created_at} for v in reviews
        ],
    }


class ReportReview(BaseModel):
    decision: Literal["start_review", "verify", "reject", "duplicate", "request_info"]
    notes: str = Field(default="", max_length=5000)
    public_note: str | None = Field(default=None, max_length=1000)
    duplicate_of: uuid.UUID | None = None
    confidence: CONFIDENCE = "medium"
    campaign_id: uuid.UUID | None = None
    expires_in_days: int = Field(default=180, ge=1, le=730)


@router.post("/reports/{report_id}/review")
def review_report(
    report_id: uuid.UUID,
    body: ReportReview,
    request: Request,
    auth: AuthContext = Depends(REVIEW),
    db: Session = Depends(get_db),
) -> dict:
    from app.security.rbac import intel_permissions

    _sys(db)
    r = db.get(ScamReport, report_id)
    if r is None:
        raise not_found("Report")
    perms = intel_permissions(auth.user.is_platform_admin, auth.user.platform_role)
    if body.decision == "verify" and IntelPerm.PUBLISH not in perms:
        raise APIError(
            403, "forbidden", "Reviewers can triage; an analyst must verify and publish."
        )
    previous = r.status
    if body.decision == "start_review":
        r.status = "under_review"
    elif body.decision == "verify":
        if len(body.notes.strip()) < 10:
            raise APIError(422, "notes_required", "Explain the evidence behind the verification.")
        r.status = "verified"
        for raw in r.indicator_ids or []:
            ind = db.get(Indicator, uuid.UUID(raw))
            if ind is None:
                continue
            if body.campaign_id:
                ind.campaign_id = body.campaign_id
            ind.evidence_summary = ind.evidence_summary or body.notes
            intel.change_status(
                db,
                ind,
                status="verified",
                confidence=body.confidence,
                actor=auth.user,
                reason=f"Report {r.id}: {body.notes}",
                expires_in_days=body.expires_in_days,
            )
    elif body.decision == "reject":
        r.status = "rejected"
    elif body.decision == "duplicate":
        if not body.duplicate_of or not db.get(ScamReport, body.duplicate_of):
            raise APIError(422, "duplicate_required", "Choose the report this duplicates.")
        r.status, r.duplicate_of = "duplicate", body.duplicate_of
    else:  # request_info
        r.status = "under_review"
    if body.public_note is not None:
        r.public_note = body.public_note
    db.add(
        AnalystReview(
            report_id=r.id, reviewer_id=auth.user.id, decision=body.decision, notes=body.notes
        )
    )
    audit.record(
        db,
        f"report.{body.decision}",
        actor=auth.user,
        resource_type="scam_report",
        resource_id=r.id,
        details={"from": previous, "to": r.status},
        request=request,
    )
    if r.reporter_id and r.status != previous:
        db.add(
            Notification(
                user_id=r.reporter_id,
                organisation_id=r.organisation_id,
                kind="report_update",
                severity="info",
                title="Update on your scam report",
                body=(r.public_note or f"Status: {r.status.replace('_', ' ')}")[:500],
                link=f"/reports/{r.id}",
            )
        )
    if r.organisation_id and r.status != previous:
        from app.services import webhooks

        webhooks.emit(
            db,
            r.organisation_id,
            "report.status_changed",
            {"report_id": str(r.id), "status": r.status},
        )
    db.commit()
    return {"id": r.id, "status": r.status}


# --- False-positive / false-negative feedback ----------------------------------------------


@router.get("/feedback")
def feedback_queue(
    status: str = "open", auth: AuthContext = Depends(READ), db: Session = Depends(get_db)
) -> list[dict]:
    _sys(db)
    rows = db.execute(
        select(ScanFeedback, Scan)
        .join(Scan, Scan.id == ScanFeedback.scan_id)
        .where(ScanFeedback.status == status, ScanFeedback.kind != "correct")
        .order_by(ScanFeedback.created_at)
        .limit(200)
    ).all()
    return [
        {
            "id": f.id,
            "kind": f.kind,
            "comment": f.comment,
            "status": f.status,
            "created_at": f.created_at,
            "scan": {
                "id": s.id,
                "kind": s.kind,
                "title": s.title,
                "verdict": s.verdict,
                "risk_score": s.risk_score,
                "indicator_ids": s.artifacts.get("indicator_ids", []),
            },
        }
        for f, s in rows
    ]


class FeedbackResolve(BaseModel):
    status: Literal["accepted", "dismissed"]
    resolution: str = Field(min_length=5, max_length=2000)


@router.post("/feedback/{feedback_id}/resolve")
def resolve_feedback(
    feedback_id: uuid.UUID,
    body: FeedbackResolve,
    request: Request,
    auth: AuthContext = Depends(REVIEW),
    db: Session = Depends(get_db),
) -> dict:
    _sys(db)
    f = db.get(ScanFeedback, feedback_id)
    if f is None:
        raise not_found("Feedback")
    f.status, f.resolution = body.status, body.resolution
    f.resolved_by, f.resolved_at = auth.user.id, datetime.now(UTC)
    audit.record(
        db,
        "feedback.resolved",
        actor=auth.user,
        resource_type="scan_feedback",
        resource_id=f.id,
        details={"status": body.status, "kind": f.kind},
        request=request,
    )
    db.commit()
    return {"id": f.id, "status": f.status}


# --- Campaigns ----------------------------------------------------------------------------------


class CampaignIn(BaseModel):
    name: str = Field(min_length=3, max_length=200)
    category: str = Field(max_length=32)
    description: str = Field(default="", max_length=5000)
    status: Literal["active", "dormant", "closed"] = "active"
    published: bool = False
    public_title: str | None = Field(default=None, max_length=200)
    public_summary: str | None = Field(default=None, max_length=1000)


def _campaign_out(db: Session, c: ThreatCampaign) -> dict:
    count = db.scalar(select(func.count()).where(Indicator.campaign_id == c.id)) or 0
    return {
        "id": c.id,
        "name": c.name,
        "category": c.category,
        "category_label": intel.CATEGORY_LABELS.get(c.category, c.category),
        "description": c.description,
        "status": c.status,
        "published": c.published,
        "public_title": c.public_title,
        "public_summary": c.public_summary,
        "published_at": c.published_at,
        "indicators": count,
        "created_at": c.created_at,
        "updated_at": c.updated_at,
    }


@router.get("/campaigns")
def list_campaigns(auth: AuthContext = Depends(READ), db: Session = Depends(get_db)):
    _sys(db)
    return [
        _campaign_out(db, c)
        for c in db.scalars(select(ThreatCampaign).order_by(ThreatCampaign.updated_at.desc()))
    ]


def _apply_campaign(c: ThreatCampaign, body: CampaignIn) -> None:
    if body.published and not (body.public_title and body.public_summary):
        raise APIError(
            422,
            "public_text_required",
            "Add a public title and summary before publishing a warning.",
        )
    for k, v in body.model_dump().items():
        setattr(c, k, v)
    if body.published and c.published_at is None:
        c.published_at = datetime.now(UTC)
    if not body.published:
        c.published_at = None


@router.post("/campaigns", status_code=201)
def create_campaign(
    body: CampaignIn,
    request: Request,
    auth: AuthContext = Depends(PUBLISH),
    db: Session = Depends(get_db),
) -> dict:
    _sys(db)
    c = ThreatCampaign(created_by=auth.user.id, name=body.name, category=body.category)
    _apply_campaign(c, body)
    db.add(c)
    db.flush()
    audit.record(
        db,
        "campaign.created",
        actor=auth.user,
        resource_type="campaign",
        resource_id=c.id,
        request=request,
    )
    db.commit()
    return _campaign_out(db, c)


@router.put("/campaigns/{campaign_id}")
def update_campaign(
    campaign_id: uuid.UUID,
    body: CampaignIn,
    request: Request,
    auth: AuthContext = Depends(PUBLISH),
    db: Session = Depends(get_db),
) -> dict:
    _sys(db)
    c = db.get(ThreatCampaign, campaign_id)
    if c is None:
        raise not_found("Campaign")
    _apply_campaign(c, body)
    audit.record(
        db,
        "campaign.updated",
        actor=auth.user,
        resource_type="campaign",
        resource_id=c.id,
        details={"published": c.published},
        request=request,
    )
    db.commit()
    return _campaign_out(db, c)


# --- Sources, brands, staff (platform administrators) --------------------------------------------


@router.get("/sources")
def list_sources(auth: AuthContext = Depends(READ), db: Session = Depends(get_db)) -> list[dict]:
    from app.intelligence.providers import PROVIDERS

    configured = {p.code: p.enabled() for p in PROVIDERS}
    _sys(db)
    out = []
    for s in db.scalars(select(IntelligenceSource).order_by(IntelligenceSource.name)):
        count = db.scalar(select(func.count()).where(Indicator.source_id == s.id)) or 0
        out.append(
            {
                "code": s.code,
                "name": s.name,
                "kind": s.kind,
                "licence": s.licence,
                "permitted_use": s.permitted_use,
                "sharing_restrictions": s.sharing_restrictions,
                "enabled": s.enabled,
                "default_confidence": s.default_confidence,
                "recheck_days": s.recheck_days,
                "indicators": count,
                "credentials_configured": configured.get(s.code),
                "last_synced_at": s.last_synced_at,
            }
        )
    return out


class SourcePatch(BaseModel):
    enabled: bool | None = None
    licence: str | None = Field(default=None, max_length=300)
    permitted_use: str | None = Field(default=None, max_length=500)
    sharing_restrictions: str | None = Field(default=None, max_length=500)
    default_confidence: CONFIDENCE | None = None
    recheck_days: int | None = Field(default=None, ge=1, le=365)


@router.patch("/sources/{code}")
def update_source(
    code: str,
    body: SourcePatch,
    request: Request,
    auth: AuthContext = Depends(ADMIN),
    db: Session = Depends(get_db),
) -> dict:
    _sys(db)
    s = intel.source_by_code(db, code)
    if s is None:
        raise not_found("Source")
    changes = body.model_dump(exclude_unset=True)
    licence = changes.get("licence", s.licence) or ""
    if changes.get("enabled") and s.kind in {"commercial", "feed"} and not licence.strip():
        raise APIError(422, "licence_required", "Record the licence before enabling a source.")
    for k, v in changes.items():
        setattr(s, k, v)
    audit.record(
        db,
        "source.updated",
        actor=auth.user,
        resource_type="intelligence_source",
        resource_id=s.id,
        details=changes,
        request=request,
    )
    db.commit()
    return {"code": s.code, "enabled": s.enabled}


class BrandIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    category: str = Field(default="other", max_length=32)
    official_domains: list[str] = Field(min_length=1, max_length=30)
    keywords: list[str] = Field(default_factory=list, max_length=30)
    sender_ids: list[str] = Field(default_factory=list, max_length=30)
    official_contact: str | None = Field(default=None, max_length=300)
    verified: bool = False
    active: bool = True


def brand_out(b: BrandProfile) -> dict:
    return {
        "id": b.id,
        "name": b.name,
        "category": b.category,
        "official_domains": b.official_domains,
        "keywords": b.keywords,
        "sender_ids": b.sender_ids,
        "official_contact": b.official_contact,
        "verified": b.verified,
        "active": b.active,
        "organisation_id": b.organisation_id,
    }


def clean_brand(body: BrandIn) -> dict:
    data = body.model_dump()
    data["official_domains"] = sorted(
        {d.strip().lower().removeprefix("www.") for d in body.official_domains if d.strip()}
    )
    data["keywords"] = sorted({k.strip().lower() for k in body.keywords if len(k.strip()) >= 3})
    return data


@router.get("/brands")
def list_brands(auth: AuthContext = Depends(READ), db: Session = Depends(get_db)) -> list[dict]:
    _sys(db)
    return [
        brand_out(b)
        for b in db.scalars(
            select(BrandProfile)
            .where(BrandProfile.organisation_id.is_(None))
            .order_by(BrandProfile.name)
        )
    ]


@router.post("/brands", status_code=201)
def create_brand(
    body: BrandIn,
    request: Request,
    auth: AuthContext = Depends(ADMIN),
    db: Session = Depends(get_db),
) -> dict:
    _sys(db)
    b = BrandProfile(**clean_brand(body))
    db.add(b)
    db.flush()
    audit.record(
        db,
        "brand.created",
        actor=auth.user,
        resource_type="brand",
        resource_id=b.id,
        request=request,
    )
    db.commit()
    return brand_out(b)


@router.put("/brands/{brand_id}")
def update_brand(
    brand_id: uuid.UUID,
    body: BrandIn,
    request: Request,
    auth: AuthContext = Depends(ADMIN),
    db: Session = Depends(get_db),
) -> dict:
    _sys(db)
    b = db.get(BrandProfile, brand_id)
    if b is None or b.organisation_id is not None:
        raise not_found("Brand")
    for k, v in clean_brand(body).items():
        setattr(b, k, v)
    audit.record(
        db,
        "brand.updated",
        actor=auth.user,
        resource_type="brand",
        resource_id=b.id,
        request=request,
    )
    db.commit()
    return brand_out(b)


class StaffIn(BaseModel):
    email: str = Field(max_length=320)
    role: Literal["analyst", "reviewer", ""]


@router.get("/staff")
def list_staff(auth: AuthContext = Depends(ADMIN), db: Session = Depends(get_db)) -> list[dict]:
    _sys(db)
    rows = db.scalars(
        select(User).where(or_(User.platform_role != "", User.is_platform_admin.is_(True)))
    ).all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "name": u.full_name,
            "role": "administrator" if u.is_platform_admin else u.platform_role,
        }
        for u in rows
    ]


@router.post("/staff")
def set_staff_role(
    body: StaffIn,
    request: Request,
    auth: AuthContext = Depends(ADMIN),
    db: Session = Depends(get_db),
) -> dict:
    _sys(db)
    user = db.scalar(select(User).where(func.lower(User.email) == body.email.strip().lower()))
    if user is None:
        raise APIError(404, "user_not_found", "No account uses that email address.")
    if body.role and body.role not in {r.value for r in PlatformRole}:
        raise APIError(422, "invalid_role", "Unknown role.")
    previous = user.platform_role
    user.platform_role = body.role
    audit.record(
        db,
        "staff.role_changed",
        actor=auth.user,
        resource_type="user",
        resource_id=user.id,
        details={"from": previous, "to": body.role},
        request=request,
    )
    db.commit()
    return {"email": user.email, "role": user.platform_role}
