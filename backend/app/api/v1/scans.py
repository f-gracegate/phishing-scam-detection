"""Scanning endpoints, shared by the web app, mobile apps, browser extension and business API.

Scope comes from the caller:

* a signed-in person without ``X-Organisation-Id`` works in their private, personal space;
* with ``X-Organisation-Id`` the scan belongs to that organisation workspace;
* a business API key (``psk_…``) acts for its organisation;
* an extension token (``pse_…``) acts for the person who created it.
"""

import time
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.api.deps import Actor, get_actor
from app.core.config import settings
from app.core.db import get_db
from app.core.errors import APIError, forbidden, not_found
from app.core.redis import rate_limit
from app.detection.scoring import VERDICT_LABELS
from app.detection.signals import SOURCE_LABELS
from app.intelligence.service import CATEGORY_LABELS
from app.models import Scan, ScanEvidence, ScanFeedback, User
from app.scanning import service
from app.schemas.common import Message
from app.security.rbac import Perm

router = APIRouter(prefix="/scans", tags=["Scans"])


# --- Schemas -------------------------------------------------------------------------------------


class ScanOptions(BaseModel):
    check_reputation: bool = True
    check_redirects: bool = True
    check_domain: bool = True
    check_tls: bool = True
    check_website: bool = True


class PrivacyOptions(BaseModel):
    allow_external_intelligence_lookup: bool = True


class UrlScanIn(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    scan_options: ScanOptions = Field(default_factory=ScanOptions)
    privacy: PrivacyOptions = Field(default_factory=PrivacyOptions)


class MessageScanIn(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)
    sender: str | None = Field(default=None, max_length=120)
    channel: Literal["sms", "whatsapp", "social", "other"] = "sms"
    check_links: bool = False
    privacy: PrivacyOptions = Field(default_factory=PrivacyOptions)


class EmailScanIn(BaseModel):
    raw: str = Field(min_length=1, max_length=2_100_000)
    privacy: PrivacyOptions = Field(default_factory=PrivacyOptions)


class QrScanIn(BaseModel):
    payload: str = Field(min_length=1, max_length=4096, description="The decoded QR content")
    privacy: PrivacyOptions = Field(default_factory=PrivacyOptions)


class BulkItem(BaseModel):
    kind: Literal["url", "message"]
    content: str = Field(min_length=1, max_length=20_000)


class BulkIn(BaseModel):
    items: list[BulkItem] = Field(min_length=1, max_length=100)
    check_website: bool = False


class EvidenceOut(BaseModel):
    layer: str
    code: str
    severity: str
    title: str
    description: str
    source_kind: str
    source_label: str
    source_name: str
    reliability: str
    weight: int
    observed_at: datetime
    data: dict[str, Any]


class ScanOut(BaseModel):
    id: uuid.UUID
    kind: str
    source: str
    status: str
    title: str
    verdict: str | None
    verdict_label: str | None
    risk_score: int | None
    confidence: str | None
    headline: str | None
    summary: str | None
    category: str | None
    category_label: str | None
    recommendations: list[str]
    error: str | None
    created_at: datetime
    completed_at: datetime | None
    organisation_id: uuid.UUID | None
    submitted_by: str | None = None


class ScanDetail(ScanOut):
    artifacts: dict[str, Any]
    evidence: list[EvidenceOut]
    feedback: str | None = None
    content_available: bool


class ScanPage(BaseModel):
    items: list[ScanOut]
    total: int
    page: int
    page_size: int


class FeedbackIn(BaseModel):
    kind: Literal["false_positive", "false_negative", "correct"]
    comment: str | None = Field(default=None, max_length=2000)


class QuotaOut(BaseModel):
    scope: str
    limit: int | None
    used: int
    period: str


class BulkOut(BaseModel):
    batch_id: uuid.UUID
    scan_ids: list[uuid.UUID]


class BatchOut(BaseModel):
    batch_id: uuid.UUID
    total: int
    completed: int
    failed: int
    high_risk: int
    items: list[ScanOut]


# --- Helpers -------------------------------------------------------------------------------------


def scan_out(scan: Scan, submitted_by: str | None = None) -> dict:
    return dict(
        id=scan.id,
        kind=scan.kind,
        source=scan.source,
        status=scan.status,
        title=scan.title,
        verdict=scan.verdict,
        verdict_label=VERDICT_LABELS.get(scan.verdict) if scan.verdict else None,
        risk_score=scan.risk_score,
        confidence=scan.confidence,
        headline=scan.headline,
        summary=scan.summary,
        category=scan.category,
        category_label=CATEGORY_LABELS.get(scan.category or ""),
        recommendations=scan.recommendations or [],
        error=scan.error,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        organisation_id=scan.organisation_id,
        submitted_by=submitted_by,
    )


def _visible(q, actor: Actor, *, mine_only: bool = False):
    if actor.org is None:
        return q.where(Scan.user_id == actor.user.id, Scan.organisation_id.is_(None))
    q = q.where(Scan.organisation_id == actor.org_id)
    if mine_only or not actor.org.has(Perm.SCANS_READ_ALL):
        q = q.where(Scan.user_id == actor.user.id) if actor.user else q.where(Scan.id.is_(None))
    return q


def get_visible_scan(db: Session, actor: Actor, scan_id: uuid.UUID) -> Scan:
    scan = db.scalar(_visible(select(Scan).where(Scan.id == scan_id), actor))
    if scan is None:
        raise not_found("Scan")
    return scan


def _create(
    db: Session, actor: Actor, kind: str, content: str, *, options: dict, allow_external: bool
) -> Scan:
    key = actor.api_key.id if actor.api_key else (actor.user.id if actor.user else "anon")
    rate_limit(f"scan-submit:{key}", limit=60, window_seconds=60)
    return service.submit(
        db,
        kind=kind,
        content=content,
        user=actor.user,
        organisation=actor.organisation,
        api_key=actor.api_key if actor.org else None,
        source=actor.source,
        options=options,
        allow_external_lookup=allow_external,
    )


def _respond(db: Session, scan: Scan, wait: bool) -> ScanDetail:
    service.dispatch(db, scan)
    if wait and not settings.scan_inline:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            db.expire_all()
            current = db.get(Scan, scan.id)
            if current and current.status in {"completed", "failed"}:
                break
            time.sleep(0.5)
    db.expire_all()
    return _detail(db, db.get(Scan, scan.id))


def _detail(db: Session, scan: Scan, user: User | None = None) -> ScanDetail:
    evidence = db.scalars(
        select(ScanEvidence).where(ScanEvidence.scan_id == scan.id).order_by(ScanEvidence.position)
    ).all()
    feedback = None
    if user:
        feedback = db.scalar(
            select(ScanFeedback.kind).where(
                ScanFeedback.scan_id == scan.id, ScanFeedback.user_id == user.id
            )
        )
    submitted_by = None
    if scan.organisation_id and scan.user_id:
        person = db.get(User, scan.user_id)
        submitted_by = person.full_name or person.email if person else None
    elif scan.organisation_id and scan.api_key_id:
        submitted_by = "API"
    return ScanDetail(
        **scan_out(scan, submitted_by),
        artifacts=scan.artifacts or {},
        evidence=[
            EvidenceOut(
                layer=e.layer,
                code=e.code,
                severity=e.severity,
                title=e.title,
                description=e.description,
                source_kind=e.source_kind,
                source_label=SOURCE_LABELS.get(e.source_kind, e.source_kind),
                source_name=e.source_name,
                reliability=e.reliability,
                weight=e.weight,
                observed_at=e.observed_at,
                data=e.data,
            )
            for e in evidence
        ],
        feedback=feedback,
        content_available=bool(scan.content_encrypted),
    )


# --- Submission ----------------------------------------------------------------------------------


@router.post("/url", response_model=ScanDetail, status_code=201)
def scan_url(
    body: UrlScanIn,
    wait: bool = Query(default=False, description="Wait up to 20 s for the result"),
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> ScanDetail:
    options = body.scan_options.model_dump()
    scan = _create(
        db,
        actor,
        "url",
        body.url,
        options=options,
        allow_external=body.privacy.allow_external_intelligence_lookup,
    )
    return _respond(db, scan, wait)


@router.post("/message", response_model=ScanDetail, status_code=201)
def scan_message(
    body: MessageScanIn,
    wait: bool = Query(default=False),
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> ScanDetail:
    options = {"sender": body.sender, "channel": body.channel, "check_links": body.check_links}
    scan = _create(
        db,
        actor,
        "message",
        body.text,
        options=options,
        allow_external=body.privacy.allow_external_intelligence_lookup,
    )
    return _respond(db, scan, wait)


@router.post("/email", response_model=ScanDetail, status_code=201)
def scan_email(
    body: EmailScanIn,
    wait: bool = Query(default=False),
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> ScanDetail:
    scan = _create(
        db,
        actor,
        "email",
        body.raw,
        options={},
        allow_external=body.privacy.allow_external_intelligence_lookup,
    )
    return _respond(db, scan, wait)


@router.post("/email/file", response_model=ScanDetail, status_code=201)
async def scan_email_file(
    file: UploadFile = File(...),
    wait: bool = Query(default=False),
    allow_external: bool = Query(default=True),
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> ScanDetail:
    data = await file.read(settings.max_email_bytes + 1)
    if len(data) > settings.max_email_bytes:
        raise APIError(413, "too_large", "That email is too large to check (2 MB maximum).")
    raw = data.decode("utf-8", "replace")
    scan = _create(
        db,
        actor,
        "email",
        raw,
        options={"filename": (file.filename or "")[:120]},
        allow_external=allow_external,
    )
    return _respond(db, scan, wait)


@router.post("/qr", response_model=ScanDetail, status_code=201)
def scan_qr(
    body: QrScanIn,
    wait: bool = Query(default=False),
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> ScanDetail:
    """Checks what a QR code points to. Apps decode the image on the device and send the text."""
    scan = _create(
        db,
        actor,
        "qr",
        body.payload,
        options={"check_website": True},
        allow_external=body.privacy.allow_external_intelligence_lookup,
    )
    return _respond(db, scan, wait)


@router.post("/bulk", response_model=BulkOut, status_code=202)
def scan_bulk(body: BulkIn, actor: Actor = Depends(get_actor), db: Session = Depends(get_db)):
    if actor.org is None:
        raise APIError(400, "organisation_required", "Bulk scanning is a business feature.")
    if actor.api_key is None:
        actor.org.require(Perm.SCANS_BULK)
    service.check_quota(db, user=None, organisation=actor.organisation, count=len(body.items))
    batch = uuid.uuid4()
    scans = []
    for item in body.items:
        options = {"check_website": body.check_website} if item.kind == "url" else {}
        try:
            scan = service.submit(
                db,
                kind=item.kind,
                content=item.content,
                user=actor.user,
                organisation=actor.organisation,
                api_key=actor.api_key,
                source="bulk",
                options=options,
                batch_id=batch,
                count_quota=False,
            )
        except APIError:
            continue
        scans.append(scan)
    if not scans:
        raise APIError(422, "nothing_to_scan", "None of the items could be checked.")
    db.commit()
    for scan in scans:
        if settings.scan_inline:
            service.run_scan(db, scan.id)
        else:
            service.enqueue(scan)
    return BulkOut(batch_id=batch, scan_ids=[s.id for s in scans])


@router.get("/batches/{batch_id}", response_model=BatchOut)
def get_batch(
    batch_id: uuid.UUID, actor: Actor = Depends(get_actor), db: Session = Depends(get_db)
) -> BatchOut:
    scans = db.scalars(
        _visible(select(Scan).where(Scan.batch_id == batch_id), actor).order_by(Scan.created_at)
    ).all()
    if not scans:
        raise not_found("Batch")
    return BatchOut(
        batch_id=batch_id,
        total=len(scans),
        completed=sum(s.status == "completed" for s in scans),
        failed=sum(s.status == "failed" for s in scans),
        high_risk=sum((s.verdict or "") in {"high", "critical"} for s in scans),
        items=[ScanOut(**scan_out(s)) for s in scans],
    )


# --- Reading -------------------------------------------------------------------------------------


@router.get("", response_model=ScanPage)
def list_scans(
    kind: str | None = None,
    verdict: str | None = None,
    mine: bool = False,
    q: str | None = Query(default=None, max_length=100),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> ScanPage:
    query = _visible(select(Scan), actor, mine_only=mine)
    if kind:
        query = query.where(Scan.kind == kind)
    if verdict:
        if verdict == "high_risk":
            query = query.where(Scan.verdict.in_(("high", "critical")))
        else:
            query = query.where(Scan.verdict == verdict)
    if q:
        query = query.where(Scan.title.ilike(f"%{q.replace('%', '')}%"))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(
        query.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    names: dict[uuid.UUID, str] = {}
    if actor.org is not None:
        ids = {s.user_id for s in rows if s.user_id}
        if ids:
            names = {
                u.id: u.full_name or u.email
                for u in db.scalars(select(User).where(User.id.in_(ids)))
            }
    return ScanPage(
        items=[
            ScanOut(
                **scan_out(
                    s, names.get(s.user_id) if s.user_id else ("API" if s.api_key_id else None)
                )
            )
            for s in rows
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/quota", response_model=QuotaOut)
def quota(actor: Actor = Depends(get_actor), db: Session = Depends(get_db)) -> QuotaOut:
    from app.billing.service import usage
    from app.core.redis import redis_client

    if actor.org is not None:
        plan = service.get_plan(service._org_plan_code(db, actor.organisation))
        return QuotaOut(
            scope="organisation",
            limit=plan.monthly_scans,
            used=usage(db, actor.org_id).scans_this_month,
            period="month",
        )
    user = actor.user
    plus = user.personal_plan == "plus" and (
        user.personal_plan_until is None or user.personal_plan_until > datetime.now(UTC)
    )
    try:
        used = int(redis_client.get(service._quota_key(f"user:{user.id}")) or 0)
    except Exception:  # noqa: BLE001
        used = 0
    return QuotaOut(
        scope="personal",
        limit=settings.plus_daily_scans if plus else settings.free_daily_scans,
        used=used,
        period="day",
    )


class ReputationOut(BaseModel):
    domain: str
    status: Literal["verified_malicious", "verified_suspicious", "reported", "no_record"]
    category: str | None = None
    category_label: str | None = None
    message: str


@router.get("/reputation", response_model=ReputationOut)
def reputation(
    domain: str = Query(min_length=3, max_length=253),
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> ReputationOut:
    """Quick verdict for a website's domain from verified intelligence only.

    Used by the browser extension to warn before a page is opened. Only the domain is sent and
    nothing is stored, so browsing history is never collected.
    """
    from app.detection.urls import InvalidURL, parse_url
    from app.intelligence import service as intel

    key = actor.api_key.id if actor.api_key else actor.user.id
    rate_limit(f"reputation:{key}", limit=600, window_seconds=60)
    try:
        parsed = parse_url(f"https://{domain.strip().lower()}/")
    except InvalidURL as exc:
        raise APIError(422, "invalid_domain", str(exc)) from exc
    signals, _ = intel.lookup_url(db, parsed)
    verified = next((s for s in signals if s.source_kind == "verified_intel"), None)
    if verified:
        malicious = verified.weight >= 75
        return ReputationOut(
            domain=parsed.host,
            status="verified_malicious" if malicious else "verified_suspicious",
            category=verified.category,
            category_label=CATEGORY_LABELS.get(verified.category or ""),
            message=verified.description,
        )
    if signals:
        return ReputationOut(
            domain=parsed.host,
            status="reported",
            message="Others have reported this site; it hasn't been verified.",
        )
    return ReputationOut(
        domain=parsed.host,
        status="no_record",
        message="Not on our verified threat list. That doesn't make it safe.",
    )


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan_id: uuid.UUID, actor: Actor = Depends(get_actor), db: Session = Depends(get_db)
) -> ScanDetail:
    return _detail(db, get_visible_scan(db, actor, scan_id), actor.user)


@router.get("/{scan_id}/evidence", response_model=list[EvidenceOut])
def get_evidence(
    scan_id: uuid.UUID, actor: Actor = Depends(get_actor), db: Session = Depends(get_db)
) -> list[EvidenceOut]:
    return _detail(db, get_visible_scan(db, actor, scan_id)).evidence


@router.post("/{scan_id}/feedback", response_model=Message)
def give_feedback(
    scan_id: uuid.UUID,
    body: FeedbackIn,
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> Message:
    if actor.user is None:
        raise forbidden("Feedback needs a person's account.")
    scan = get_visible_scan(db, actor, scan_id)
    existing = db.scalar(
        select(ScanFeedback).where(
            ScanFeedback.scan_id == scan.id, ScanFeedback.user_id == actor.user.id
        )
    )
    if existing:
        existing.kind, existing.comment, existing.status = body.kind, body.comment, "open"
    else:
        db.add(
            ScanFeedback(
                scan_id=scan.id,
                user_id=actor.user.id,
                organisation_id=scan.organisation_id,
                kind=body.kind,
                comment=body.comment,
                status="open" if body.kind != "correct" else "accepted",
            )
        )
    db.commit()
    return Message(
        message="Thanks — an analyst will review this result."
        if body.kind != "correct"
        else "Thanks for confirming."
    )


@router.delete("/{scan_id}", response_model=Message)
def delete_scan(
    scan_id: uuid.UUID, actor: Actor = Depends(get_actor), db: Session = Depends(get_db)
) -> Message:
    scan = get_visible_scan(db, actor, scan_id)
    if scan.organisation_id is not None and scan.user_id != (actor.user.id if actor.user else None):
        raise forbidden("Only the person who submitted it can delete an organisation scan.")
    db.delete(scan)
    db.commit()
    return Message(message="Scan deleted.")


@router.delete("", response_model=Message)
def clear_history(actor: Actor = Depends(get_actor), db: Session = Depends(get_db)) -> Message:
    """Delete your whole personal scan history (never touches organisation records)."""
    if actor.org is not None or actor.user is None:
        raise APIError(400, "personal_only", "Only personal history can be cleared.")
    n = db.execute(
        delete(Scan).where(Scan.user_id == actor.user.id, Scan.organisation_id.is_(None))
    ).rowcount
    db.commit()
    return Message(message=f"Deleted {n} scan{'s' if n != 1 else ''}.")


@router.post("/{scan_id}/rescan", response_model=ScanDetail, status_code=201)
def rescan(
    scan_id: uuid.UUID,
    request: Request,
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> ScanDetail:
    """Run a link check again (results change as sites and intelligence change)."""
    scan = get_visible_scan(db, actor, scan_id)
    if scan.kind not in {"url", "qr"} or scan.options.get("decoded_as") == "text":
        raise APIError(400, "not_a_link", "Only link checks can be run again.")
    url = (scan.artifacts.get("link") or {}).get("url") or scan.title
    new = _create(
        db, actor, "url", url, options=dict(scan.options), allow_external=scan.allow_external_lookup
    )
    return _respond(db, new, False)
