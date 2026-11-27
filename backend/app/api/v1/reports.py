"""Scam reporting. Every report starts unverified and is reviewed by analysts.

A report never publicly labels a phone number, website or person. What it names becomes an
*unverified* indicator that scans mention only as "reported by others, not verified".
"""

import hashlib
import uuid
from datetime import UTC, date, datetime
from typing import Literal

from fastapi import APIRouter, Depends, File, Header, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import Actor, get_actor
from app.core.config import settings
from app.core.db import get_db
from app.core.errors import APIError, forbidden, not_found
from app.core.redis import rate_limit
from app.detection.text import mask_phone, normalise_phone, phone_hash, redact
from app.detection.urls import InvalidURL, parse_url
from app.intelligence.service import CATEGORY_LABELS, InvalidIndicator, upsert_indicator
from app.models import ReportEvidence, ScamReport, Scan
from app.security.rbac import Perm
from app.security.tokens import encrypt_secret
from app.services import storage

router = APIRouter(prefix="/reports", tags=["Scam reports"])

CATEGORIES = Literal[
    "momo",
    "bank",
    "government",
    "delivery",
    "recruitment",
    "investment",
    "ecommerce",
    "social_engineering",
    "impersonation",
    "crypto",
    "university",
    "romance",
    "prize",
    "other",
]
CHANNELS = Literal["sms", "whatsapp", "email", "website", "social", "phone_call", "other"]
ALLOWED_EVIDENCE = {
    "image/png",
    "image/jpeg",
    "image/webp",
    "application/pdf",
    "text/plain",
    "message/rfc822",
}
STATUS_LABELS = {
    "unverified": "Received — not yet verified",
    "under_review": "Being reviewed",
    "verified": "Verified by an analyst",
    "rejected": "Reviewed — not confirmed",
    "duplicate": "Already reported",
}


class ReportIn(BaseModel):
    category: CATEGORIES
    channel: CHANNELS
    url: str | None = Field(default=None, max_length=2048)
    phone: str | None = Field(default=None, max_length=40)
    sender: str | None = Field(default=None, max_length=320)
    message: str | None = Field(default=None, max_length=10_000)
    description: str = Field(min_length=10, max_length=5000)
    occurred_on: date | None = None
    money_lost: bool = False
    contact_email: EmailStr | None = None
    scan_id: uuid.UUID | None = None
    consent: bool = Field(description="Must be true: you agree to the reporting terms")

    @field_validator("consent")
    @classmethod
    def _consent(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Please confirm you agree to how reports are used.")
        return v

    @field_validator("occurred_on")
    @classmethod
    def _past(cls, v: date | None) -> date | None:
        if v and v > date.today():
            raise ValueError("The date can't be in the future.")
        return v


class EvidenceOut(BaseModel):
    id: uuid.UUID
    filename: str
    content_type: str
    size_bytes: int
    created_at: datetime


class ReportOut(BaseModel):
    id: uuid.UUID
    category: str
    category_label: str
    channel: str
    url: str | None
    phone: str | None
    sender: str | None
    description: str
    occurred_on: date | None
    money_lost: bool
    status: str
    status_label: str
    public_note: str | None
    created_at: datetime
    updated_at: datetime
    evidence: list[EvidenceOut] = []
    organisation_id: uuid.UUID | None = None


def _out(db: Session, r: ScamReport, with_evidence: bool = False) -> ReportOut:
    evidence = []
    if with_evidence:
        evidence = [
            EvidenceOut(
                id=e.id,
                filename=e.filename,
                content_type=e.content_type,
                size_bytes=e.size_bytes,
                created_at=e.created_at,
            )
            for e in db.scalars(select(ReportEvidence).where(ReportEvidence.report_id == r.id))
        ]
    return ReportOut(
        id=r.id,
        category=r.category,
        category_label=CATEGORY_LABELS.get(r.category, r.category),
        channel=r.channel,
        url=r.url,
        phone=r.phone_display,
        sender=r.sender,
        description=r.description,
        occurred_on=r.occurred_on,
        money_lost=r.money_lost,
        status=r.status,
        status_label=STATUS_LABELS.get(r.status, r.status),
        public_note=r.public_note,
        created_at=r.created_at,
        updated_at=r.updated_at,
        evidence=evidence,
        organisation_id=r.organisation_id,
    )


def _visible(q, actor: Actor):
    if actor.user is None:
        raise forbidden("Reports need a person's account.")
    if actor.org is not None and actor.org.has(Perm.REPORTS_READ):
        return q.where(ScamReport.organisation_id == actor.org_id)
    q = q.where(ScamReport.reporter_id == actor.user.id)
    if actor.org is not None:
        return q.where(ScamReport.organisation_id == actor.org_id)
    return q.where(ScamReport.organisation_id.is_(None))


@router.post("", response_model=ReportOut, status_code=201)
def submit_report(
    body: ReportIn,
    idempotency_key: str | None = Header(default=None, max_length=80),
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> ReportOut:
    if actor.user is None:
        raise forbidden("Reports need a person's account.")
    rate_limit(f"report:{actor.user.id}", limit=20, window_seconds=3600)
    if idempotency_key:
        existing = db.scalar(
            select(ScamReport).where(
                ScamReport.reporter_id == actor.user.id,
                ScamReport.idempotency_key == idempotency_key,
            )
        )
        if existing:
            return _out(db, existing)
    if not (body.url or body.phone or body.sender or body.message):
        raise APIError(
            422, "nothing_reported", "Add the suspicious link, phone number, sender or message."
        )
    url = None
    if body.url:
        try:
            url = parse_url(body.url).canonical
        except InvalidURL as exc:
            raise APIError(422, "invalid_url", str(exc)) from exc
    e164 = normalise_phone(body.phone) if body.phone else None
    if body.phone and not e164:
        raise APIError(422, "invalid_phone", "Enter a Ghanaian phone number, like 024 123 4567.")
    scan_id = None
    if body.scan_id:
        scan = db.get(Scan, body.scan_id)
        if scan and scan.user_id == actor.user.id:
            scan_id = scan.id
    report = ScamReport(
        reporter_id=actor.user.id,
        organisation_id=actor.org_id,
        scan_id=scan_id,
        idempotency_key=idempotency_key,
        category=body.category,
        channel=body.channel,
        url=url,
        phone_encrypted=encrypt_secret(e164) if e164 else None,
        phone_hash=phone_hash(e164) if e164 else None,
        phone_display=mask_phone(e164) if e164 else None,
        sender=body.sender,
        message_encrypted=encrypt_secret(redact(body.message)[0]) if body.message else None,
        description=redact(body.description)[0],
        occurred_on=body.occurred_on,
        money_lost=body.money_lost,
        contact_email=str(body.contact_email) if body.contact_email else None,
        consent_at=datetime.now(UTC),
        status="unverified",
    )
    db.add(report)
    db.flush()
    from app.core.db import system_context

    ids: list[str] = []
    with system_context(db):
        for kind, value in (("url", url), ("phone", e164)):
            if not value:
                continue
            try:
                ind = upsert_indicator(
                    db,
                    kind,
                    value,
                    source_code="community",
                    category=body.category,
                    report_id=report.id,
                )
                ids.append(str(ind.id))
            except InvalidIndicator:
                continue
        if url:
            try:
                host = parse_url(url).host
                ind = upsert_indicator(
                    db,
                    "domain",
                    host,
                    source_code="community",
                    category=body.category,
                    report_id=report.id,
                )
                ids.append(str(ind.id))
            except (InvalidURL, InvalidIndicator):
                pass
    report.indicator_ids = ids
    db.commit()
    return _out(db, report)


@router.get("", response_model=list[ReportOut])
def list_reports(
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> list[ReportOut]:
    q = _visible(select(ScamReport), actor)
    if status:
        q = q.where(ScamReport.status == status)
    rows = db.scalars(q.order_by(ScamReport.created_at.desc()).limit(limit)).all()
    return [_out(db, r) for r in rows]


@router.get("/summary")
def report_summary(actor: Actor = Depends(get_actor), db: Session = Depends(get_db)) -> dict:
    rows = db.execute(
        _visible(select(ScamReport.status, func.count()), actor).group_by(ScamReport.status)
    ).all()
    return {status: count for status, count in rows}


def _get(db: Session, actor: Actor, report_id: uuid.UUID) -> ScamReport:
    report = db.scalar(_visible(select(ScamReport).where(ScamReport.id == report_id), actor))
    if report is None:
        raise not_found("Report")
    return report


@router.get("/{report_id}", response_model=ReportOut)
def get_report(
    report_id: uuid.UUID, actor: Actor = Depends(get_actor), db: Session = Depends(get_db)
) -> ReportOut:
    return _out(db, _get(db, actor, report_id), with_evidence=True)


@router.post("/{report_id}/evidence", response_model=EvidenceOut, status_code=201)
async def add_evidence(
    report_id: uuid.UUID,
    file: UploadFile = File(...),
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> EvidenceOut:
    report = _get(db, actor, report_id)
    if report.reporter_id != actor.user.id:
        raise forbidden("Only the person who reported it can add evidence.")
    count = db.scalar(select(func.count()).where(ReportEvidence.report_id == report.id)) or 0
    if count >= 5:
        raise APIError(409, "too_many_files", "A report can have up to 5 files.")
    ctype = (file.content_type or "").split(";")[0].lower()
    if ctype not in ALLOWED_EVIDENCE:
        raise APIError(
            415,
            "unsupported_type",
            "Attach a screenshot (PNG, JPEG, WebP), a PDF, a text file or an email.",
        )
    data = await file.read(settings.max_evidence_bytes + 1)
    if len(data) > settings.max_evidence_bytes:
        raise APIError(413, "too_large", "Files can be up to 10 MB.")
    owner = report.organisation_id or report.reporter_id
    key = storage.put(owner, "report-evidence", data)
    ev = ReportEvidence(
        report_id=report.id,
        reporter_id=report.reporter_id,
        organisation_id=report.organisation_id,
        storage_key=key,
        filename=(file.filename or "evidence")[:255],
        content_type=ctype,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )
    db.add(ev)
    db.commit()
    return EvidenceOut(
        id=ev.id,
        filename=ev.filename,
        content_type=ev.content_type,
        size_bytes=ev.size_bytes,
        created_at=ev.created_at,
    )


@router.get("/{report_id}/evidence/{evidence_id}")
def download_evidence(
    report_id: uuid.UUID,
    evidence_id: uuid.UUID,
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
) -> Response:
    report = _get(db, actor, report_id)
    ev = db.scalar(
        select(ReportEvidence).where(
            ReportEvidence.id == evidence_id, ReportEvidence.report_id == report.id
        )
    )
    if ev is None:
        raise not_found("File")
    data = storage.get(report.organisation_id or report.reporter_id, ev.storage_key)
    return Response(
        data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{ev.filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
