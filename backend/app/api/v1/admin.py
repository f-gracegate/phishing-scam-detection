"""Organisation audit log, platform operations overview and development-only helpers."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, OrgContext, org_scope, require_platform_admin
from app.core.config import settings
from app.core.db import get_db, system_context
from app.core.errors import APIError
from app.models import AuditLog, Membership, Organisation, Scan, Subscription
from app.schemas.common import ORMModel, Page
from app.security.rbac import Perm
from app.services.email import read_dev_mailbox
from app.services.push import read_dev_pushes

router = APIRouter(tags=["Administration"])


class AuditEntryOut(ORMModel):
    id: uuid.UUID
    action: str
    actor_label: str | None
    resource_type: str | None
    resource_id: str | None
    details: dict
    ip_address: str | None
    created_at: datetime


@router.get("/audit-logs", response_model=Page[AuditEntryOut])
def audit_logs(
    ctx: OrgContext = Depends(org_scope(Perm.AUDIT_READ)),
    db: Session = Depends(get_db),
    action: str | None = Query(default=None, max_length=80),
    actor: str | None = Query(default=None, max_length=320),
    resource_type: str | None = Query(default=None, max_length=40),
    since: datetime | None = None,
    until: datetime | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> Page[AuditEntryOut]:
    stmt = select(AuditLog).where(AuditLog.organisation_id == ctx.org_id)
    if action:
        stmt = stmt.where(AuditLog.action.startswith(action))
    if actor:
        stmt = stmt.where(AuditLog.actor_label.ilike(f"%{actor}%"))
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
    if since:
        stmt = stmt.where(AuditLog.created_at >= since)
    if until:
        stmt = stmt.where(AuditLog.created_at <= until)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    )
    return Page[AuditEntryOut](
        items=[AuditEntryOut.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


class PlatformOrganisation(BaseModel):
    id: uuid.UUID
    name: str
    industry: str | None
    status: str
    plan_code: str | None
    members: int
    scans_total: int
    created_at: datetime


@router.get("/platform/organisations", response_model=list[PlatformOrganisation])
def platform_organisations(
    auth: AuthContext = Depends(require_platform_admin), db: Session = Depends(get_db)
) -> list[PlatformOrganisation]:
    """Customer list for the platform operations team. Counts only, never customer content."""
    members = (
        select(func.count()).where(Membership.organisation_id == Organisation.id).scalar_subquery()
    )
    scans = select(func.count()).where(Scan.organisation_id == Organisation.id).scalar_subquery()
    with system_context(db):
        rows = db.execute(
            select(Organisation, Subscription.plan_code, members, scans)
            .outerjoin(Subscription, Subscription.organisation_id == Organisation.id)
            .order_by(Organisation.created_at.desc())
        ).all()
    return [
        PlatformOrganisation(
            id=o.id,
            name=o.name,
            industry=o.industry,
            status=o.status,
            plan_code=plan,
            members=m,
            scans_total=s,
            created_at=o.created_at,
        )
        for o, plan, m, s in rows
    ]


@router.get("/dev/mailbox", include_in_schema=False)
def dev_mailbox() -> list[dict]:
    """Development only: recent emails, so invitations and resets can be tested locally."""
    if not settings.is_development:
        raise APIError(404, "not_found", "Not found.")
    return read_dev_mailbox()


@router.get("/dev/push", include_in_schema=False)
def dev_push() -> list[dict]:
    """Development only: recent push notifications sent by the log provider."""
    if not settings.is_development:
        raise APIError(404, "not_found", "Not found.")
    return read_dev_pushes()
