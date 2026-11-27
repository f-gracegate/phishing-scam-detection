"""Personal account features: notifications, browser-extension tokens, public warnings."""

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, get_auth
from app.core.db import get_db, system_context
from app.core.errors import APIError, not_found
from app.core.redis import rate_limit
from app.intelligence.service import CATEGORY_LABELS
from app.models import ApiKey, Notification, ThreatCampaign
from app.security.tokens import hash_token
from app.services import audit
from app.services.plans import PERSONAL_PLANS

router = APIRouter(tags=["Account"])


# --- Notifications -------------------------------------------------------------------------------


@router.get("/notifications")
def list_notifications(
    auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)
) -> dict:
    rows = db.scalars(
        select(Notification)
        .where(Notification.user_id == auth.user.id)
        .order_by(Notification.created_at.desc())
        .limit(50)
    ).all()
    unread = (
        db.scalar(
            select(func.count()).where(
                Notification.user_id == auth.user.id, Notification.read_at.is_(None)
            )
        )
        or 0
    )
    return {
        "unread": unread,
        "items": [
            {
                "id": n.id,
                "kind": n.kind,
                "severity": n.severity,
                "title": n.title,
                "body": n.body,
                "link": n.link,
                "read": n.read_at is not None,
                "created_at": n.created_at,
                "organisation_id": n.organisation_id,
            }
            for n in rows
        ],
    }


@router.post("/notifications/read")
def mark_read(auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> dict:
    db.execute(
        update(Notification)
        .where(Notification.user_id == auth.user.id, Notification.read_at.is_(None))
        .values(read_at=datetime.now(UTC))
    )
    db.commit()
    return {"unread": 0}


# --- Personal plan -----------------------------------------------------------------------------


@router.get("/me/plan")
def my_plan(auth: AuthContext = Depends(get_auth)) -> dict:
    u = auth.user
    active_plus = u.personal_plan == "plus" and (
        u.personal_plan_until is None or u.personal_plan_until > datetime.now(UTC)
    )
    code = "plus" if active_plus else "free"
    plan = PERSONAL_PLANS[code]
    return {
        "code": code,
        "name": plan.name,
        "until": u.personal_plan_until if active_plus else None,
        "features": plan.features,
        "plans": [
            {
                "code": p.code,
                "name": p.name,
                "monthly_price_ghs": p.monthly_price_ghs,
                "features": p.features,
            }
            for p in PERSONAL_PLANS.values()
        ],
    }


# --- Browser extension tokens ------------------------------------------------------------------


class ExtensionTokenIn(BaseModel):
    name: str = Field(default="Browser extension", min_length=2, max_length=100)


@router.get("/me/extension-tokens")
def list_tokens(auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> list:
    rows = db.scalars(
        select(ApiKey)
        .where(
            ApiKey.user_id == auth.user.id, ApiKey.kind == "extension", ApiKey.status == "active"
        )
        .order_by(ApiKey.created_at.desc())
    ).all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "prefix": k.prefix,
            "created_at": k.created_at,
            "last_used_at": k.last_used_at,
            "expires_at": k.expires_at,
        }
        for k in rows
    ]


@router.post("/me/extension-tokens", status_code=201)
def create_token(
    body: ExtensionTokenIn,
    request: Request,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> dict:
    rate_limit(f"ext-token:{auth.user.id}", limit=10, window_seconds=3600)
    active = (
        db.scalar(
            select(func.count()).where(
                ApiKey.user_id == auth.user.id,
                ApiKey.kind == "extension",
                ApiKey.status == "active",
            )
        )
        or 0
    )
    if active >= 5:
        raise APIError(409, "too_many_tokens", "Revoke an old browser connection first.")
    secret = "pse_" + secrets.token_urlsafe(32)
    with system_context(db):
        key = ApiKey(
            user_id=auth.user.id,
            kind="extension",
            name=body.name,
            prefix=secret[:12],
            key_hash=hash_token(secret),
            scopes=["scans"],
            created_by=auth.user.id,
            expires_at=datetime.now(UTC) + timedelta(days=365),
        )
        db.add(key)
        db.flush()
        audit.record(
            db,
            "extension_token.created",
            actor=auth.user,
            resource_type="api_key",
            resource_id=key.id,
            request=request,
        )
        db.commit()
    return {
        "id": key.id,
        "name": key.name,
        "prefix": key.prefix,
        "token": secret,
        "expires_at": key.expires_at,
    }


@router.delete("/me/extension-tokens/{token_id}")
def revoke_token(
    token_id: uuid.UUID, auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)
) -> dict:
    with system_context(db):
        key = db.scalar(select(ApiKey).where(ApiKey.id == token_id, ApiKey.user_id == auth.user.id))
        if key is None:
            raise not_found("Token")
        key.status, key.revoked_at = "revoked", datetime.now(UTC)
        db.commit()
    return {"revoked": True}


# --- Public warnings ---------------------------------------------------------------------------


@router.get("/public/warnings")
def public_warnings(db: Session = Depends(get_db)) -> list[dict]:
    """Published scam warnings. Contains no private message content or personal numbers."""
    rows = db.scalars(
        select(ThreatCampaign)
        .where(ThreatCampaign.published.is_(True))
        .order_by(ThreatCampaign.published_at.desc())
        .limit(10)
    ).all()
    return [
        {
            "id": c.id,
            "title": c.public_title,
            "summary": c.public_summary,
            "category": c.category,
            "category_label": CATEGORY_LABELS.get(c.category, c.category),
            "published_at": c.published_at,
        }
        for c in rows
    ]
