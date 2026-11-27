"""Signed webhooks for business integrations.

Each delivery is signed with HMAC-SHA256 over ``timestamp.body`` using the endpoint's secret:

    X-PSD-Signature: t=<unix seconds>,v1=<hex digest>

Receivers should recompute the digest, compare in constant time and reject old timestamps.
Deliveries are retried with backoff; the target URL is checked against private addresses
like any other outbound request.
"""

import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.fetcher.net import UnsafeTarget, resolve_public
from app.models import WebhookDelivery, WebhookEndpoint
from app.security.tokens import decrypt_secret

log = logging.getLogger(__name__)
EVENTS = (
    "scan.completed",
    "scan.high_risk",
    "case.created",
    "case.closed",
    "report.status_changed",
)
MAX_ATTEMPTS = 6


def sign(secret: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"t={timestamp},v1={mac.hexdigest()}"


def emit(db: Session, organisation_id: uuid.UUID, event: str, data: dict) -> int:
    endpoints = db.scalars(
        select(WebhookEndpoint).where(
            WebhookEndpoint.organisation_id == organisation_id,
            WebhookEndpoint.active.is_(True),
        )
    ).all()
    count = 0
    for ep in endpoints:
        if event not in ep.events:
            continue
        db.add(
            WebhookDelivery(
                endpoint_id=ep.id,
                organisation_id=organisation_id,
                event=event,
                payload={
                    "id": uuid.uuid4().hex,
                    "event": event,
                    "created_at": datetime.now(UTC).isoformat(),
                    "data": data,
                },
            )
        )
        count += 1
    return count


def check_target(url: str) -> None:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme != "https" and not settings.is_development:
        raise UnsafeTarget("Webhook URLs must use https")
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise UnsafeTarget("Enter a full http(s) URL")
    if not settings.allow_private_fetch_targets:
        resolve_public(parts.hostname, parts.port or 443)


def deliver(db: Session, delivery: WebhookDelivery) -> bool:
    endpoint = db.get(WebhookEndpoint, delivery.endpoint_id)
    if endpoint is None or not endpoint.active:
        delivery.status = "failed"
        delivery.last_error = "Endpoint disabled"
        return False
    secret = decrypt_secret(endpoint.secret_encrypted) or ""
    body = json.dumps(delivery.payload, separators=(",", ":")).encode()
    ts = int(time.time())
    delivery.attempts += 1
    try:
        check_target(endpoint.url)
        resp = httpx.post(
            endpoint.url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "GraceGate-Webhooks/1.0",
                "X-PSD-Event": delivery.event,
                "X-PSD-Delivery": str(delivery.id),
                "X-PSD-Signature": sign(secret, ts, body),
            },
            timeout=settings.webhook_timeout_seconds,
            follow_redirects=False,
        )
        delivery.response_status = resp.status_code
        ok = 200 <= resp.status_code < 300
        error = None if ok else f"HTTP {resp.status_code}"
    except (UnsafeTarget, LookupError) as exc:
        ok, error = False, str(exc)[:300]
    except httpx.HTTPError as exc:
        ok, error = False, type(exc).__name__
    now = datetime.now(UTC)
    if ok:
        delivery.status = "delivered"
        delivery.delivered_at = now
        delivery.last_error = None
        endpoint.consecutive_failures = 0
        return True
    delivery.last_error = error
    endpoint.consecutive_failures += 1
    if delivery.attempts >= MAX_ATTEMPTS:
        delivery.status = "failed"
    else:
        delivery.next_attempt_at = now + timedelta(minutes=2**delivery.attempts)
    if endpoint.consecutive_failures >= 50:
        endpoint.active = False
    return False


def deliver_due(db: Session, limit: int = 50) -> int:
    due = db.scalars(
        select(WebhookDelivery)
        .where(
            WebhookDelivery.status == "pending",
            WebhookDelivery.next_attempt_at <= datetime.now(UTC),
        )
        .order_by(WebhookDelivery.next_attempt_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    ).all()
    for d in due:
        deliver(db, d)
    return len(due)
