"""Gauges for /api/metrics: queue depth and backlog, read from the database and Redis."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from app.core.db import SessionLocal
from app.core.redis import redis_client
from app.models import Notification, Scan, WebhookDelivery


def collect_gauges() -> dict[str, float]:
    gauges: dict[str, float] = {}
    try:
        gauges["psd_scan_queue_length"] = float(redis_client.llen("scan-queue"))
    except Exception:  # noqa: BLE001
        gauges["psd_scan_queue_length"] = -1
    db = SessionLocal()
    db.info["rls"] = {"bypass": True}
    try:
        stale = datetime.now(UTC) - timedelta(minutes=2)
        gauges["psd_scans_waiting"] = float(
            db.scalar(select(func.count()).where(Scan.status == "queued", Scan.created_at < stale))
            or 0
        )
        gauges["psd_scans_failed_24h"] = float(
            db.scalar(
                select(func.count()).where(
                    Scan.status == "failed", Scan.created_at > datetime.now(UTC) - timedelta(days=1)
                )
            )
            or 0
        )
        gauges["psd_webhooks_pending"] = float(
            db.scalar(select(func.count()).where(WebhookDelivery.status == "pending")) or 0
        )
        gauges["psd_push_backlog"] = float(
            db.scalar(select(func.count()).where(Notification.pushed_at.is_(None))) or 0
        )
    finally:
        db.close()
    return gauges
