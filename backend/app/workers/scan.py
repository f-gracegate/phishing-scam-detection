"""Scan worker: runs queued scans and the periodic housekeeping jobs.

    python -m app.workers.scan

Several workers can run side by side. Scans are claimed from the Redis queue; the database is
the source of truth, so a sweeper re-queues scans whose worker disappeared and picks up any
that were created while Redis was unavailable.
"""

import logging
import signal
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import redis
from sqlalchemy import select, update

from app.billing.service import sweep_subscriptions
from app.core.db import SessionLocal
from app.core.observability import configure_logging, worker_heartbeat
from app.core.redis import redis_client
from app.intelligence.service import change_status
from app.models import Indicator, Scan
from app.privacy.service import purge_expired_content, run_due_erasures
from app.scanning.service import QUEUE, run_scan
from app.services.push import dispatch_pending
from app.services.webhooks import deliver_due

log = logging.getLogger("app.workers.scan")
CONCURRENCY = 8
HOUSEKEEPING_SECONDS = 30


def _session():
    db = SessionLocal()
    db.info["rls"] = {"bypass": True}
    return db


def process(scan_id: str) -> None:
    db = _session()
    try:
        run_scan(db, uuid.UUID(scan_id))
    except Exception:  # noqa: BLE001
        log.exception("scan %s crashed the runner", scan_id)
    finally:
        db.close()


def sweep_scans() -> list[str]:
    """Scans queued for a while (lost from Redis) or stuck running (worker died)."""
    db = _session()
    try:
        now = datetime.now(UTC)
        stale_running = (
            db.execute(
                update(Scan)
                .where(Scan.status == "running", Scan.started_at < now - timedelta(minutes=5))
                .values(status="queued")
                .returning(Scan.id)
            )
            .scalars()
            .all()
        )
        waiting = db.scalars(
            select(Scan.id)
            .where(Scan.status == "queued", Scan.created_at < now - timedelta(minutes=1))
            .limit(50)
        ).all()
        db.commit()
        return [str(i) for i in {*stale_running, *waiting}]
    finally:
        db.close()


def expire_indicators() -> int:
    db = _session()
    try:
        due = db.scalars(
            select(Indicator)
            .where(Indicator.status == "verified", Indicator.expires_at <= datetime.now(UTC))
            .limit(500)
        ).all()
        for ind in due:
            change_status(
                db,
                ind,
                status="expired",
                confidence=ind.confidence,
                actor=None,
                reason="Verification period ended; recheck before re-publishing.",
            )
        db.commit()
        return len(due)
    finally:
        db.close()


def housekeeping() -> None:
    jobs = (
        ("webhooks", lambda db: deliver_due(db)),
        ("push", lambda db: dispatch_pending(db)),
        ("content retention", lambda db: purge_expired_content(db)),
        ("erasures", lambda db: run_due_erasures(db)),
        ("billing", lambda db: sweep_subscriptions(db)),
    )
    for name, job in jobs:
        db = _session()
        try:
            count = job(db)
            db.commit()
            if count:
                log.info("%s: %d", name, count)
        except Exception:  # noqa: BLE001
            log.exception("housekeeping job %s failed", name)
            db.rollback()
        finally:
            db.close()
    expired = expire_indicators()
    if expired:
        log.info("expired %d indicator(s)", expired)


def main() -> None:
    configure_logging()
    logging.getLogger("httpx").setLevel(logging.WARNING)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    log.info("scan worker started (concurrency=%s)", CONCURRENCY)
    last_housekeeping = 0.0
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        while not stop.is_set():
            try:
                worker_heartbeat()
                item = redis_client.blpop([QUEUE], timeout=2)
                if item:
                    pool.submit(process, item[1])
                if time.monotonic() - last_housekeeping > HOUSEKEEPING_SECONDS:
                    last_housekeeping = time.monotonic()
                    for scan_id in sweep_scans():
                        pool.submit(process, scan_id)
                    housekeeping()
            except redis.RedisError:
                log.warning("redis unavailable; retrying")
                stop.wait(3)
                for scan_id in sweep_scans():
                    pool.submit(process, scan_id)
            except Exception:  # noqa: BLE001
                log.exception("worker loop error")
                stop.wait(3)
    log.info("scan worker stopped")


if __name__ == "__main__":
    main()
