"""What happens after a scan completes: observations, usage, notifications and webhooks."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import (
    ApiUsage,
    IndicatorObservation,
    Membership,
    Notification,
    Scan,
)
from app.security.rbac import Perm, permissions_for
from app.services import webhooks

HIGH = {"high", "critical"}


def scan_payload(scan: Scan) -> dict:
    return {
        "scan_id": str(scan.id),
        "kind": scan.kind,
        "status": scan.status,
        "verdict": scan.verdict,
        "risk_score": scan.risk_score,
        "confidence": scan.confidence,
        "category": scan.category,
        "title": scan.title,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }


def after_scan(db: Session, scan: Scan) -> None:
    for raw in scan.artifacts.get("indicator_ids", [])[:20]:
        db.add(
            IndicatorObservation(
                indicator_id=uuid.UUID(raw), scan_id=scan.id, details={"kind": "scan_match"}
            )
        )
    if scan.organisation_id is None:
        if scan.user_id and scan.source in {"api", "extension", "share"} and scan.verdict in HIGH:
            db.add(
                Notification(
                    user_id=scan.user_id,
                    kind="scan_completed",
                    severity=scan.verdict,
                    title=scan.headline or "High-risk result",
                    body=scan.title[:200],
                    link=f"/scans/{scan.id}",
                )
            )
        return
    if scan.api_key_id:
        stmt = (
            insert(ApiUsage)
            .values(
                id=uuid.uuid4(),
                organisation_id=scan.organisation_id,
                day=datetime.now(UTC).date(),
                endpoint=f"scans.{scan.kind}",
                quantity=1,
            )
            .on_conflict_do_update(
                index_elements=["organisation_id", "day", "endpoint"],
                set_={"quantity": ApiUsage.quantity + 1},
            )
        )
        db.execute(stmt)
    payload = scan_payload(scan)
    webhooks.emit(db, scan.organisation_id, "scan.completed", payload)
    if scan.verdict in HIGH:
        webhooks.emit(db, scan.organisation_id, "scan.high_risk", payload)
        analysts = db.execute(
            select(Membership.user_id, Membership.role).where(
                Membership.organisation_id == scan.organisation_id,
                Membership.status == "active",
            )
        ).all()
        for user_id, role in analysts:
            if Perm.SCANS_READ_ALL in permissions_for(role) and user_id != scan.user_id:
                db.add(
                    Notification(
                        user_id=user_id,
                        organisation_id=scan.organisation_id,
                        kind="scan_completed",
                        severity=scan.verdict,
                        title=f"High-risk {scan.kind} submitted",
                        body=(scan.headline or "")[:200],
                        link=f"/business/scans/{scan.id}",
                    )
                )
