"""Domain registration facts (RDAP), cached per registrable domain.

A young domain is *not* malicious by itself — a new business may have registered yesterday. It
only adds weight next to other signs, which the scoring engine handles.
"""

import logging
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.detection.signals import Signal, info
from app.models import Domain

log = logging.getLogger(__name__)
RDAP_CACHE_DAYS = 7


def _rdap(name: str) -> tuple[datetime | None, str | None]:
    resp = httpx.get(
        f"{settings.rdap_base_url}/domain/{name}",
        timeout=5,
        follow_redirects=True,
        headers={"Accept": "application/rdap+json"},
    )
    if resp.status_code == 404:
        return None, None
    resp.raise_for_status()
    body = resp.json()
    registered = None
    for event in body.get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            registered = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
    registrar = None
    for entity in body.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [None, []])[1]
            for item in vcard:
                if item and item[0] == "fn":
                    registrar = str(item[3])[:200]
    return registered, registrar


def domain_signals(db: Session, registrable: str) -> tuple[list[Signal], dict]:
    if not registrable or "." not in registrable:
        return [], {}
    domain = db.scalar(select(Domain).where(Domain.name == registrable))
    now = datetime.now(UTC)
    if domain is None:
        domain = Domain(name=registrable, first_seen_at=now)
        db.add(domain)
        db.flush()
    stale = domain.rdap_checked_at is None or domain.rdap_checked_at < now - timedelta(
        days=RDAP_CACHE_DAYS
    )
    if settings.rdap_enabled and stale:
        try:
            domain.registered_at, domain.registrar = _rdap(registrable)
        except (httpx.HTTPError, ValueError) as exc:
            log.info("rdap lookup failed for %s: %s", registrable, type(exc).__name__)
        domain.rdap_checked_at = now
    facts: dict = {"domain": registrable}
    signals: list[Signal] = []
    if domain.registered_at:
        age = (now - domain.registered_at).days
        facts.update(
            registered_at=domain.registered_at.isoformat(), age_days=age, registrar=domain.registrar
        )
        if age < 7:
            signals.append(
                Signal(
                    "domain",
                    "domain_very_new",
                    "Domain registered in the last week",
                    f"{registrable} was registered {age} day(s) ago. Scam sites are usually "
                    "brand new; on its own this isn't proof.",
                    30,
                    source_kind="observed",
                    data={"age_days": age},
                )
            )
        elif age < 30:
            signals.append(
                Signal(
                    "domain",
                    "domain_new",
                    "Domain registered in the last month",
                    f"{registrable} was registered {age} days ago.",
                    15,
                    source_kind="observed",
                    data={"age_days": age},
                )
            )
        elif age > 365 * 3:
            signals.append(
                info(
                    "domain",
                    "domain_established",
                    "Long-established domain",
                    f"{registrable} has been registered for over {age // 365} years. Old "
                    "domains can still be hacked or misused.",
                )
            )
    return signals, facts
