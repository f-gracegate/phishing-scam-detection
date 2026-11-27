"""Indicator storage and lookup.

Verified indicators produce strong evidence. Unverified ones (community reports) produce only a
weak "reported, not verified" signal and are never shown with the reporter's details.
"""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.detection.brands import Brand
from app.detection.signals import Signal
from app.detection.text import mask_phone, normalise_phone
from app.detection.urls import InvalidURL, ParsedURL, parse_url
from app.models import (
    BrandProfile,
    Indicator,
    IndicatorHistory,
    IndicatorObservation,
    IntelligenceSource,
    User,
)

PERSONAL_TYPES = {"phone", "momo_number", "wallet"}
INDICATOR_TYPES = {"url", "domain", "ip", "phone", "email", "sender_id", "momo_number", "wallet"}

CATEGORY_LABELS = {
    "momo": "Mobile money scam",
    "bank": "Bank impersonation",
    "government": "Government impersonation",
    "delivery": "Delivery scam",
    "recruitment": "Recruitment scam",
    "investment": "Investment scam",
    "ecommerce": "Online shopping scam",
    "social_engineering": "Social engineering",
    "impersonation": "Impersonation",
    "crypto": "Cryptocurrency scam",
    "university": "University / scholarship scam",
    "romance": "Romance or advance-fee scam",
    "prize": "Prize or lottery scam",
    "advance_fee": "Advance-fee fraud",
    "malware": "Malware",
    "other": "Other",
}


class InvalidIndicator(ValueError):
    pass


def value_hash(kind: str, value: str) -> str:
    return hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()


def normalise(kind: str, raw: str) -> tuple[str | None, str, str]:
    """Returns (stored value or None for personal data, hash, display value)."""
    raw = raw.strip()
    if kind not in INDICATOR_TYPES:
        raise InvalidIndicator("Unknown indicator type.")
    if kind == "url":
        try:
            url = parse_url(raw)
        except InvalidURL as exc:
            raise InvalidIndicator(str(exc)) from exc
        value = url.canonical
        return value, value_hash(kind, value), value[:300]
    if kind == "domain":
        try:
            host = parse_url(raw).host
        except InvalidURL as exc:
            raise InvalidIndicator(str(exc)) from exc
        return host, value_hash(kind, host), host
    if kind in {"phone", "momo_number"}:
        e164 = normalise_phone(raw)
        if not e164:
            raise InvalidIndicator("Enter a Ghanaian phone number, such as 024 123 4567.")
        return None, value_hash("phone", e164), mask_phone(e164)
    if kind == "email":
        value = raw.lower()
        if "@" not in value:
            raise InvalidIndicator("Enter a valid email address.")
        return value, value_hash(kind, value), value
    value = raw.lower() if kind != "wallet" else raw
    if kind == "wallet":
        return None, value_hash(kind, value), value[:6] + "…" + value[-4:]
    return value, value_hash(kind, value), value[:300]


def source_by_code(db: Session, code: str) -> IntelligenceSource | None:
    return db.scalar(select(IntelligenceSource).where(IntelligenceSource.code == code))


def upsert_indicator(
    db: Session,
    kind: str,
    raw: str,
    *,
    source_code: str,
    category: str | None = None,
    report_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    status: str = "unverified",
    confidence: str = "low",
) -> Indicator:
    """Find or create an indicator and record that we saw it again.

    Never upgrades status: only an analyst review (or a licensed feed) verifies.
    """
    stored, digest, display = normalise(kind, raw)
    lookup_type = "phone" if kind == "momo_number" else kind
    now = datetime.now(UTC)
    source = source_by_code(db, source_code)
    indicator = db.scalar(
        select(Indicator).where(Indicator.type == lookup_type, Indicator.value_hash == digest)
    )
    if indicator is None:
        indicator = Indicator(
            type=lookup_type,
            value=stored,
            value_hash=digest,
            display_value=display,
            status=status,
            confidence=confidence,
            category=category,
            source_id=source.id if source else None,
            first_seen_at=now,
            last_seen_at=now,
            report_count=0,
        )
        db.add(indicator)
        db.flush()
    else:
        indicator.last_seen_at = now
        if category and not indicator.category:
            indicator.category = category
    if report_id:
        indicator.report_count += 1
    db.add(
        IndicatorObservation(
            indicator_id=indicator.id,
            source_id=source.id if source else None,
            report_id=report_id,
            scan_id=scan_id,
            observed_at=now,
        )
    )
    return indicator


def change_status(
    db: Session,
    indicator: Indicator,
    *,
    status: str,
    confidence: str,
    actor: User | None,
    reason: str,
    expires_in_days: int | None = None,
) -> None:
    db.add(
        IndicatorHistory(
            indicator_id=indicator.id,
            actor_id=actor.id if actor else None,
            actor_label=actor.email if actor else "system",
            from_status=indicator.status,
            to_status=status,
            from_confidence=indicator.confidence,
            to_confidence=confidence,
            reason=reason[:2000],
        )
    )
    now = datetime.now(UTC)
    indicator.status = status
    indicator.confidence = confidence
    if status == "verified":
        indicator.last_verified_at = now
        indicator.reviewed_by = actor.id if actor else None
        indicator.reviewed_at = now
        if expires_in_days:
            indicator.expires_at = now + timedelta(days=expires_in_days)
    elif actor:
        indicator.reviewed_by = actor.id
        indicator.reviewed_at = now


def _live(q):
    now = datetime.now(UTC)
    return q.where(
        Indicator.status.in_(("verified", "unverified")),
        or_(Indicator.expires_at.is_(None), Indicator.expires_at > now),
    )


def _signal_for(ind: Indicator, label: str, matched: str) -> Signal | None:
    category = CATEGORY_LABELS.get(ind.category or "", "scam")
    seen = ind.last_verified_at or ind.last_seen_at
    when = seen.strftime("%d %b %Y") if seen else "recently"
    if ind.status == "verified":
        strong = ind.disposition == "malicious"
        return Signal(
            "reputation",
            "verified_indicator",
            f"{label} is on our verified threat list",
            f"Our analysts verified {matched} as {'malicious' if strong else 'suspicious'} "
            f"({category.lower()}), last confirmed {when}. "
            f"Confidence: {ind.confidence}.",
            95 if strong and ind.confidence != "low" else (75 if strong else 55),
            source_kind="verified_intel",
            source_name="GraceGate verified intelligence",
            reliability="high" if ind.confidence == "high" else "medium",
            category=ind.category,
            data={
                "indicator_id": str(ind.id),
                "matched": matched,
                "last_verified": seen.isoformat() if seen else None,
            },
        )
    if ind.report_count > 0:
        return Signal(
            "community",
            "community_reports",
            f"{label} has been reported by others (not verified)",
            f"{ind.report_count} report{'s' if ind.report_count != 1 else ''} mention "
            f"{matched}. Reports haven't been checked by an analyst yet, so treat this as a "
            "warning sign, not proof.",
            min(10 + 5 * ind.report_count, 30),
            source_kind="community",
            source_name="Community reports",
            reliability="low",
            category=ind.category,
            data={"indicator_id": str(ind.id), "reports": ind.report_count},
        )
    return None


def lookup_url(db: Session, url: ParsedURL) -> tuple[list[Signal], list[uuid.UUID]]:
    keys: list[tuple[str, str, str, str]] = []  # (type, hash, label, matched)
    keys.append(("url", value_hash("url", url.canonical), "This exact link", url.canonical))
    if url.query:
        bare = url.canonical.split("?", 1)[0]
        keys.append(("url", value_hash("url", bare), "This link", bare))
    if url.is_ip:
        keys.append(("ip", value_hash("ip", url.host), "This IP address", url.host))
    else:
        keys.append(("domain", value_hash("domain", url.host), "This website", url.host))
        if url.registrable and url.registrable != url.host:
            keys.append(
                ("domain", value_hash("domain", url.registrable), "This domain", url.registrable)
            )
    found = (
        db.execute(
            _live(select(Indicator)).where(
                or_(*[(Indicator.type == t) & (Indicator.value_hash == h) for t, h, _, _ in keys])
            )
        )
        .scalars()
        .all()
    )
    by_key = {(i.type, i.value_hash): i for i in found}
    signals: list[Signal] = []
    matched_ids: list[uuid.UUID] = []
    verified_seen = False
    for t, h, label, matched in keys:
        ind = by_key.get((t, h))
        if not ind:
            continue
        if ind.status == "verified":
            if verified_seen:
                continue
            verified_seen = True
        sig = _signal_for(ind, label, matched)
        if sig:
            signals.append(sig)
            matched_ids.append(ind.id)
    return signals, matched_ids


def lookup_phones(db: Session, phones: list[str]) -> tuple[list[Signal], list[uuid.UUID]]:
    if not phones:
        return [], []
    hashes = {value_hash("phone", p): p for p in phones}
    found = (
        db.execute(
            _live(select(Indicator)).where(
                Indicator.type == "phone", Indicator.value_hash.in_(list(hashes))
            )
        )
        .scalars()
        .all()
    )
    signals, ids = [], []
    for ind in found:
        sig = _signal_for(ind, "A phone number in this message", ind.display_value)
        if sig:
            signals.append(sig)
            ids.append(ind.id)
    return signals, ids


def lookup_emails(db: Session, addresses: list[str]) -> tuple[list[Signal], list[uuid.UUID]]:
    if not addresses:
        return [], []
    hashes = {value_hash("email", a.lower()): a for a in addresses}
    found = (
        db.execute(
            _live(select(Indicator)).where(
                Indicator.type == "email", Indicator.value_hash.in_(list(hashes))
            )
        )
        .scalars()
        .all()
    )
    signals, ids = [], []
    for ind in found:
        sig = _signal_for(ind, "The sender's address", ind.display_value)
        if sig:
            signals.append(sig)
            ids.append(ind.id)
    return signals, ids


def load_brands(db: Session, organisation_id: uuid.UUID | None) -> list[Brand]:
    q = select(BrandProfile).where(BrandProfile.active.is_(True))
    if organisation_id:
        q = q.where(
            or_(
                BrandProfile.organisation_id.is_(None),
                BrandProfile.organisation_id == organisation_id,
            )
        )
    else:
        q = q.where(BrandProfile.organisation_id.is_(None))
    return [
        Brand(
            name=b.name,
            category=b.category,
            official_domains=tuple(d.lower() for d in b.official_domains),
            keywords=tuple(k.lower() for k in b.keywords),
            sender_ids=tuple(b.sender_ids),
            official_contact=b.official_contact,
            id=str(b.id),
        )
        for b in db.scalars(q.order_by(BrandProfile.name))
    ]
