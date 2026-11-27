"""Scan orchestration: accept a submission, queue it, run the right analysers, store results.

Flow: submit() validates, redacts and encrypts the content, creates a ``queued`` scan and puts
its id on the Redis queue (or runs it immediately when SCAN_INLINE is on). A worker calls
run_scan(), which writes evidence, the verdict and side effects (notifications, webhooks,
usage, indicator observations).
"""

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import redis
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import system_context
from app.core.errors import APIError
from app.core.redis import redis_client
from app.detection import email_analysis, scoring, text, urls, website
from app.detection.brands import Brand
from app.detection.signals import Signal, info
from app.intelligence import domains, providers
from app.intelligence import service as intel
from app.models import ApiKey, IntelligenceSource, Organisation, Scan, ScanEvidence, User
from app.security.tokens import decrypt_secret, encrypt_secret
from app.services.plans import get_plan

log = logging.getLogger(__name__)
QUEUE = "scan-queue"
KINDS = {"url", "message", "email", "qr"}


# --- Submission ------------------------------------------------------------------------------


def _quota_key(scope: str) -> str:
    return f"quota:{scope}:{datetime.now(UTC):%Y%m%d}"


def check_quota(
    db: Session, *, user: User | None, organisation: Organisation | None, count: int = 1
) -> None:
    """Personal accounts have a daily allowance; organisations a monthly one per plan."""
    if organisation is not None:
        plan = get_plan(_org_plan_code(db, organisation))
        if plan.monthly_scans is None:
            return
        month_start = datetime.now(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        used = (
            db.scalar(
                select(func.count()).where(
                    Scan.organisation_id == organisation.id, Scan.created_at >= month_start
                )
            )
            or 0
        )
        if used + count > plan.monthly_scans:
            raise APIError(
                402,
                "quota_exceeded",
                f"Your organisation has used its {plan.monthly_scans:,} scans for this month. "
                "Upgrade the plan for more.",
            )
        return
    if user is None:
        return
    now = datetime.now(UTC)
    plus = user.personal_plan == "plus" and (
        user.personal_plan_until is None or user.personal_plan_until > now
    )
    limit = settings.plus_daily_scans if plus else settings.free_daily_scans
    key = _quota_key(f"user:{user.id}")
    try:
        used = int(redis_client.get(key) or 0)
    except redis.RedisError:
        return
    if used + count > limit:
        raise APIError(
            429,
            "daily_limit_reached",
            f"You've used today's {limit} free checks. Try again tomorrow"
            + ("." if plus else ", or upgrade to Personal Plus for more."),
        )


def _count_quota(user: User | None, organisation: Organisation | None) -> None:
    if organisation is not None or user is None:
        return
    key = _quota_key(f"user:{user.id}")
    try:
        pipe = redis_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, 2 * 86400)
        pipe.execute()
    except redis.RedisError:
        log.warning("could not count scan quota")


def _org_plan_code(db: Session, organisation: Organisation) -> str:
    from app.models import Subscription

    sub = db.scalar(select(Subscription).where(Subscription.organisation_id == organisation.id))
    return sub.plan_code if sub else "sme"


def _retention_days(organisation: Organisation | None) -> int:
    return organisation.content_retention_days if organisation else settings.content_retention_days


def submit(
    db: Session,
    *,
    kind: str,
    content: str,
    user: User | None,
    organisation: Organisation | None = None,
    api_key: ApiKey | None = None,
    source: str = "web",
    options: dict[str, Any] | None = None,
    allow_external_lookup: bool = True,
    batch_id: uuid.UUID | None = None,
    count_quota: bool = True,
) -> Scan:
    if kind not in KINDS:
        raise APIError(400, "invalid_kind", "Unknown scan type.")
    options = options or {}
    title, stored = _prepare(kind, content, options)
    if count_quota:
        check_quota(db, user=user, organisation=organisation)
    now = datetime.now(UTC)
    scan = Scan(
        user_id=user.id if user else None,
        organisation_id=organisation.id if organisation else None,
        api_key_id=api_key.id if api_key else None,
        batch_id=batch_id,
        kind=kind,
        source=source,
        status="queued",
        title=title[:500],
        content_hash=hashlib.sha256(content.encode("utf-8", "replace")).hexdigest(),
        content_encrypted=encrypt_secret(stored) if stored else None,
        content_expires_at=now + timedelta(days=_retention_days(organisation)) if stored else None,
        options=options,
        allow_external_lookup=allow_external_lookup,
        created_at=now,
    )
    db.add(scan)
    db.flush()
    if count_quota:
        _count_quota(user, organisation)
    return scan


def _prepare(kind: str, content: str, options: dict) -> tuple[str, str | None]:
    """Validate the submission; return (list title, redacted content to keep encrypted)."""
    if kind in {"url", "qr"} and options.get("decoded_as") != "text":
        try:
            parsed = urls.parse_url(content)
        except urls.InvalidURL as exc:
            if kind == "qr":
                options["decoded_as"] = "text"
                return _prepare_text(content, "QR code: ", options)
            raise APIError(422, "invalid_url", str(exc)) from exc
        return parsed.canonical, parsed.canonical
    if kind == "qr":
        return _prepare_text(content, "QR code: ", options)
    if kind == "message":
        return _prepare_text(content, "", options)
    # email
    if len(content.encode("utf-8", "replace")) > settings.max_email_bytes:
        raise APIError(413, "too_large", "That email is too large to check (2 MB maximum).")
    parsed_email = email_analysis.parse_email(content)
    subject = parsed_email.subject or text.redact(parsed_email.text[:80])[0]
    return (subject or "Email").strip()[:200], content


def _prepare_text(content: str, prefix: str, options: dict | None = None) -> tuple[str, str]:
    content = content.strip()
    if not content:
        raise APIError(422, "empty", "Paste the message you want to check.")
    if len(content) > settings.max_message_chars:
        raise APIError(413, "too_large", "That message is too long to check.")
    redacted, removed = text.redact(content)
    if options is not None and removed:
        options["removed_secrets"] = removed
    first = " ".join(redacted.split())[:120]
    return prefix + first, redacted


def enqueue(scan: Scan) -> None:
    try:
        redis_client.rpush(QUEUE, str(scan.id))
    except redis.RedisError:
        # The worker's sweeper picks up queued scans from the database as a fallback.
        log.warning("scan queue unavailable; scan %s will be picked up by the sweeper", scan.id)


def dispatch(db: Session, scan: Scan) -> None:
    """Commit the new scan, then queue it (or run it now in inline mode)."""
    db.commit()
    if settings.scan_inline:
        run_scan(db, scan.id)
    else:
        enqueue(scan)


# --- Running ---------------------------------------------------------------------------------


def fetch_website(url: str) -> dict:
    """Ask the isolated fetcher to load a page. 'inline' runs it in-process (tests only)."""
    if settings.fetcher_url == "inline":
        from app.fetcher.net import fetch

        return fetch(
            url,
            timeout=settings.fetch_timeout_seconds,
            max_redirects=settings.fetch_max_redirects,
            max_bytes=settings.fetch_max_bytes,
        ).to_dict()
    try:
        resp = httpx.post(
            f"{settings.fetcher_url}/fetch",
            json={
                "url": url,
                "timeout": settings.fetch_timeout_seconds,
                "max_redirects": settings.fetch_max_redirects,
                "max_bytes": settings.fetch_max_bytes,
            },
            headers={"X-Fetcher-Token": settings.fetcher_token},
            timeout=settings.fetch_timeout_seconds * 3,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as exc:
        log.warning("fetcher unavailable: %s", type(exc).__name__)
        return {
            "requested_url": url,
            "ok": False,
            "error": "Website analysis is unavailable right now",
            "hops": [],
        }


def _enabled_providers(db: Session) -> set[str]:
    return set(
        db.scalars(
            select(IntelligenceSource.code).where(
                IntelligenceSource.enabled.is_(True), IntelligenceSource.kind == "commercial"
            )
        )
    ) | set(
        db.scalars(
            select(IntelligenceSource.code).where(
                IntelligenceSource.enabled.is_(True), IntelligenceSource.kind == "feed"
            )
        )
    )


class Context:
    def __init__(self, db: Session, scan: Scan, brands: list[Brand]) -> None:
        self.db = db
        self.scan = scan
        self.brands = brands
        self.signals: list[Signal] = []
        self.artifacts: dict[str, Any] = {}
        self.indicator_ids: list[uuid.UUID] = []


def _analyse_link(ctx: Context, raw: str, *, deep: bool, primary: bool) -> dict:
    """Static, reputation, domain and (optionally) website analysis of one URL."""
    try:
        parsed = urls.parse_url(raw)
    except urls.InvalidURL as exc:
        return {"input": raw[:200], "error": str(exc)}
    found: list[Signal] = urls.analyse_url(parsed, ctx.brands)
    rep, ids = intel.lookup_url(ctx.db, parsed)
    found += rep
    ctx.indicator_ids += ids
    detail: dict[str, Any] = {
        "url": parsed.canonical,
        "display_host": parsed.unicode_host,
        "domain": parsed.registrable,
        "scheme": parsed.scheme,
        "intelligence": [],
    }
    if parsed.host:
        ext_checked: list[dict] = []
        if ctx.scan.allow_external_lookup:
            ext, ext_checked = providers.check_url(parsed, _enabled_providers(ctx.db))
            found += ext
        else:
            found.append(
                info(
                    "reputation",
                    "external_lookup_off",
                    "Outside services not consulted",
                    "You chose not to share this link with external threat-intelligence "
                    "providers, so only our own intelligence was checked.",
                )
            )
        detail["intelligence"] = [
            {"provider": "GraceGate intelligence", "status": "match" if rep else "no_match"}
        ] + ext_checked
        dom, facts = domains.domain_signals(ctx.db, parsed.registrable)
        found += dom
        if facts:
            detail["registration"] = facts
    if deep and parsed.host:
        # Secrets in the link are redacted before visiting, so we never use someone's one-time
        # login or reset link on their behalf.
        fetched = fetch_website(parsed.canonical)
        web_signals, facts = website.analyse_fetch(fetched, ctx.brands)
        found += web_signals
        detail["website"] = facts
        final = fetched.get("final_url")
        if fetched.get("ok") and final:
            try:
                final_parsed = urls.parse_url(final)
            except urls.InvalidURL:
                final_parsed = None
            if final_parsed and final_parsed.registrable != parsed.registrable:
                # Judge where the link really lands, too.
                for s in urls.analyse_url(final_parsed, ctx.brands):
                    if s.layer != "positive" and s.weight > 0:
                        s.title = f"Final destination: {s.title[0].lower()}{s.title[1:]}"
                        found.append(s)
                rep2, ids2 = intel.lookup_url(ctx.db, final_parsed)
                found += rep2
                ctx.indicator_ids += ids2
                detail["final_domain"] = final_parsed.registrable
    if not primary:
        # A brand's real address quoted inside a message proves nothing about the message
        # (scammers paste official links next to their own), so positive credit only applies
        # to the link that was actually submitted.
        found = [s for s in found if s.layer != "positive"]
        for s in found:
            s.data.setdefault("link", parsed.canonical)
    ctx.signals += found
    return detail


def _run_url(ctx: Context, content: str) -> None:
    deep = ctx.scan.options.get("check_website", True)
    ctx.artifacts["link"] = _analyse_link(ctx, content, deep=deep, primary=True)


def _run_text(ctx: Context, content: str, *, sender: str | None = None) -> None:
    analysis = text.analyse_text(content, ctx.brands, sender=sender)
    ctx.signals += analysis.signals
    ex = analysis.extracted
    links = []
    for raw in ex.urls[:5]:
        links.append(
            _analyse_link(ctx, raw, deep=bool(ctx.scan.options.get("check_links")), primary=False)
        )
    # A message naming a brand but linking elsewhere is impersonation.
    if analysis.brands and links:
        brand = analysis.brands[0]
        for link in links:
            host = link.get("display_host") or ""
            if host and not any(
                host == d or host.endswith("." + d) for d in brand.official_domains
            ):
                ctx.signals.append(
                    Signal(
                        "message",
                        "brand_link_mismatch",
                        f"Mentions {brand.name} but links to another website",
                        f"The message refers to {brand.name}, but its link goes to "
                        f"{link.get('domain') or host}, not "
                        f"{', '.join(brand.official_domains)}.",
                        50,
                        category=brand.category,
                        data={"brand": brand.name},
                    )
                )
                break
    phone_signals, phone_ids = intel.lookup_phones(ctx.db, ex.phones)
    ctx.signals += phone_signals
    ctx.indicator_ids += phone_ids
    ctx.artifacts["extracted"] = {
        "links": links,
        "phones": [text.mask_phone(p) for p in ex.phones],
        "dial_codes": ex.shortcodes,
        "amounts": ex.amounts,
        "transaction_ids": ex.transaction_ids,
        "emails": ex.emails,
        "brands_mentioned": [b.name for b in analysis.brands],
        "removed_secrets": sorted(
            set(analysis.removed) | set(ctx.scan.options.get("removed_secrets", []))
        ),
    }


def _run_email(ctx: Context, content: str) -> None:
    parsed = email_analysis.parse_email(content)
    ctx.signals += email_analysis.analyse_email(parsed, ctx.brands)
    sender_signals, ids = intel.lookup_emails(
        ctx.db, [a for a in (parsed.from_address, parsed.reply_to) if a]
    )
    ctx.signals += sender_signals
    ctx.indicator_ids += ids
    body = parsed.text or ""
    hrefs = [h for h, _ in parsed.links if h.lower().startswith(("http://", "https://"))]
    combined = body + ("\n" + "\n".join(hrefs[:5]) if hrefs else "")
    _run_text(ctx, combined[: settings.max_message_chars])
    ctx.artifacts["email"] = {
        "from": f"{parsed.from_name} <{parsed.from_address}>".strip()
        if parsed.from_address
        else None,
        "reply_to": parsed.reply_to or None,
        "return_path": parsed.return_path or None,
        "subject": parsed.subject or None,
        "date": parsed.date or None,
        "received_hops": parsed.received_count,
        "authentication": parsed.auth,
        "attachments": [
            {"filename": a.filename[:120], "content_type": a.content_type, "size": a.size}
            for a in parsed.attachments[:20]
        ],
        "headers_provided": parsed.has_headers,
    }


def run_scan(db: Session, scan_id: uuid.UUID) -> Scan | None:
    with system_context(db):
        scan = db.get(Scan, scan_id, with_for_update=True)
        if scan is None or scan.status not in {"queued", "running"}:
            db.rollback()
            return scan
        scan.status = "running"
        scan.started_at = datetime.now(UTC)
        scan.attempts += 1
        db.commit()
    try:
        with system_context(db):
            _execute(db, scan)
            db.commit()
    except Exception:  # noqa: BLE001 - a broken scan must not take the worker down
        log.exception("scan %s failed", scan_id)
        db.rollback()
        with system_context(db):
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = "failed" if scan.attempts >= 2 else "queued"
                scan.error = "The analysis could not be completed. Please try again."
                db.commit()
                if scan.status == "queued" and not settings.scan_inline:
                    enqueue(scan)
    with system_context(db):
        scan = db.get(Scan, scan_id)
        if scan and scan.status == "completed":
            from app.scanning import effects

            effects.after_scan(db, scan)
            db.commit()
    return scan


def _execute(db: Session, scan: Scan) -> None:
    content = decrypt_secret(scan.content_encrypted) if scan.content_encrypted else ""
    if content is None:
        raise RuntimeError("content could not be decrypted")
    ctx = Context(db, scan, intel.load_brands(db, scan.organisation_id))
    kind = scan.kind
    if kind == "url" or (kind == "qr" and scan.options.get("decoded_as") != "text"):
        _run_url(ctx, content)
        family = "url"
    elif kind == "email":
        _run_email(ctx, content)
        family = "email"
    else:
        _run_text(ctx, content, sender=scan.options.get("sender"))
        family = "message"
    if kind == "qr":
        ctx.artifacts["qr"] = {"decoded_as": scan.options.get("decoded_as", "url")}
    assessment = scoring.assess(family, ctx.signals)
    db.query(ScanEvidence).filter(ScanEvidence.scan_id == scan.id).delete()
    ordered = sorted(ctx.signals, key=lambda s: (-s.weight, s.layer))
    for position, s in enumerate(ordered[:40]):
        db.add(
            ScanEvidence(
                scan_id=scan.id,
                user_id=scan.user_id,
                organisation_id=scan.organisation_id,
                layer=s.layer,
                code=s.code,
                severity=s.severity,
                title=s.title[:200],
                description=s.description,
                source_kind=s.source_kind,
                source_name=s.source_name[:120],
                reliability=s.reliability,
                weight=s.weight,
                data=json.loads(json.dumps(s.data, default=str)),
                position=position,
            )
        )
    scan.verdict = assessment.verdict
    scan.risk_score = assessment.score
    scan.confidence = assessment.confidence
    scan.headline = assessment.headline
    scan.summary = assessment.summary
    scan.recommendations = assessment.recommendations
    scan.category = assessment.category
    ctx.artifacts["indicator_ids"] = [str(i) for i in dict.fromkeys(ctx.indicator_ids)]
    scan.artifacts = json.loads(json.dumps(ctx.artifacts, default=str))
    scan.status = "completed"
    scan.error = None
    scan.completed_at = datetime.now(UTC)
