"""Monthly security report for a business workspace (PDF)."""

import calendar
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.detection.scoring import VERDICT_LABELS
from app.intelligence.service import CATEGORY_LABELS
from app.models import Case, Organisation, ScamReport, Scan
from app.reports.content import ReportContent, Section, Table
from app.reports.render import to_pdf


def monthly_pdf(db: Session, org: Organisation, year: int, month: int) -> bytes:
    start = datetime(year, month, 1, tzinfo=UTC)
    end = datetime(year + (month == 12), month % 12 + 1, 1, tzinfo=UTC)
    in_month = (Scan.organisation_id == org.id, Scan.created_at >= start, Scan.created_at < end)
    total = db.scalar(select(func.count()).where(*in_month)) or 0
    verdicts = dict(
        db.execute(select(Scan.verdict, func.count()).where(*in_month).group_by(Scan.verdict)).all()
    )
    kinds = dict(
        db.execute(select(Scan.kind, func.count()).where(*in_month).group_by(Scan.kind)).all()
    )
    high = verdicts.get("high", 0) + verdicts.get("critical", 0)
    categories = db.execute(
        select(Scan.category, func.count())
        .where(
            *in_month,
            Scan.category.is_not(None),
            Scan.verdict.in_(("suspicious", "high", "critical")),
        )
        .group_by(Scan.category)
        .order_by(func.count().desc())
        .limit(8)
    ).all()
    day = func.date_trunc("day", Scan.created_at)
    trend = db.execute(select(day, func.count()).where(*in_month).group_by(day).order_by(day)).all()
    worst = db.scalars(
        select(Scan)
        .where(*in_month, Scan.verdict.in_(("high", "critical")))
        .order_by(Scan.risk_score.desc())
        .limit(15)
    ).all()
    reports = (
        db.scalar(
            select(func.count()).where(
                ScamReport.organisation_id == org.id,
                ScamReport.created_at >= start,
                ScamReport.created_at < end,
            )
        )
        or 0
    )
    cases_opened = (
        db.scalar(
            select(func.count()).where(
                Case.organisation_id == org.id, Case.created_at >= start, Case.created_at < end
            )
        )
        or 0
    )
    cases_closed = (
        db.scalar(
            select(func.count()).where(
                Case.organisation_id == org.id, Case.closed_at >= start, Case.closed_at < end
            )
        )
        or 0
    )

    period = f"{calendar.month_name[month]} {year}"
    content = ReportContent(
        title="Monthly phishing and scam report",
        organisation=org.name,
        period=period,
        kpis=[
            ("Items checked", f"{total:,}", "links, messages and emails"),
            ("High risk", f"{high:,}", f"{(high / total * 100):.0f}% of checks" if total else "—"),
            ("Employee reports", f"{reports:,}", "suspected scams reported"),
            ("Cases", f"{cases_opened} / {cases_closed}", "opened / closed"),
        ],
    )
    content.sections.append(
        Section(
            heading="Summary",
            paragraphs=[
                f"In {period}, your team checked {total:,} item(s): {kinds.get('url', 0):,} links, "
                f"{kinds.get('message', 0):,} messages, {kinds.get('email', 0):,} emails and "
                f"{kinds.get('qr', 0):,} QR codes. {high:,} were rated high or critical risk and "
                f"{verdicts.get('suspicious', 0):,} suspicious.",
                "Scores are assessments based on the evidence available at the time of each check, "
                "not guarantees. 'Unknown' means no warning signs were found, not that an item "
                "was safe.",
            ],
            chart=[(d.strftime("%d"), n) for d, n in trend] or None,
        )
    )
    if categories:
        content.sections.append(
            Section(
                heading="Most common scam types",
                table=Table(
                    ["Type", "Detections"],
                    [[CATEGORY_LABELS.get(c, c), str(n)] for c, n in categories],
                ),
            )
        )
    if worst:
        content.sections.append(
            Section(
                heading="Highest-risk items",
                table=Table(
                    ["Date", "Type", "Item", "Verdict", "Score"],
                    [
                        [
                            s.created_at.strftime("%d %b"),
                            s.kind,
                            s.title[:70],
                            VERDICT_LABELS.get(s.verdict or "", "—"),
                            str(s.risk_score or ""),
                        ]
                        for s in worst
                    ],
                    widths=[18, 16, 96, 24, 14],
                ),
            )
        )
    content.sections.append(
        Section(
            heading="Recommendations",
            bullets=[
                "Remind staff never to share PINs, passwords or one-time codes, by phone or "
                "message.",
                "Encourage staff to check suspicious links and messages before acting on them.",
                "Verify payment-change requests by calling a known number, never one in the "
                "message.",
                "Review open investigation cases and close them with an outcome.",
            ],
        )
    )
    return to_pdf(content, "monthly")
