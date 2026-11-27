"""Report content model, rendered to PDF or CSV by app.reports.render."""

from dataclasses import dataclass, field


@dataclass
class Table:
    headers: list[str]
    rows: list[list[str]]
    widths: list[float] | None = None


@dataclass
class Section:
    heading: str
    paragraphs: list[str] = field(default_factory=list)
    bullets: list[str] = field(default_factory=list)
    table: Table | None = None
    chart: list[tuple[str, int]] | None = None  # (label, value) points for a trend line


@dataclass
class ReportContent:
    title: str
    organisation: str
    period: str
    kpis: list[tuple[str, str, str]] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    csv: Table | None = None
