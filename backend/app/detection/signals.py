"""The unit of explanation: one detected signal with its source, reliability and weight."""

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Where a signal comes from. Shown to people so a rule-based guess is never mistaken for a
# confirmed match in threat intelligence.
SOURCE_LABELS = {
    "model": "Our detection rules",
    "verified_intel": "Verified threat intelligence",
    "external_provider": "External threat intelligence",
    "community": "Community reports (unverified)",
    "observed": "Observed during the scan",
}


@dataclass
class Signal:
    layer: str  # reputation | domain | website | message | email | community | positive
    code: str
    title: str
    description: str
    # 0-100: how strongly this signal on its own points to phishing or fraud.
    weight: int
    source_kind: str = "model"
    source_name: str = "Detection rules"
    reliability: str = "medium"  # low | medium | high
    category: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        if self.layer == "positive" or self.weight <= 0:
            return "info"
        if self.weight >= 85:
            return "critical"
        if self.weight >= 55:
            return "high"
        if self.weight >= 30:
            return "medium"
        return "low"


def info(layer: str, code: str, title: str, description: str, **data: Any) -> Signal:
    """A neutral observation: shown as context, never adds risk."""
    return Signal(layer, code, title, description, 0, source_kind="observed", data=data)
