"""External threat-intelligence providers. Each is off until configured with its own licence.

Licensing matters: Google's free Safe Browsing API is for non-commercial use only, so this
product uses Google Web Risk (the commercial service). Check each provider's terms before
enabling it, and record the licence on its intelligence source.

Privacy: only ``ParsedURL.lookup_url`` is sent (secrets stripped), and only when the person
allowed external lookups for the scan.
"""

import logging
from dataclasses import dataclass

import httpx

from app.core.config import settings
from app.detection.signals import Signal
from app.detection.urls import ParsedURL

log = logging.getLogger(__name__)


@dataclass
class ProviderResult:
    provider: str
    matched: bool
    threat: str | None = None
    error: str | None = None


class Provider:
    code = "provider"
    name = "Provider"

    def enabled(self) -> bool:
        return False

    def check(self, url: ParsedURL) -> ProviderResult:
        raise NotImplementedError


class GoogleWebRisk(Provider):
    code = "google_web_risk"
    name = "Google Web Risk"

    def enabled(self) -> bool:
        return bool(settings.google_web_risk_api_key)

    def check(self, url: ParsedURL) -> ProviderResult:
        resp = httpx.get(
            "https://webrisk.googleapis.com/v1/uris:search",
            params=[
                ("uri", url.lookup_url),
                ("threatTypes", "MALWARE"),
                ("threatTypes", "SOCIAL_ENGINEERING"),
                ("threatTypes", "UNWANTED_SOFTWARE"),
                ("key", settings.google_web_risk_api_key),
            ],
            timeout=5,
        )
        resp.raise_for_status()
        threat = resp.json().get("threat")
        if threat:
            return ProviderResult(self.code, True, ", ".join(threat.get("threatTypes", [])))
        return ProviderResult(self.code, False)


class URLhaus(Provider):
    code = "urlhaus"
    name = "URLhaus (abuse.ch)"

    def enabled(self) -> bool:
        return bool(settings.urlhaus_auth_key)

    def check(self, url: ParsedURL) -> ProviderResult:
        resp = httpx.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url.lookup_url},
            headers={"Auth-Key": settings.urlhaus_auth_key},
            timeout=5,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("query_status") == "ok":
            return ProviderResult(self.code, True, body.get("threat") or "malware_download")
        return ProviderResult(self.code, False)


PROVIDERS: list[Provider] = [GoogleWebRisk(), URLhaus()]


def check_url(url: ParsedURL, enabled_codes: set[str]) -> tuple[list[Signal], list[dict]]:
    signals: list[Signal] = []
    checked: list[dict] = []
    for provider in PROVIDERS:
        if not provider.enabled() or provider.code not in enabled_codes:
            continue
        try:
            result = provider.check(url)
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("intel provider %s failed: %s", provider.code, type(exc).__name__)
            checked.append({"provider": provider.name, "status": "unavailable"})
            continue
        checked.append(
            {"provider": provider.name, "status": "match" if result.matched else "no_match"}
        )
        if result.matched:
            signals.append(
                Signal(
                    "reputation",
                    "external_match",
                    f"Flagged by {provider.name}",
                    f"{provider.name} lists this link as a threat ({result.threat}).",
                    88,
                    source_kind="external_provider",
                    source_name=provider.name,
                    reliability="high",
                    category="malware" if "MALWARE" in (result.threat or "") else None,
                    data={"provider": provider.code, "threat": result.threat},
                )
            )
    return signals, checked
