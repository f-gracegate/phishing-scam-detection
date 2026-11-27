"""SSRF-safe fetching of untrusted websites.

This module runs inside the isolated fetcher service and deliberately imports nothing from the
rest of the application (no database, no secrets).

Protections, per hop:

1. Only http/https on ports 80, 443, 8080 and 8443.
2. The hostname is resolved once; every resolved address must be globally routable (no
   loopback, private, link-local, CGNAT, multicast, reserved or cloud-metadata addresses).
3. The connection goes to that exact validated IP, with the hostname sent as Host and TLS SNI,
   so a second DNS answer (DNS rebinding) can't redirect it.
4. Redirects are followed manually; each target goes through the same checks.
5. Hard limits on redirects, time and bytes read. No cookies, no JavaScript, no downloads kept.
"""

import ipaddress
import os
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

USER_AGENT = (
    "Mozilla/5.0 (compatible; GraceGatePhishingScanner/1.0; +https://gracegate.example/scanner)"
)
ALLOWED_PORTS = {80, 443, 8080, 8443}
_METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}


class UnsafeTarget(Exception):
    pass


def _allow_private() -> bool:
    return os.environ.get("ALLOW_PRIVATE_FETCH_TARGETS", "false").lower() == "true"


def is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.sixtofour:
            ip = ip.sixtofour
    if _allow_private():
        return not (ip.is_unspecified or ip.is_multicast)
    return ip.is_global and not ip.is_multicast


def resolve_public(host: str, port: int) -> str:
    if host.lower().rstrip(".") in _METADATA_HOSTS:
        raise UnsafeTarget("Blocked internal address")
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        raise LookupError(f"{host} could not be found (no DNS record)") from exc
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise LookupError(f"{host} could not be found (no DNS record)")
    for addr in addresses:
        if not is_public_ip(addr):
            raise UnsafeTarget(f"{host} points to a private or reserved address")
    return addresses[0]


@dataclass
class Hop:
    url: str
    status: int
    location: str | None
    peer_ip: str
    elapsed_ms: int


@dataclass
class Certificate:
    subject: str
    issuer: str
    not_before: str
    not_after: str
    sans: list[str]
    self_signed: bool


@dataclass
class TLSInfo:
    trusted: bool
    error: str | None = None
    protocol: str | None = None
    certificate: Certificate | None = None


@dataclass
class FetchOutcome:
    requested_url: str
    ok: bool = False
    final_url: str | None = None
    status: int | None = None
    content_type: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_bytes: int = 0
    truncated: bool = False
    hops: list[Hop] = field(default_factory=list)
    tls: TLSInfo | None = None
    error: str | None = None
    unsafe: bool = False
    download: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


_KEEP_HEADERS = {
    "content-type",
    "server",
    "location",
    "refresh",
    "content-disposition",
    "x-powered-by",
    "content-security-policy",
    "strict-transport-security",
    "set-cookie",
}


def _charset(content_type: str | None, raw: bytes) -> str:
    if content_type and "charset=" in content_type.lower():
        return content_type.lower().split("charset=")[-1].split(";")[0].strip() or "utf-8"
    head = raw[:2048].lower()
    marker = head.find(b"charset=")
    if marker != -1:
        value = head[marker + 8 : marker + 40].strip(b"\"' ").split(b'"')[0].split(b";")[0]
        value = value.split(b">")[0].split(b" ")[0].strip(b"\"'/")
        if value:
            return value.decode("ascii", "ignore") or "utf-8"
    return "utf-8"


def _one_request(url: str, timeout: float, max_bytes: int):
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise UnsafeTarget("Only http and https links can be fetched")
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise UnsafeTarget(f"Port {port} is not allowed")
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None:
        if not is_public_ip(str(literal)):
            raise UnsafeTarget("Link points to a private or reserved address")
        ip = str(literal)
    else:
        ip = resolve_public(host, port)
    ip_host = f"[{ip}]" if ":" in ip else ip
    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"
    target = f"{parts.scheme}://{ip_host}:{port}{path}"
    host_header = host if port in {80, 443} else f"{host}:{port}"
    extensions = {"sni_hostname": host} if parts.scheme == "https" else {}
    started = time.monotonic()
    # Certificate trust is checked separately (probe_tls), so verification is off here.
    client = httpx.Client(timeout=httpx.Timeout(timeout), follow_redirects=False, verify=False)  # noqa: S501
    with client as c:
        # Certificate trust is checked separately (probe_tls); here we still want to see the
        # page a victim would see after clicking through a warning.
        with c.stream(
            "GET",
            target,
            headers={
                "Host": host_header,
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-GB,en;q=0.8",
            },
            extensions=extensions,
        ) as resp:
            chunks, read, truncated = [], 0, False
            ctype = resp.headers.get("content-type", "")
            disposition = resp.headers.get("content-disposition", "")
            textual = (not ctype) or any(
                t in ctype for t in ("text", "html", "xml", "json", "javascript")
            )
            download = "attachment" in disposition.lower() or not textual
            if not download and resp.status_code not in {301, 302, 303, 307, 308}:
                for chunk in resp.iter_bytes():
                    chunks.append(chunk)
                    read += len(chunk)
                    if read >= max_bytes:
                        truncated = True
                        break
                    if time.monotonic() - started > timeout:
                        truncated = True
                        break
            raw = b"".join(chunks)[:max_bytes]
            elapsed = int((time.monotonic() - started) * 1000)
            headers = {
                k.lower(): v[:500] for k, v in resp.headers.items() if k.lower() in _KEEP_HEADERS
            }
            return resp.status_code, headers, raw, truncated, ip, elapsed, download


def fetch(
    url: str, *, timeout: float = 10.0, max_redirects: int = 5, max_bytes: int = 1_000_000
) -> FetchOutcome:
    outcome = FetchOutcome(requested_url=url)
    current = url
    deadline = time.monotonic() + timeout * 2
    try:
        for _ in range(max_redirects + 1):
            if time.monotonic() > deadline:
                outcome.error = "The website took too long to respond"
                return outcome
            status, headers, raw, truncated, ip, elapsed, download = _one_request(
                current, timeout, max_bytes
            )
            location = headers.get("location")
            outcome.hops.append(Hop(current, status, location, ip, elapsed))
            if status in {301, 302, 303, 307, 308} and location:
                current = urljoin(current, location)
                continue
            outcome.ok = True
            outcome.final_url = current
            outcome.status = status
            outcome.headers = headers
            outcome.content_type = headers.get("content-type")
            outcome.download = download
            outcome.body_bytes = len(raw)
            outcome.truncated = truncated
            outcome.body = raw.decode(_charset(outcome.content_type, raw), "replace")
            if urlsplit(current).scheme == "https":
                outcome.tls = probe_tls(urlsplit(current).hostname or "", ip, timeout)
            return outcome
        outcome.error = f"More than {max_redirects} redirects"
        outcome.final_url = current
        return outcome
    except UnsafeTarget as exc:
        outcome.unsafe = True
        outcome.error = str(exc)
    except LookupError as exc:
        outcome.error = str(exc)
    except httpx.TimeoutException:
        outcome.error = "The website took too long to respond"
    except httpx.HTTPError as exc:
        outcome.error = _connect_reason(exc)
    except (OSError, ssl.SSLError) as exc:
        outcome.error = f"Could not connect ({type(exc).__name__})"
    return outcome


def _connect_reason(exc: Exception) -> str:
    text = str(exc).lower()
    if "refused" in text:
        return "The website refused the connection"
    if "ssl" in text or "tls" in text or "certificate" in text:
        return "Secure connection failed"
    return "Could not connect to the website"


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME) or name.get_attributes_for_oid(
        NameOID.ORGANIZATION_NAME
    )
    return str(attrs[0].value) if attrs else name.rfc4514_string()


def parse_certificate(der: bytes) -> Certificate:
    cert = x509.load_der_x509_certificate(der)
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = list(ext.value.get_values_for_type(x509.DNSName))[:20]
    except x509.ExtensionNotFound:
        sans = []
    return Certificate(
        subject=_cn(cert.subject),
        issuer=_cn(cert.issuer),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        sans=sans,
        self_signed=cert.issuer == cert.subject,
    )


def probe_tls(host: str, ip: str, timeout: float) -> TLSInfo:
    """Check the certificate a browser would see, connecting to the already-validated IP."""
    trust_error: str | None = None
    for verify in (True, False):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
                    return TLSInfo(
                        trusted=verify,
                        error=trust_error,
                        protocol=tls.version(),
                        certificate=parse_certificate(der) if der else None,
                    )
        except ssl.SSLCertVerificationError as exc:
            trust_error = (exc.verify_message or "Certificate not trusted")[:200]
            continue
        except (OSError, ssl.SSLError) as exc:
            return TLSInfo(trusted=False, error=f"TLS handshake failed ({type(exc).__name__})")
    return TLSInfo(trusted=False, error=trust_error)


def now_iso() -> str:
    return datetime.now(UTC).isoformat()
