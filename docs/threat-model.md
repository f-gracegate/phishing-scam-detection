# Threat model

The platform processes untrusted URLs, websites, emails, messages and files, so the scanner
itself is a target.

| Threat | Impact | Control in the code |
| --- | --- | --- |
| SSRF via submitted links | Scanner reaches internal services or cloud metadata | Isolated fetcher (`app/fetcher/`) on its own network with no DB/Redis credentials; resolves once and pins the validated IP (no DNS rebinding); refuses loopback, private, link-local, CGNAT, reserved, multicast and metadata hosts; validates every redirect hop; ports 80/443/8080/8443 only; time, size and redirect limits. Tests: `tests/test_fetcher.py` |
| Malicious web content | Scanner compromise | No JavaScript execution, no cookies, no downloads kept; body parsed as text. Headless sandbox is future work and must run disposable and network-restricted |
| Malicious attachments | Malware execution | Attachments are never opened; only name, type and size are read |
| Webhook SSRF | Customer webhook points inside | Same address validation; https outside development |
| XSS / HTML injection | Account compromise | React escaping, no `dangerouslySetInnerHTML`, CSP-friendly headers, `nosniff` on downloads |
| Cross-tenant / employer access | Disclosure of private scans | PostgreSQL RLS forced on scans, evidence, feedback, reports, cases, keys, webhooks; personal rows visible only to their owner. Tests: `tests/test_tenancy.py` |
| Intelligence poisoning, fake reports | False alerts, reputational harm | Reports create only unverified indicators; verification needs an analyst with publish rights and written evidence; history is append-only; expiry and revocation |
| API abuse and cost escalation | Outage, provider costs | Per-key and per-person rate limits, daily/monthly quotas, bulk limit 100, external lookups metered by plan |
| Credential theft | Account takeover | Argon2id, MFA, lockout, short sessions, rotating refresh tokens, hashed API keys shown once |
| Prompt injection (future AI) | Wrong explanations | Detection doesn't depend on AI; any AI output must be labelled and never treated as a verified finding |
| Privacy leakage | Exposure of private messages | Redaction, Fernet encryption, retention purge, masked phones, audited phone reveal, no message content in public warnings |

Residual risks / to do: headless-browser sandbox, host-level egress firewall for the fetcher
(block 169.254.169.254 and private ranges as a second layer), independent penetration test.
