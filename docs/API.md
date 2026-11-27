# API

Base path `/api/v1`. Interactive docs at `/api/docs` in development. JSON errors:
`{"error": {"code", "message", "details?"}, "request_id"}`.

## Authentication

| Caller | How | Scope |
| --- | --- | --- |
| Web app | httpOnly cookies + `X-CSRF-Token` | Personal space, or a workspace with `X-Organisation-Id` |
| Mobile app | `Authorization: Bearer <access token>` (`client: "mobile"` at login) | Same |
| Business API | `Authorization: Bearer psk_…` (Business → API & usage) | The key's organisation |
| Browser extension | `Authorization: Bearer pse_…` (Settings → Browser extension) | The person's private history |

## Scans

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/scans/url` | `{url, scan_options, privacy: {allow_external_intelligence_lookup}}` |
| POST | `/scans/message` | `{text, sender?, channel, check_links}` |
| POST | `/scans/email` | `{raw}` (full source or pasted text) |
| POST | `/scans/email/file` | multipart `.eml` |
| POST | `/scans/qr` | `{payload}` — decoded on the device |
| POST | `/scans/bulk` | business only, up to 100 items → `batch_id` |
| GET | `/scans/batches/{id}` | batch progress |
| GET | `/scans` | history (`kind`, `verdict`, `q`, `mine`, `page`) |
| GET | `/scans/{id}`, `/scans/{id}/evidence` | result and evidence |
| POST | `/scans/{id}/feedback` | `false_positive` / `false_negative` / `correct` |
| POST | `/scans/{id}/rescan` | links only |
| DELETE | `/scans/{id}`, `/scans` | delete one / clear personal history |
| GET | `/scans/quota`, `/scans/reputation?domain=` | allowance; verified-intel domain check (nothing stored) |

Scans are queued and return `status: "queued"`; poll `GET /scans/{id}` or add `?wait=true`
(waits up to 20 s). Example response fields: `verdict`, `risk_score`, `confidence`, `headline`,
`summary`, `recommendations`, `evidence[]` (each with `source_kind`, `source_label`,
`reliability`, `observed_at`), `artifacts`.

## Reports, business, intelligence, account

- Reports: `POST /reports` (header `Idempotency-Key`), `POST /reports/{id}/evidence`,
  `GET /reports`, `GET /reports/{id}`.
- Business: `/business/analytics`, `/business/report.pdf`, `/business/cases[/{id}[/notes]]`,
  `/business/api-keys`, `/business/usage`, `/business/webhooks[/{id}/test]`, `/business/brands`.
- Intelligence (platform staff): `/intelligence/overview`, `/indicators[/{id}[/review]]`,
  `/reports[/{id}/review]`, `/feedback[/{id}/resolve]`, `/campaigns`, `/sources`, `/brands`, `/staff`.
- Account: `/notifications`, `/me/plan`, `/me/extension-tokens`, `/me/export`,
  `/me/delete-account`, `/public/warnings`.
- Foundation: `/auth/*`, `/organisations/*`, `/billing/*`, `/me/push-devices`, `/audit-logs`.

## Webhooks

Events: `scan.completed`, `scan.high_risk`, `case.created`, `case.closed`,
`report.status_changed`. Header `X-PSD-Signature: t=<unix>,v1=<hex>` where the digest is
HMAC-SHA256 of `"<t>." + body` with the endpoint secret. Retries with exponential backoff (6
attempts).
