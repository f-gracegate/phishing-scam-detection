# Project 02 — Phishing and Scam Detection Platform

Ghana-first platform that helps individuals and organisations judge suspicious links, websites,
emails, SMS, WhatsApp messages and QR codes **before** they become financial or security
incidents. Product promise: *show the risk first, explain the evidence second, and give the next
action third.* Brand: undecided (working name "Phishing and Scam Detection"; set
`BRAND_PRODUCT_NAME`). Powered by GraceGate Technologies.

The full product definition (vision, scenarios, UX, architecture, data model, API, risk engine,
security, legal, roadmap and commercial strategy) was supplied by the product owner on
27 November 2026. This file records what is built and what is left.

## Principles the code enforces

- **Unknown is not safe.** Without positive evidence, a quiet result is "Unknown — insufficient
  evidence", never green.
- **Evidence has provenance.** Every reason shows whether it came from our rules, verified
  intelligence, an external provider, unverified community reports or an observation, with
  its reliability and time.
- **Reports are not accusations.** Community reports stay unverified until an analyst reviews
  them; phone numbers are encrypted and masked; nothing private is published.
- **Personal history is private.** An employer never sees a person's personal scans.
- **Untrusted content stays contained.** Websites are visited by an isolated fetcher with no
  database access and per-hop SSRF checks; attachments are never opened.

## Status (27 Nov 2026)

| Roadmap phase | Status |
| --- | --- |
| 1. Platform foundation (auth, MFA, consumer + organisation accounts, roles, audit) | ✅ Built |
| 2. URL and domain detection, risk engine, scan results and history | ✅ Built |
| 3. Website analysis (isolated fetcher, login forms, impersonation, redirects) | ✅ Built (static HTML analysis) |
| 4. Message and email analysis, Ghana rules, extraction, attachments | ✅ Built (English) |
| 5. Threat intelligence, community reporting, analyst console, expiry, false positives | ✅ Built |
| 6. Business dashboards, cases, bulk scans, API keys, usage, webhooks, subscriptions | ✅ Built |
| 7. Browser extension | ✅ Built (Chrome/Edge MV3) |
| 7. Flutter Android/iOS apps: check, QR camera, history, reports, push, app lock, Android share-to-scan | ✅ Built |
| 7. iOS share extension and iOS SMS filter extension | ⏳ Not started |
| 8. Security testing, privacy assessment, accuracy evaluation, pilot, launch | ⏳ Not started |

## Left to do

Engineering:
- iOS native extensions: a Share Extension (share a link or message into the app; Android
  already supports this) and the `ILMessageFilterExtension` (unknown SMS senders only — no
  iMessage/WhatsApp monitoring). Today iOS users paste with the clipboard button.
- Android SMS integration (needs Play Store policy review; not built).
- Firebase project and APNs key for push in store builds; store listings and signing.
- Disposable headless-browser sandbox for script-heavy pages (today: static HTML analysis).
- Server-side QR image decoding (today: decoded on the device; only the text is sent).
- Personal Plus checkout (Paystack MoMo) — business checkout works; personal plan is stored but
  can't be bought yet.
- Campaign correlation automation (indicator relationships are modelled, not auto-built).
- Ghanaian Pidgin and local-language rules, only after evaluating a labelled dataset.
- Optional AI explanation layer (pluggable, off by default, never shown as a verified finding).
- Enterprise email (Microsoft 365 / Google Workspace) and approved messaging integrations.
- Firefox/Safari extension packaging; store listings.
- Independent security review of the scanning code; load test of the scan pipeline.
- Labelled test set and precision/recall measurement (target ≥95% precision on high-confidence
  phishing before presenting high-risk as strongly established).

Owner tasks:
- Brand name. Analyst review of the seeded brand catalogue (official domains start unverified).
- Commercial licences before enabling providers: Google Web Risk (not the free Safe Browsing
  API), URLhaus, PhishTank, any RDAP/DNS data provider.
- Written CSA guidance on classification; DPC registration, privacy notice and DPA reviewed by
  a lawyer; NCA review before any telecom/carrier integration.
- Confirm public contact details shown in the app (e.g. CSA "call or text 292").
- Pilot: 100–200 consumers, 5–10 SMEs, 1–2 API pilots; hosting; Paystack live keys.
