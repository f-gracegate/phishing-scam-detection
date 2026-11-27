# Phishing and Scam Detection

Ghana-first platform that checks suspicious **links, websites, emails, SMS, WhatsApp messages
and QR codes** and explains the result: the risk first, the evidence second, what to do next
third. For individuals (private, freemium), businesses (dashboards, investigations, bulk checks)
and enterprises (API, webhooks).

Powered by **GraceGate Technologies**. Brand name: undecided (`BRAND_PRODUCT_NAME`).

| Part | Stack | Folder |
| --- | --- | --- |
| API and detection engine | Python 3.15, FastAPI, SQLAlchemy, PostgreSQL (RLS), Redis | `backend/` |
| Isolated website fetcher | Same image, separate container, no database access | `backend/app/fetcher/` |
| Web app (consumer, business, analyst console) | Next.js 16, React 19, Tailwind 4 | `apps/web/` |
| Browser extension | TypeScript, Manifest V3 | `apps/browser-extension/` |
| Mobile apps | Flutter | *not started* |

## Run it locally

```bash
docker compose up --build
```

- Web: http://localhost:3820, API: http://localhost:8200/api/docs
- Sign in as `Admin` / `password` (development seed only; you must change it at first sign-in).
- The demo seeds a business workspace and clearly fake threats on reserved domains. Try checking
  `http://mtn-momo-reversal.example/verify` or a message like *"MTN MoMo: GHS 450 was sent to
  you by mistake, dial \*170# and enter your PIN to reverse it"*.

Tests:

```bash
docker compose run --rm -T backend pytest -q
```

```bash
cd apps/browser-extension && npm ci && npm test
```

Load the extension: `npm run build`, then `chrome://extensions` → Developer mode → Load
unpacked → `apps/browser-extension/dist`.

## Docs

- [Product status and what's left](docs/PRD.md)
- [Detection and risk scoring](docs/detection.md)
- [Threat model](docs/threat-model.md)
- [API](docs/API.md)
- [Security](docs/security.md), [Deployment](docs/deployment.md), [Operations](docs/operations.md)

Fonts: Poppins (text) and Montserrat (headings) only, across web, extension and PDFs.
