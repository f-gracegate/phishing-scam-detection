# Detection and risk scoring

Code: `backend/app/detection/` (pure, unit-tested), `app/intelligence/`, `app/scanning/`.

## Layers

| Layer | Module | Examples |
| --- | --- | --- |
| Reputation | `intelligence/service.py`, `providers.py` | Verified indicators (URL, host, registrable domain, IP, phone, email); Google Web Risk / URLhaus when licensed and allowed |
| Domain | `detection/urls.py`, `intelligence/domains.py` | Brand keyword on a non-official domain, look-alikes (edit distance, homoglyphs, punycode), IP hosts, `@` tricks, shorteners, free hosting, risky TLDs, domain age (RDAP, optional) |
| Website | `detection/website.py` via the isolated fetcher | Fake sign-in/payment pages for a brand, forms posting elsewhere, password/PIN/OTP/card fields, cross-domain and scripted redirects, obfuscated code, APK downloads, untrusted or brand-new certificates |
| Message | `detection/text.py` | PIN/OTP requests, MoMo reversal and approve-prompt scams, threats, urgency, prizes, fees, delivery, jobs, investment, crypto/seed phrases, government payments, admission fees, emergencies, secrecy, sender-ID mismatch |
| Email | `detection/email_analysis.py` | Look-alike sender domains, display-name impersonation, free-mail senders, reply-to/return-path mismatch, SPF/DKIM/DMARC failures, link-text mismatch, risky attachments (never opened) |
| Community | indicators with reports | "Reported by N people (not verified)" — weak and clearly labelled |
| Positive | official brand domain | Caps the score unless verified/external intelligence disagrees |

## Score

0–100 assessment (not a probability). Signals combine with diminishing returns
(`1 − Π(1 − wᵢ)`), and repeated signals from the same layer count for less. A verified malicious
indicator sets a floor of 92; an external provider match 85.

| Score | Verdict |
| --- | --- |
| 90–100 | Critical |
| 70–89 | High |
| 40–69 | Suspicious |
| 20–39 | Caution |
| 0–19 | Low — **only** with positive evidence; otherwise **Unknown** |

Confidence (low/medium/high) is separate: high needs verified/external intelligence or several
strong signals across layers.

## Privacy in the pipeline

- Redaction before storage: one-time codes, PINs, passwords, card numbers (Luhn), and secret
  query parameters (`token`, `session`, `code`, …). Secret-bearing links are visited and looked
  up only in redacted form, so a one-time login link is never used on someone's behalf.
- External lookups are opt-out per scan and receive `lookup_url` (no secrets, no fragment).
- Phone numbers in indicators are stored as a hash plus a masked display value.

## Tuning

Add brands and domains in the analyst console (Sources & brands). Rules live in `RULES` in
`text.py`; each has a weight and a plain-language explanation. False-positive feedback lands in
the "Disputed results" queue. Measure precision and recall on a labelled Ghanaian dataset before
changing weights.
