# Saarthi — AI-assisted Well-being Monitoring

An SIH prototype for a continuous, privacy-aware victim well-being monitoring module that can conceptually complement NHAA workflows.

## What works in this prototype

- Separate sign-in and sign-up pages with victim, counsellor, officer, and admin role boundaries
- Protected victim dashboard: private chat check-ins, safe contact preferences, phone number capture for IVRS calls, and scheduled SMS/IVRS reminders
- Officer dashboard with priority queue, case trend chart, and aggregate district view
- Case registration with consent acknowledgement and channel/language/frequency settings
- Simulated chatbot, SMS and IVRS check-ins
- Explainable, configurable rule-based distress signal analysis (no external AI key needed)
- Dynamic longitudinal score, trend detection, risk banding, and human-review alerts
- Human intervention logging and automatic follow-up scheduling
- Pseudonymous case aliases, masked contacts, audit-log data model, and prominent decision-support safeguards

## Run

```powershell
cd D:\94sih
.\.venv\Scripts\python.exe -m uvicorn app:app --reload
```

Open `http://127.0.0.1:8000`.

Start at `http://127.0.0.1:8000/signin`. Seeded demo accounts are shown on that page.

The demo uses SQLite (`saarthi.db`), created automatically on first launch. Delete only that database file if you intentionally want a fresh demo dataset.

## Deployment hardening checklist

The application already uses PBKDF2 password hashing, signed HTTP-only sessions, role-checked APIs, consent-aware contact preferences, audit logging, masked display data, and explainable risk signals. Before a real deployment, set `SAARTHI_AUTH_SECRET` to a managed secret and enable secure cookies behind HTTPS. Add CSRF protection, rate limiting, MFA/approved identity verification, provider webhooks, encrypted PII fields, a managed database, SIEM/audit retention, backups, monitoring, accessibility testing, penetration testing, and a formal clinical/governance review.

## Prototype boundaries

This is not a clinical diagnostic, emergency-response service, or production government integration. A real deployment needs authorised NHAA/ICJS APIs, formal consent and retention policy, role-based authentication, encryption/key management, clinical validation, accessibility reviews, and approved telecom/SMS providers.
