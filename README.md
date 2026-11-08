# Vigilante Core

Vigilante Core is an open-source, self-hostable security operations foundation. It pairs a small FastAPI backend with an analyst-focused web console for reviewing alerts and managing investigations.

## What’s included

- Authenticated webhook ingestion with idempotency and payload-size limits
- Deterministic baseline triage and severity scoring (rules-based, not an ML model)
- Alert review, severity overrides, case management, and audit events through the API
- Responsive SOC console with alert search and filters, severity overview, alert details, and case creation
- Synthetic demo workspace for trying the interface without a backend or real telemetry
- GitHub Pages deployment for the static console; Docker Compose deployment for the API and database

> **Demo and operational scope:** the dashboard opens with clearly labeled synthetic examples. GitHub Pages hosts only the static UI; it does not run the API, ingest telemetry, or store alert data. The bundled triage is a deterministic reference implementation and is not a substitute for validated detections, analyst review, or an incident-response program.

## Try the hosted console

The Pages workflow publishes the static interface at:

**https://saadcyber21.github.io/vigilante-core/**

The console starts in demo mode. To connect it to a self-hosted API, deploy the backend separately, expose it over HTTPS, and set `CORS_ORIGINS=https://saadcyber21.github.io` on the API server. In the console, choose **Connect API** and enter the API URL and an existing analyst account. The page keeps the access token in memory only; never put API keys or webhook secrets in the static site.

## Run locally

Python 3.12 or newer is required.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
# Change ADMIN_PASSWORD, JWT_SECRET, and WEBHOOK_SECRET in .env.
uvicorn app.main:app --reload
```

Open <http://localhost:8000>. The same console is served from the FastAPI app; the default display is synthetic demo data. To connect to the local API, enter `http://localhost:8000` in the connection dialog.

The development administrator is configured through `ADMIN_USERNAME` and `ADMIN_PASSWORD`. Replace both values before deployment.

## Webhook ingestion

```bash
curl -X POST http://localhost:8000/api/v1/ingest/webhooks/identity \
  -H 'Content-Type: application/json' \
  -H 'X-Webhook-Secret: replace-with-a-source-specific-secret' \
  -d '{"payload":{"event_type":"authentication","message":"multiple failed login attempts"},"idempotency_key":"event-001"}'
```

## Tests

```bash
pip install -e '.[test]'
pytest
node --check docs/static/app.js
```

## Deployment

- **Static console:** GitHub Actions deploys `docs/` to GitHub Pages on pushes to `main` that change the dashboard or Pages workflow. See [DEPLOYMENT.md](DEPLOYMENT.md).
- **API and database:** use Docker Compose on a secured Linux host behind TLS. GitHub Pages is not a backend host.

For production, configure PostgreSQL through `DATABASE_URL`, place the API behind TLS, use a high-entropy `JWT_SECRET`, replace the development webhook secret, and review role and tenant isolation for your deployment. Raw payloads are stored as JSON in this compact reference implementation; production deployments should move immutable raw evidence to access-controlled object storage as specified by the architecture.
