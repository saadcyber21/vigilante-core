# Vigilante Core

Vigilante Core is an open-source, defensive security operations MVP. It combines a static analyst console with a self-hosted FastAPI service and PostgreSQL database. The hosted website is a demo until you deploy and connect your own API.

## Product today

- **Alert ingestion:** authenticated source webhooks, payload size limits, idempotency, deterministic baseline severity scoring, and evidence summaries.
- **Triage:** searchable/filterable alerts; analysts can record status changes with a reason.
- **Cases:** create cases from alerts and update case status.
- **Accounts:** initial administrator provisioning and administrator-managed analyst, manager, auditor, and security-admin accounts.
- **Audit:** successful and failed sign-ins, alert and case changes, and response-proposal decisions are recorded.
- **Response workflow:** analysts can propose a bounded defensive action; a different manager or security administrator can approve or reject it. Approval records a decision only—Vigilante does not execute commands or call response integrations.
- **Deployment:** Docker Compose runs the API and PostgreSQL. The console can be served by the API or hosted separately on GitHub Pages.

Triage is a deterministic reference ruleset, not an AI/ML model. This is a single-deployment MVP, not a multi-tenant SaaS service or an enterprise SIEM replacement. It does not autonomously hunt, attack, contain, disable accounts, or generate bug-bounty revenue. Review detections and actions with qualified staff before operational use.

## Hosted console

**https://vigilante-core.github.io/**

The console starts in synthetic demo mode; it does not connect to live data by itself. To use real alerts and cases, deploy the backend below, expose it through HTTPS, configure its `CORS_ORIGINS` to include `https://vigilante-core.github.io`, then select **Connect API** and sign in with an API account. The access token is kept in browser memory only. Never put passwords, JWT keys, or webhook secrets in the static Pages repository.

## Run the self-hosted MVP

Requirements: Docker Engine and the Docker Compose plugin.

```bash
git clone https://github.com/saadcyber21/vigilante-core.git
cd vigilante-core
cp .env.example .env
```

Edit `.env` and replace the example values for `POSTGRES_PASSWORD`, `JWT_SECRET`, `ADMIN_PASSWORD`, and `WEBHOOK_SECRET` with unique random secrets. For example, generate random values locally with `openssl rand -hex 32`; keep the output private and do not commit `.env`. Use a strong administrator password of at least 16 characters. Set `CORS_ORIGINS` to the exact console origin you use, and set a unique `TENANT_ID` for this deployment.

Start the stack:

```bash
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:8000/api/v1/health/ready
```

The API listens on `127.0.0.1:8000` by default. Put a TLS reverse proxy in front of it before connecting from a browser or exposing it beyond the host. The first start creates the administrator named by `ADMIN_USERNAME` and `ADMIN_PASSWORD`. The interactive API reference is at `https://your-api-host/docs` when deployed behind HTTPS.

For local development without Docker:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
uvicorn app.main:app --reload
```

The development server uses a local SQLite file by default and serves the same console at <http://localhost:8000>. Do not use development defaults for a production deployment.

## Send a test event

Once the API is running, replace the webhook secret below with the configured secret and send a normalized event:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest/webhooks/identity \
  -H 'Content-Type: application/json' \
  -H 'X-Webhook-Secret: replace-with-your-source-secret' \
  -d '{"payload":{"event_type":"authentication","message":"multiple failed login attempts"},"idempotency_key":"event-001"}'
```

For separate per-source credentials, configure `WEBHOOK_SOURCE_SECRETS` as a JSON object; when present, only listed source keys are accepted. Never include a webhook secret in frontend JavaScript.

## Verify changes

```bash
pip install -e '.[test]'
pytest
node --check docs/static/app.js
```

CI runs the backend tests and checks dashboard JavaScript syntax. Docker is not required to run the Python tests.

## Important MVP boundaries

- One API deployment is one organization boundary. Do not put multiple customers into one shared database; `TENANT_ID` is a deployment setting, not SaaS-grade tenant isolation.
- TLS, host firewalls, backups, monitoring, and secret rotation are the operator’s responsibility.
- Existing legacy SQLite data is not automatically migrated to PostgreSQL. Back up and plan any migration before upgrading an existing deployment.
- The application currently uses SQLAlchemy table creation, not a production migration framework. Back up before upgrades and review schema changes.
- The service is not independently security-certified, high-availability, or a replacement for a staffed incident-response program.

See [DEPLOYMENT.md](DEPLOYMENT.md) for TLS, backup, and operational instructions, and [SECURITY.md](SECURITY.md) for responsible vulnerability reporting.
