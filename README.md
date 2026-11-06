# Vigilante AI

A self-hostable security operations platform providing:

- Authenticated webhook ingestion
- Syslog parsing endpoint
- Idempotent alert acceptance
- Deterministic AI-compatible triage and severity scoring
- Analyst severity overrides
- Case management
- Audit logging
- Analyst dashboard

## Run locally

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
uvicorn app.main:app --reload
```

Open http://localhost:8000.

The development administrator is configured through `ADMIN_USERNAME` and
`ADMIN_PASSWORD`. Change both values before deployment.

## Webhook ingestion

```bash
curl -X POST http://localhost:8000/api/v1/ingest/webhooks/identity \
  -H 'Content-Type: application/json' \
  -H 'X-Webhook-Secret: replace-with-a-source-specific-secret' \
  -d '{"payload":{"event_type":"authentication","message":"multiple failed login attempts"},"idempotency_key":"event-001"}'
```

## Tests

```bash
pytest
```

For production, configure PostgreSQL through `DATABASE_URL`, place the API
behind TLS, use a high-entropy `JWT_SECRET`, and replace the development
webhook secret. Raw payloads are stored as JSON in the transactional database
in this compact reference implementation; production deployments should move
immutable raw evidence to S3-compatible object storage as specified by the
architecture.
