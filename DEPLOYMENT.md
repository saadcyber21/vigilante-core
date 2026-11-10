# Deployment guide

This guide deploys the self-hosted Vigilante Core MVP on a Linux host using Docker Compose. The static console may be served by the API or opened from GitHub Pages; the API and database are always deployed separately.

## Requirements

- Linux host with Docker Engine and Docker Compose plugin
- DNS name pointing to the host
- Firewall allowing SSH and HTTPS to a TLS reverse proxy
- Off-host backup location

## Prepare secrets and start

```bash
git clone https://github.com/saadcyber21/vigilante-core.git
cd vigilante-core
cp .env.example .env
```

Edit `.env` before startup. Replace `POSTGRES_PASSWORD`, `JWT_SECRET`, `ADMIN_PASSWORD`, and `WEBHOOK_SECRET` with unique secrets. Generate random secret material locally (for example, `openssl rand -hex 32`) and keep it private. Use an administrator password of at least 16 characters. Set a unique deployment `TENANT_ID` and the exact `CORS_ORIGINS` value for your console. Never commit `.env` or put API secrets in GitHub Pages.

Start and check the services:

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 vigilante
curl http://127.0.0.1:8000/api/v1/health/live
curl http://127.0.0.1:8000/api/v1/health/ready
```

The API is bound to localhost on port 8000 by default. PostgreSQL is not published to the host. The first application start provisions the configured administrator. The interactive API reference is available at `/docs` after deployment.

## HTTPS reverse proxy

Configure your reverse proxy to terminate TLS and forward requests to `http://127.0.0.1:8000`. Pass the `Authorization`, `Content-Type`, and `X-Webhook-Secret` headers. Redirect HTTP to HTTPS after certificate issuance. Expose only the reverse proxy’s HTTPS listener publicly; do not expose the API or PostgreSQL ports directly.

For the hosted console at `https://vigilante-core.github.io/`, set:

```dotenv
CORS_ORIGINS=https://vigilante-core.github.io
```

CORS accepts origins, not paths. If you serve the UI from your own API host, use that origin instead. After the API is reachable over HTTPS, open the hosted console and select **Connect API**. The static site has no access to API credentials until a user submits the login form; its short-lived bearer token is kept in memory only.

## Webhook ingestion

Send normalized JSON events to `/api/v1/ingest/webhooks/{source_key}` and include the configured `X-Webhook-Secret`. Use an idempotency key supplied by the source when available. Prefer unique credentials per integration by configuring `WEBHOOK_SOURCE_SECRETS` with a JSON object, for example:

```dotenv
WEBHOOK_SOURCE_SECRETS={"identity":"<random-secret>","endpoint":"<different-random-secret>"}
```

When this mapping is present, only listed source keys are accepted. Secrets belong in the backend environment, not client-side code or webhook URLs.

## Configuration reference

| Variable | Purpose |
| --- | --- |
| `APP_NAME` | Display name for the service |
| `ENVIRONMENT` | Use `production` for deployment-time secret validation |
| `TENANT_ID` | Fixed organization/deployment identifier; clients cannot choose it |
| `DATABASE_URL` | Internal SQLAlchemy URL; Compose constructs a PostgreSQL URL |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | PostgreSQL database and login |
| `JWT_SECRET` | HMAC signing secret for API access tokens |
| `JWT_EXPIRE_MINUTES` | Token lifetime, 5–1440 minutes |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Initial administrator created at first startup |
| `WEBHOOK_SECRET` | Shared fallback webhook credential |
| `WEBHOOK_SOURCE_SECRETS` | Optional JSON mapping of per-source webhook credentials |
| `MAX_PAYLOAD_BYTES` | Maximum accepted normalized payload size |
| `CORS_ORIGINS` | Comma-separated exact browser origins |
| `PORT` | Host-local API port, default 8000 |
| `LLM_ENABLED` | Currently disabled; baseline triage is deterministic rules, not an LLM |

The production settings validator refuses short or obvious placeholder secrets. It is a useful guardrail, not a secrets manager.

## Persistent data and backups

PostgreSQL data is stored in the named `vigilante-postgres` Docker volume. `docker compose down` keeps this volume; `docker compose down -v` deletes it. Do not use `-v` unless intentional destruction of all database contents is desired.

Create an encrypted, off-host logical backup:

```bash
mkdir -p backups
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' \
  > "backups/vigilante-$(date -u +%Y%m%dT%H%M%SZ).sql"
```

Protect backup files as sensitive security data, copy them away from the server, retain multiple dated versions, and periodically test restoration. For example, restore into a stopped/test deployment with:

```bash
cat backups/vigilante-backup.sql | docker compose exec -T postgres \
  sh -c 'psql -U "$POSTGRES_USER" "$POSTGRES_DB"'
```

For a restore, use a clean/test database and confirm the target before importing; do not overwrite valuable live data inadvertently.

## Updates and schema changes

Back up before every update. Pull the desired revision and rebuild:

```bash
git pull
docker compose up -d --build
docker compose logs --tail=100 vigilante
```

Check both health endpoints, sign in, confirm the dashboard and alert/case lists, and verify that backups still work. The current MVP creates tables on startup and does not yet ship a schema migration framework. Review each release’s schema changes; older SQLite databases are not automatically migrated to PostgreSQL.

## Operational checks

```bash
docker compose ps
docker compose logs --tail=200 vigilante
docker compose logs --tail=100 postgres
docker stats
curl https://your-api-host.example/api/v1/health/ready
```

Monitor host disk, Docker volume use, reverse-proxy certificate renewal, failed logins, and backup freshness. Restrict administrator access, rotate secrets after exposure, and review audit events. This MVP does not provide high availability, outsourced monitoring, automatic threat-hunting, or automatic containment.

## Scope and trust boundary

GitHub Pages hosts only static HTML, CSS, and JavaScript. It does not host the API, database, authentication service, or webhook receiver. One backend installation is one organization boundary; do not share its database across unrelated customers. Response proposals and approvals are auditable records only, and no approved action is executed automatically. Validate all detections and response plans with qualified staff.
