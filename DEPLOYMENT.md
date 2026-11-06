# Deployment guide

This guide describes a small Linux VPS deployment using Docker Compose and a
reverse proxy that terminates HTTPS.

## Requirements

- A Linux host with Docker Engine and the Docker Compose plugin
- A DNS name pointing to the host
- Firewall access for SSH and the HTTPS port
- A backup destination with sufficient capacity

The application persists its SQLite database in the `vigilante-data` Docker
volume. The Compose configuration exposes the application on port `8000`;
place a reverse proxy in front of it rather than exposing that port publicly.

## Prepare the host

Clone the repository and enter the project directory:

```bash
git clone <repository-url> vigilante-core
cd vigilante-core
cp .env.example .env
```

Edit `.env` before starting the service. At minimum, replace:

- `JWT_SECRET`
- `ADMIN_PASSWORD`
- `WEBHOOK_SECRET`
- `CORS_ORIGINS`

Use long, randomly generated values for secrets. Do not commit `.env`.

## Start the application

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f vigilante
```

Verify the local health endpoints:

```bash
curl http://127.0.0.1:8000/api/v1/health/live
curl http://127.0.0.1:8000/api/v1/health/ready
```

The first application start creates the administrator configured by
`ADMIN_USERNAME` and `ADMIN_PASSWORD`.

## HTTPS reverse proxy

Configure the reverse proxy for the public hostname and forward requests to:

```text
http://127.0.0.1:8000
```

The proxy must support normal HTTP methods and pass the `Authorization` and
`X-Webhook-Secret` headers. Configure an HTTPS certificate with your proxy's
certificate automation. Redirect HTTP to HTTPS after certificate issuance.

Only expose the reverse proxy's HTTPS listener to the Internet. Restrict or
remove public access to port `8000` after confirming proxy connectivity.

## Configuration

The application reads environment variables from `.env`. Important values
include:

| Variable | Purpose |
| --- | --- |
| `APP_NAME` | Application title |
| `ENVIRONMENT` | Runtime environment label |
| `DATABASE_URL` | Database connection URL |
| `JWT_SECRET` | HMAC signing secret for access tokens |
| `JWT_EXPIRE_MINUTES` | Access-token lifetime |
| `ADMIN_USERNAME` | Initial administrator username |
| `ADMIN_PASSWORD` | Initial administrator password |
| `WEBHOOK_SECRET` | Secret used for webhook authentication |
| `MAX_PAYLOAD_BYTES` | Maximum accepted webhook payload size |
| `CORS_ORIGINS` | Comma-separated allowed browser origins |
| `LLM_ENABLED` | LLM configuration flag |
| `LLM_PROVIDER` | LLM provider label |
| `LLM_BASE_URL` | Optional LLM base URL |
| `LLM_API_KEY` | Optional LLM API key |
| `LLM_MODEL` | Optional LLM model name |

The included Compose file overrides `DATABASE_URL` to store the SQLite database
at `/data/vigilante.db` inside the named volume.

## Persistent storage

The `vigilante-data` volume contains the application database. Inspect the
volume with:

```bash
docker volume inspect vigilante-core_vigilante-data
```

Do not delete the volume when recreating containers. `docker compose down`
does not remove named volumes unless `-v` is supplied; do not use `-v` unless
you intend to remove the database.

For larger deployments, configure a PostgreSQL connection through
`DATABASE_URL`. The generated dependency set does not include a PostgreSQL
driver, so install a suitable driver in the image before using a PostgreSQL URL.

## Backups

Stop writes or briefly stop the application before copying the SQLite database
to ensure a consistent file-level backup:

```bash
mkdir -p backups
docker compose stop vigilante
docker run --rm \
  -v vigilante-core_vigilante-data:/data:ro \
  -v "$PWD/backups:/backup" \
  alpine \
  cp /data/vigilante.db /backup/vigilante-$(date -u +%Y%m%dT%H%M%SZ).db
docker compose start vigilante
```

Copy backups to storage outside the VPS and periodically test restoration.
Retain multiple dated copies and protect them as sensitive security data.

## Updates

Pull the desired revision, rebuild, and recreate the service:

```bash
git pull
docker compose up -d --build
docker compose logs --tail=100 vigilante
```

Check both health endpoints and the dashboard after each update. Keep a backup
before upgrades.

## Operational checks

Useful commands:

```bash
docker compose ps
docker compose logs --tail=200 vigilante
docker stats
curl https://your-hostname.example/api/v1/health/live
```

Review host disk usage, Docker volume usage, reverse-proxy certificate renewal,
and backup freshness regularly.
