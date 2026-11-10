# Security policy

## Reporting a vulnerability

Please do not disclose security vulnerabilities in public issues. Report suspected vulnerabilities privately to the project maintainers with a concise description, affected endpoints/files, reproduction steps, potential impact, and any suggested mitigation. If no private reporting channel is configured, use the repository host’s private security-reporting feature.

## Deployment guidance

Before deployment:

- Replace the example `JWT_SECRET`, `ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, and webhook credentials with unique values.
- Run the API behind HTTPS and restrict direct access to the API and database ports.
- Protect `.env`, incoming security payloads, database backups, and logs as sensitive data.
- Prefer unique webhook secrets per integration and rotate secrets after exposure.
- Restrict CORS to the exact trusted console origins.
- Back up before upgrades and review schema changes; this MVP does not yet include a database migration framework.
- Monitor failed logins, host resources, service health, and backup freshness.

The static GitHub Pages site does not host authentication, API credentials, the database, or the webhook receiver. The backend is designed for one organization per deployment and must not be shared across unrelated customers. Response proposals and approvals are records only; there are no automated offensive or containment actions.

## Supported versions

The project is in active MVP development. Security fixes are applied to the current development line. Run a reviewed, current revision and read release notes before upgrading.
