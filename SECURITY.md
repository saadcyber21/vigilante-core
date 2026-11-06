# Security policy

## Reporting a vulnerability

Please do not disclose security vulnerabilities in public issues.

Report suspected vulnerabilities privately to the project maintainers with:

- A concise description of the issue
- Affected files, endpoints, or configuration
- Steps to reproduce
- Potential impact
- Any suggested mitigation

If no private reporting channel has been configured, contact the maintainers
through the repository hosting provider's private security-reporting feature.

## Deployment guidance

Before deployment:

- Replace the example `JWT_SECRET`.
- Replace `ADMIN_PASSWORD`.
- Replace `WEBHOOK_SECRET`.
- Run the application behind HTTPS.
- Restrict access to the application host and reverse proxy.
- Protect `.env` and database backups.
- Use a separate webhook secret for each external integration where
  appropriate.
- Review CORS origins and avoid broad origins in production.
- Monitor application logs, host resources, and backup status.

The application stores incoming payloads in the transactional database. Treat
the database and backups as sensitive security data.

## Supported versions

The project currently publishes version `0.1.0`. Security fixes are applied
to the current development line. Users should run the latest available
revision and review release notes before upgrading.
