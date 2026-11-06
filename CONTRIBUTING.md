# Contributing

Thank you for contributing to Vigilante AI.

## Development setup

The project requires Python 3.12 or newer.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
```

Use development-only credentials in local environments and do not commit `.env`
or database files.

## Running the application

```bash
uvicorn app.main:app --reload
```

The application is available at `http://localhost:8000`.

## Running tests

```bash
pytest
```

Add or update tests when changing API behavior, authentication, ingestion,
triage, cases, or persistence behavior.

## Pull requests

1. Create a focused branch.
2. Make the smallest change that solves the problem.
3. Add tests for behavior changes.
4. Run the test suite locally.
5. Update documentation when configuration or API behavior changes.
6. Explain operational, security, and compatibility considerations in the
   pull request description.

Keep commits focused and avoid including credentials, generated databases,
build output, or unrelated formatting changes.
