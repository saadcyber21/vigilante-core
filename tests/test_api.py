import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from app.config import Settings
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def auth(client, username="admin", password="test-password"):
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def create_user(client, headers, username, role="analyst", password="secure-test-password-2026"):
    return client.post("/api/v1/admin/users", headers=headers, json={
        "username": username,
        "password": password,
        "role": role,
    })


def test_dashboard_and_static_assets(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "Command center" in page.text
    assert "DEMO DATA" in page.text
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_login_and_health(client):
    assert client.get("/api/v1/health/live").json()["status"] == "alive"
    assert client.get("/api/v1/health/ready").json()["status"] == "ready"
    assert auth(client)["Authorization"].startswith("Bearer ")


def test_webhook_requires_authentication_for_every_source(client):
    body = {"payload": {"event_type": "authentication", "message": "failed sign-in"}}
    assert client.post("/api/v1/ingest/webhooks/identity", json=body).status_code == 401
    assert client.post(
        "/api/v1/ingest/webhooks/identity",
        headers={"X-Webhook-Secret": "wrong-secret"},
        json=body,
    ).status_code == 401
    accepted = client.post(
        "/api/v1/ingest/webhooks/identity",
        headers={"X-Webhook-Secret": "test-webhook"},
        json=body,
    )
    assert accepted.status_code == 202
    assert accepted.json()["accepted"] is True


def test_webhook_is_idempotent(client):
    payload = {
        "event_type": "authentication",
        "message": "multiple failed login attempts followed by privilege escalation",
        "source_ip": "192.0.2.10",
    }
    headers = {"X-Webhook-Secret": "test-webhook"}
    first = client.post(
        "/api/v1/ingest/webhooks/identity",
        headers=headers,
        json={"payload": payload, "idempotency_key": "sample-001"},
    )
    second = client.post(
        "/api/v1/ingest/webhooks/identity",
        headers=headers,
        json={"payload": payload, "idempotency_key": "sample-001"},
    )
    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json()["alert_id"] == second.json()["alert_id"]
    assert first.json()["accepted"] is True
    assert second.json()["accepted"] is False


def test_clients_cannot_choose_tenant(client):
    headers = {"X-Webhook-Secret": "test-webhook"}
    webhook = client.post(
        "/api/v1/ingest/webhooks/identity",
        headers=headers,
        json={"payload": {"event_type": "auth"}, "tenant_id": "other-company"},
    )
    assert webhook.status_code == 422

    alert = client.post(
        "/api/v1/alerts",
        headers=auth(client),
        json={"payload": {"event_type": "auth"}, "tenant_id": "other-company"},
    )
    assert alert.status_code == 422


def test_alert_case_and_dashboard(client):
    headers = auth(client)
    alert = client.post(
        "/api/v1/alerts",
        headers=headers,
        json={
            "source_key": "synthetic",
            "payload": {"test": True, "message": "synthetic healthcheck"},
            "idempotency_key": "case-flow-alert",
        },
    )
    assert alert.status_code == 200
    alert_id = alert.json()["alert"]["id"]
    assert alert.json()["alert"]["tenant_id"] == "test-tenant"

    changed = client.patch(f"/api/v1/alerts/{alert_id}", headers=headers, json={
        "status": "investigating",
        "reason": "Analyst opened an investigation.",
    })
    assert changed.status_code == 200
    assert changed.json()["status"] == "investigating"
    invalid_status = client.patch(f"/api/v1/alerts/{alert_id}", headers=headers, json={
        "status": "run-command",
        "reason": "This is not an allowed status.",
    })
    assert invalid_status.status_code == 422

    case = client.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "title": "Synthetic investigation",
            "description": "Test case",
            "priority": "low",
            "alert_ids": [alert_id],
        },
    )
    assert case.status_code == 200
    assert case.json()["case_number"] >= 1
    assert alert_id in case.json()["alert_ids"]

    summary = client.get("/api/v1/dashboard/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["alerts_total"] >= 1
    audit_events = client.get("/api/v1/audit-events", headers=headers)
    assert audit_events.status_code == 200
    assert any(event["action"] == "alert.status_updated" for event in audit_events.json())


def test_admin_user_lifecycle_and_role_enforcement(client):
    admin_headers = auth(client)
    created = create_user(client, admin_headers, "Analyst1")
    assert created.status_code == 201
    assert created.json()["username"] == "analyst1"
    assert "password_hash" not in created.json()

    analyst_headers = auth(client, "analyst1", "secure-test-password-2026")
    assert client.get("/api/v1/admin/users", headers=analyst_headers).status_code == 403
    listed = client.get("/api/v1/admin/users", headers=admin_headers)
    assert listed.status_code == 200
    assert any(user["username"] == "analyst1" for user in listed.json()["items"])

    deactivated = client.patch(
        f"/api/v1/admin/users/{created.json()['id']}",
        headers=admin_headers,
        json={"is_active": False},
    )
    assert deactivated.status_code == 200
    assert client.post("/api/v1/auth/login", json={
        "username": "analyst1",
        "password": "secure-test-password-2026",
    }).status_code == 401


def test_case_rejects_unknown_alert_and_invalid_status(client):
    headers = auth(client)
    missing = client.post("/api/v1/cases", headers=headers, json={
        "title": "Invalid association",
        "alert_ids": ["not-an-alert"],
    })
    assert missing.status_code == 404

    created = client.post("/api/v1/cases", headers=headers, json={"title": "Status validation"})
    assert created.status_code == 200
    changed = client.patch(
        f"/api/v1/cases/{created.json()['id']}",
        headers=headers,
        json={"status": "execute-shell"},
    )
    assert changed.status_code == 422


def test_response_proposal_requires_second_reviewer_and_never_executes(client):
    admin_headers = auth(client)
    manager = create_user(client, admin_headers, "manager1", role="manager")
    assert manager.status_code == 201
    manager_headers = auth(client, "manager1", "secure-test-password-2026")

    alert = client.post("/api/v1/alerts", headers=admin_headers, json={
        "source_key": "endpoint",
        "payload": {"host": "WS-001", "event_type": "suspicious_process"},
        "idempotency_key": "response-proposal-alert",
    })
    assert alert.status_code == 200
    alert_id = alert.json()["alert"]["id"]

    proposal = client.post(
        f"/api/v1/alerts/{alert_id}/response-proposals",
        headers=manager_headers,
        json={
            "action_type": "isolate_host",
            "target_reference": "WS-001",
            "rationale": "Containment is recommended pending analyst validation.",
        },
    )
    assert proposal.status_code == 201
    proposal_id = proposal.json()["id"]
    assert proposal.json()["status"] == "pending"
    assert proposal.json()["execution_status"] == "not_executed"

    self_review = client.post(
        f"/api/v1/response-proposals/{proposal_id}/review",
        headers=manager_headers,
        json={"decision": "approve", "reason": "I reviewed my own request."},
    )
    assert self_review.status_code == 409

    approved = client.post(
        f"/api/v1/response-proposals/{proposal_id}/review",
        headers=admin_headers,
        json={"decision": "approve", "reason": "Reviewed evidence; manual action is authorized."},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["execution_status"] == "not_executed"

    proposals = client.get("/api/v1/response-proposals?status=approved", headers=admin_headers)
    assert proposals.status_code == 200
    assert proposals.json()["items"][0]["id"] == proposal_id


def test_failed_login_is_audited_as_failure(client):
    failed = client.post("/api/v1/auth/login", json={"username": "missing-user", "password": "wrong"})
    assert failed.status_code == 401
    events = client.get("/api/v1/audit-events", headers=auth(client))
    assert events.status_code == 200
    assert any(event["action"] == "login.failed" and event["success"] is False for event in events.json())


def test_production_settings_reject_weak_secrets():
    with pytest.raises(ValidationError):
        Settings(environment="production", jwt_secret="development-only-change-me")

    safe = Settings(
        environment="production",
        jwt_secret="j" * 64,
        admin_password="Strong-admin-passphrase-2026",
        webhook_secret="w" * 64,
    )
    assert safe.environment == "production"


def test_source_specific_secrets_restrict_unknown_sources():
    configured = Settings(
        webhook_secret="fallback-secret-that-is-long-enough-123456",
        webhook_source_secrets={"identity": "i" * 64},
    )
    assert configured.webhook_secret_for("identity") == "i" * 64
    assert configured.webhook_secret_for("unknown") is None
