from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def auth():
    response = client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "test-password",
    })
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_login_and_health():
    assert client.get("/api/v1/health/live").json()["status"] == "alive"
    assert auth()["Authorization"].startswith("Bearer ")


def test_webhook_is_idempotent():
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


def test_alert_case_and_dashboard():
    headers = auth()
    alert = client.post(
        "/api/v1/alerts",
        headers=headers,
        json={
            "source_key": "synthetic",
            "payload": {"test": True, "message": "synthetic healthcheck"},
        },
    )
    assert alert.status_code == 200
    alert_id = alert.json()["alert"]["id"]

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
    assert alert_id in case.json()["alert_ids"]

    summary = client.get("/api/v1/dashboard/summary", headers=headers)
    assert summary.status_code == 200
    assert summary.json()["alerts_total"] >= 1
