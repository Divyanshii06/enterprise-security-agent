import json

import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_check_returns_healthy():
    response = client.get("/status/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_issue_token_and_call_protected_endpoint():
    response = client.post("/auth/token", json={"api_key": "super-secret-api-key"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["token_type"] == "bearer"
    assert "access_token" in payload

    token = payload["access_token"]
    metrics_response = client.get(
        "/status/metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert metrics_response.status_code == 200
    assert "active_users" in metrics_response.json()


def test_invalid_api_key_fails_authentication():
    response = client.post("/auth/token", json={"api_key": "invalid_api_key_123"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid API key"
