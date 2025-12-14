"""Tests for API endpoints."""

import pytest
from fastapi.testclient import TestClient
from soc_triage_bot.api import app


client = TestClient(app)


def test_root():
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "SOC Triage Bot"


def test_health_check():
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "adapters" in data


def test_triage_signal():
    """Test signal triage endpoint."""
    signal_data = {
        "signal_id": "test-api-001",
        "signal_type": "siem_alert",
        "timestamp": "2025-12-14T19:00:00Z",
        "source": {
            "system": "test"
        },
        "title": "Test Alert",
        "description": "Test",
        "severity": "high",
        "entities": {"ip": ["192.0.2.1"]},
        "tags": [],
        "raw_data": {},
        "metadata": {}
    }
    
    response = client.post("/triage", json={"signal": signal_data})
    assert response.status_code == 200
    data = response.json()
    
    assert "triage_id" in data
    assert "classification" in data
    assert "actions" in data
    assert data["signal_id"] == "test-api-001"


def test_normalize_signal():
    """Test signal normalization endpoint."""
    raw_signal = {
        "type": "siem_alert",
        "title": "Test Alert",
        "description": "Test description",
        "severity": "medium",
        "system": "test_system"
    }
    
    response = client.post("/signals/normalize", json=raw_signal)
    assert response.status_code == 200
    data = response.json()
    
    assert "signal_id" in data
    assert data["signal_type"] == "siem_alert"
    assert data["title"] == "Test Alert"
