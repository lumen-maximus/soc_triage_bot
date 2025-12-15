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


def test_triage_signal_response_structure():
    """Test that triage response contains all expected fields."""
    signal_data = {
        "signal_id": "test-structure-001",
        "signal_type": "siem_alert",
        "timestamp": "2025-12-15T10:00:00Z",
        "source": {"system": "test"},
        "title": "Structure Test Alert",
        "description": "Test response structure",
        "severity": "high",
        "entities": {"ip": ["192.0.2.50"]},
        "tags": [],
        "raw_data": {},
        "metadata": {}
    }
    
    response = client.post("/triage", json={"signal": signal_data})
    assert response.status_code == 200
    data = response.json()
    
    # Check legacy fields
    assert "triage_id" in data
    assert "signal_id" in data
    assert "classification" in data
    assert "label" in data["classification"]
    assert "confidence" in data["classification"]
    assert "reasoning" in data["classification"]
    
    # Check actions structure
    assert "actions" in data
    assert isinstance(data["actions"], list)
    if len(data["actions"]) > 0:
        action = data["actions"][0]
        assert "action_id" in action
        assert "type" in action
        assert "priority" in action
    
    # Check enrichments
    assert "enrichments" in data
    assert isinstance(data["enrichments"], dict)
    
    # Check timing
    assert "duration_ms" in data
    assert "timestamp" in data


def test_triage_with_different_signal_types():
    """Test triage with various signal types."""
    signal_types = ["siem_alert", "ioc", "cve", "hunt", "user_report"]
    
    for sig_type in signal_types:
        signal_data = {
            "signal_id": f"test-type-{sig_type}",
            "signal_type": sig_type,
            "timestamp": "2025-12-15T11:00:00Z",
            "source": {"system": "test"},
            "title": f"Test {sig_type.upper()} Signal",
            "description": f"Testing {sig_type} signal type",
            "severity": "medium",
            "entities": {"ip": ["192.0.2.60"]},
            "tags": [],
            "raw_data": {},
            "metadata": {}
        }
        
        response = client.post("/triage", json={"signal": signal_data})
        assert response.status_code == 200, f"Failed for signal type: {sig_type}"
        data = response.json()
        assert data["signal_id"] == f"test-type-{sig_type}"


def test_triage_with_enriched_signal():
    """Test triage with a fully enriched signal (context fields)."""
    signal_data = {
        "signal_id": "test-enriched-001",
        "signal_type": "siem_alert",
        "timestamp": "2025-12-15T13:00:00Z",
        "source": {
            "system": "splunk",
            "rule_id": "SPL-001",
            "rule_name": "Suspicious PowerShell Activity"
        },
        "title": "Suspicious PowerShell Execution",
        "description": "PowerShell with encoded command detected",
        "severity": "critical",
        "entities": {
            "ip": ["192.0.2.80", "198.51.100.10"],
            "hostname": ["workstation-01"],
            "username": ["admin-user"]
        },
        "indicators": {
            "domain": "evil.com",
            "ip": "198.51.100.10"
        },
        "tags": ["powershell", "encoded", "suspicious"],
        "raw_data": {
            "process_name": "powershell.exe",
            "command_line": "powershell -enc ..."
        },
        "metadata": {
            "mitre_attack": ["T1059.001"]
        }
    }
    
    response = client.post("/triage", json={"signal": signal_data})
    assert response.status_code == 200
    data = response.json()
    
    assert data["signal_id"] == "test-enriched-001"
    assert "classification" in data
    assert "actions" in data
    assert len(data["actions"]) > 0  # Should have action recommendations


def test_get_triage_result_not_found():
    """Test getting a non-existent triage result."""
    response = client.get("/triage/nonexistent-id-12345")
    assert response.status_code == 404


def test_get_triage_report_not_found():
    """Test getting report for non-existent triage."""
    response = client.get("/triage/nonexistent-id-12345/report")
    assert response.status_code == 404


def test_get_triage_actions_not_found():
    """Test getting actions for non-existent triage."""
    response = client.get("/triage/nonexistent-id-12345/actions")
    assert response.status_code == 404
