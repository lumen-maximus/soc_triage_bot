"""Tests for CLI functions, including SOAR container detection."""

from datetime import datetime

import pytest

from soc_triage_bot.models import SignalType
from soc_triage_bot.services.signal_router import SignalRouter


def test_detect_soar_container_with_valid_container():
    """Test SOAR container detection with valid container data."""
    soar_data = {
        "id": 107,
        "label": "incident",
        "name": "Test SOAR Container",
        "source_data_identifier": "test-id-123",
        "description": "Test description",
        "severity": "high",
        "status": "open",
        "tags": ["test"],
        "create_time": "2025-10-24T21:11:29.805433Z",
        "artifact_count": 1,
        "container_update_time": "2025-10-24T21:15:00.000000Z",
        "data": {
            "artifacts": [
                {
                    "id": 1,
                    "name": "Test Artifact",
                    "cef": {
                        "sourceAddress": "10.0.0.1",
                        "destinationAddress": "192.168.1.1",
                    },
                }
            ]
        },
    }

    signal = detect_and_parse_soar_container(soar_data)

    assert signal is not None
    assert signal.signal_id == "soar-107"
    assert signal.signal_type == SignalType.SIEM_ALERT
    assert signal.title == "Test SOAR Container"
    assert signal.description == "Test description"
    assert signal.severity == "high"
    assert signal.source.system == "soar"
    assert signal.source.rule_id == "test-id-123"
    assert "ip" in signal.entities
    assert len(signal.entities["ip"]) == 2


def test_detect_soar_container_with_insufficient_indicators():
    """Test SOAR container detection with insufficient indicators."""
    non_soar_data = {
        "signal_id": "test-001",
        "signal_type": "siem_alert",
        "title": "Regular Signal",
    }

    signal_router = SignalRouter()
    signal = signal_router.detect_and_parse_soar_container(non_soar_data)

    assert signal is None


def test_detect_soar_container_label_mapping():
    """Test SOAR label to signal_type mapping."""
    test_cases = [
        ("incident", SignalType.SIEM_ALERT),
        ("intelligence", SignalType.IOC),
        ("vulnerabilities", SignalType.CVE),
        ("email", SignalType.USER_REPORT),
        ("unknown", SignalType.SIEM_ALERT),  # default
    ]

    signal_router = SignalRouter()
    for label, expected_type in test_cases:
        soar_data = {
            "id": 1,
            "label": label,
            "name": "Test",
            "source_data_identifier": "test-id",
            "artifact_count": 0,
            "create_time": "2025-10-24T21:11:29.805433Z",
        }

        signal = signal_router.detect_and_parse_soar_container(soar_data)

        assert signal is not None
        assert signal.signal_type == expected_type


def test_detect_soar_container_cef_extraction():
    """Test CEF field extraction from artifacts."""
    soar_data = {
        "id": 1,
        "label": "incident",
        "name": "Test",
        "source_data_identifier": "test-id",
        "artifact_count": 2,
        "create_time": "2025-10-24T21:11:29.805433Z",
        "data": {
            "artifacts": [
                {
                    "id": 1,
                    "name": "Network Artifact",
                    "cef": {
                        "sourceAddress": "10.0.0.1",
                        "destinationAddress": "192.168.1.1",
                        "destinationHostName": "server.example.com",
                        "sourceHostName": "workstation.example.com",
                        "destinationDnsDomain": "example.com",
                        "requestURL": "http://evil.com/payload",
                    },
                },
                {
                    "id": 2,
                    "name": "Process Artifact",
                    "cef": {
                        "deviceProcessName": "powershell.exe",
                        "fileHashSha256": "abc123",
                        "suser": "jdoe",
                        "fileName": "malware.exe",
                        "senderAddress": "attacker@evil.com",
                    },
                },
            ]
        },
    }

    signal = detect_and_parse_soar_container(soar_data)

    assert signal is not None

    # Check extracted entities
    assert "ip" in signal.entities
    assert len(signal.entities["ip"]) == 2
    assert "10.0.0.1" in signal.entities["ip"]
    assert "192.168.1.1" in signal.entities["ip"]

    assert "hostname" in signal.entities
    assert len(signal.entities["hostname"]) == 2
    assert "server.example.com" in signal.entities["hostname"]
    assert "workstation.example.com" in signal.entities["hostname"]

    assert "domain" in signal.entities
    assert "example.com" in signal.entities["domain"]

    assert "url" in signal.entities
    assert "http://evil.com/payload" in signal.entities["url"]

    assert "process" in signal.entities
    assert "powershell.exe" in signal.entities["process"]

    assert "hash" in signal.entities
    assert "abc123" in signal.entities["hash"]

    assert "user" in signal.entities
    assert "jdoe" in signal.entities["user"]

    assert "file" in signal.entities
    assert "malware.exe" in signal.entities["file"]

    assert "email" in signal.entities
    assert "attacker@evil.com" in signal.entities["email"]


def test_detect_soar_container_metadata_preservation():
    """Test that all SOAR metadata is preserved."""
    soar_data = {
        "id": 107,
        "label": "incident",
        "name": "Test",
        "source_data_identifier": "test-id-123",
        "description": "Test",
        "severity": "high",
        "status": "open",
        "sensitivity": "amber",
        "owner": "admin",
        "hash": "abc123",
        "asset_name": "SERVER-01",
        "open_time": "2025-10-24T21:11:29.805433Z",
        "close_time": "2025-10-25T10:00:00.000000Z",
        "due_time": "2025-10-26T10:00:00.000000Z",
        "kill_chain": "exploitation",
        "artifact_count": 0,
        "create_time": "2025-10-24T21:11:29.805433Z",
        "container_update_time": "2025-10-24T21:15:00.000000Z",
    }

    signal = detect_and_parse_soar_container(soar_data)

    assert signal is not None
    assert signal.metadata["soar_id"] == 107
    assert signal.metadata["soar_label"] == "incident"
    assert signal.metadata["soar_status"] == "open"
    assert signal.metadata["soar_sensitivity"] == "amber"
    assert signal.metadata["soar_owner"] == "admin"
    assert signal.metadata["soar_hash"] == "abc123"
    assert signal.metadata["soar_asset_name"] == "SERVER-01"
    assert signal.metadata["soar_kill_chain"] == "exploitation"
    assert signal.metadata["artifact_count"] == 0
    assert signal.metadata["source_data_identifier"] == "test-id-123"

    # Check raw_data preservation
    assert signal.raw_data == soar_data


def test_detect_soar_container_deduplication():
    """Test that duplicate entities are deduplicated."""
    soar_data = {
        "id": 1,
        "label": "incident",
        "name": "Test",
        "source_data_identifier": "test-id",
        "artifact_count": 2,
        "create_time": "2025-10-24T21:11:29.805433Z",
        "data": {
            "artifacts": [
                {
                    "id": 1,
                    "name": "Artifact 1",
                    "cef": {
                        "sourceAddress": "10.0.0.1",
                        "destinationAddress": "192.168.1.1",
                    },
                },
                {
                    "id": 2,
                    "name": "Artifact 2",
                    "cef": {
                        "sourceAddress": "10.0.0.1",  # duplicate
                        "destinationAddress": "192.168.1.2",
                    },
                },
            ]
        },
    }

    signal = detect_and_parse_soar_container(soar_data)

    assert signal is not None
    assert "ip" in signal.entities
    # Should have 3 unique IPs, not 4
    assert len(signal.entities["ip"]) == 3
    assert "10.0.0.1" in signal.entities["ip"]
    assert "192.168.1.1" in signal.entities["ip"]
    assert "192.168.1.2" in signal.entities["ip"]


def test_parse_signal_from_json_with_soar_container():
    """Test that parse_signal_from_json detects SOAR containers."""
    soar_data = {
        "id": 107,
        "label": "incident",
        "name": "Test SOAR Container",
        "source_data_identifier": "test-id-123",
        "description": "Test description",
        "artifact_count": 0,
        "create_time": "2025-10-24T21:11:29.805433Z",
    }

    signal_router = SignalRouter()
    signal = signal_router.parse_signal_from_json(soar_data)

    assert signal is not None
    assert signal.signal_id == "soar-107"
    assert signal.source.system == "soar"


def test_parse_signal_from_json_with_regular_signal():
    """Test that parse_signal_from_json falls back for regular signals."""
    regular_data = {
        "signal_id": "test-001",
        "signal_type": "siem_alert",
        "timestamp": "2025-12-14T19:00:00Z",
        "source": {
            "system": "splunk",
            "rule_id": "rule-001",
        },
        "title": "Test Alert",
        "description": "Test description",
        "severity": "high",
        "entities": {"ip": ["192.168.1.1"]},
        "tags": ["test"],
    }

    signal_router = SignalRouter()
    signal = signal_router.parse_signal_from_json(regular_data)

    assert signal is not None
    assert signal.signal_id == "test-001"
    assert signal.source.system == "splunk"
    assert signal.signal_type == SignalType.SIEM_ALERT


def test_detect_soar_container_missing_artifacts_note():
    """Test that missing artifacts are noted in metadata."""
    soar_data = {
        "id": 1,
        "label": "incident",
        "name": "Test",
        "source_data_identifier": "test-id",
        "artifact_count": 5,  # Claims 5 artifacts
        "create_time": "2025-10-24T21:11:29.805433Z",
        # But no artifacts provided
    }

    signal_router = SignalRouter()
    signal = signal_router.detect_and_parse_soar_container(soar_data)

    assert signal is not None
    assert "artifacts_note" in signal.metadata
    assert "5 artifacts" in signal.metadata["artifacts_note"]


def test_detect_soar_container_empty_cef_fields():
    """Test that empty/None CEF fields are skipped."""
    soar_data = {
        "id": 1,
        "label": "incident",
        "name": "Test",
        "source_data_identifier": "test-id",
        "artifact_count": 1,
        "create_time": "2025-10-24T21:11:29.805433Z",
        "data": {
            "artifacts": [
                {
                    "id": 1,
                    "name": "Artifact",
                    "cef": {
                        "sourceAddress": "10.0.0.1",
                        "destinationAddress": None,  # None
                        "destinationHostName": "",  # Empty string
                        "suser": "jdoe",
                    },
                }
            ]
        },
    }

    signal = detect_and_parse_soar_container(soar_data)

    assert signal is not None
    assert "ip" in signal.entities
    # Should only have 1 IP (None and empty string skipped)
    assert len(signal.entities["ip"]) == 1
    assert "10.0.0.1" in signal.entities["ip"]
