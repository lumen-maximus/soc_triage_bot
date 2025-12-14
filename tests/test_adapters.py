"""Tests for adapters."""

import pytest
from datetime import datetime
from soc_triage_bot.models import Signal, SignalType, SignalSource, EnrichmentStatus
from soc_triage_bot.adapters import (
    SIEMAdapter,
    EDRAdapter,
    ThreatIntelAdapter,
    VulnerabilityAdapter,
    CMDBAdapter
)


@pytest.fixture
def sample_signal():
    """Create a sample signal for testing."""
    return Signal(
        signal_id="test-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="test"),
        title="Test Alert",
        description="Test",
        severity="high",
        entities={
            "ip": ["192.0.2.100"],
            "hostname": ["test-host"],
            "user": ["testuser"]
        }
    )


@pytest.mark.asyncio
async def test_siem_adapter(sample_signal):
    """Test SIEM adapter enrichment."""
    adapter = SIEMAdapter()
    result = await adapter.enrich(sample_signal)
    
    assert result.adapter == "siem"
    assert result.status == EnrichmentStatus.SUCCESS
    assert "alert_frequency_24h" in result.data
    assert result.duration_ms is not None


@pytest.mark.asyncio
async def test_edr_adapter(sample_signal):
    """Test EDR adapter enrichment."""
    adapter = EDRAdapter()
    result = await adapter.enrich(sample_signal)
    
    assert result.adapter == "edr"
    assert result.status == EnrichmentStatus.SUCCESS
    assert "host_online" in result.data


@pytest.mark.asyncio
async def test_threat_intel_adapter(sample_signal):
    """Test Threat Intel adapter enrichment."""
    adapter = ThreatIntelAdapter()
    result = await adapter.enrich(sample_signal)
    
    assert result.adapter == "threat_intel"
    assert result.status == EnrichmentStatus.SUCCESS
    assert "reputation" in result.data


@pytest.mark.asyncio
async def test_vulnerability_adapter(sample_signal):
    """Test Vulnerability adapter enrichment."""
    adapter = VulnerabilityAdapter()
    result = await adapter.enrich(sample_signal)
    
    assert result.adapter == "vulnerability"
    assert result.status == EnrichmentStatus.SUCCESS
    assert "vulnerabilities_found" in result.data


@pytest.mark.asyncio
async def test_cmdb_adapter(sample_signal):
    """Test CMDB adapter enrichment."""
    adapter = CMDBAdapter()
    result = await adapter.enrich(sample_signal)
    
    assert result.adapter == "cmdb"
    assert result.status == EnrichmentStatus.SUCCESS
    assert "assets_found" in result.data


@pytest.mark.asyncio
async def test_adapter_health_check():
    """Test adapter health check."""
    adapter = SIEMAdapter()
    is_healthy = await adapter.health_check()
    
    assert is_healthy is True
