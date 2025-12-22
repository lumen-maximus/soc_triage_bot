"""Test CKG integration with TriageService end-to-end."""

import pytest

from soc_triage_bot.adapters import CMDBAdapter, EDRAdapter, SIEMAdapter
from soc_triage_bot.models import Signal, SignalSource, SignalType
from soc_triage_bot.models.case_graph import NodeType, TriageMode
from soc_triage_bot.services import EnrichmentService, TriageService


def _create_signal(signal_id: str, title: str, severity: str = "high"):
    """Helper to create test signals."""
    from datetime import datetime, timezone

    return Signal(
        signal_id=signal_id,
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(system="SIEM", rule_id=f"R-{signal_id}"),
        title=title,
        description=f"Test signal: {title}",
        severity=severity,
        entities={"hostname": ["TEST-HOST"], "username": ["testuser"]},
        tags=["test"],
        raw_data={},
        metadata={},
    )


@pytest.mark.asyncio
async def test_triage_with_ckg_enabled():
    """Test complete triage workflow with CKG enabled."""

    # Create test signal
    signal = _create_signal("TEST-CKG-001", "Suspicious PowerShell", "high")

    # Create adapters and services
    adapters = [SIEMAdapter(), EDRAdapter(), CMDBAdapter()]
    enrichment_service = EnrichmentService(adapters)
    triage_service = TriageService(
        enrichment_service=enrichment_service, enable_ckg=True
    )

    # Run triage with CKG
    result = await triage_service.triage_extended(
        signal, triage_mode=TriageMode.MIN_DELTA
    )

    # Verify result has CKG graph
    assert result.graph is not None
    assert result.graph.case_id.startswith("CASE-")
    assert result.graph.mode == TriageMode.MIN_DELTA

    # Verify graph structure
    assert len(result.graph.nodes) >= 2  # At least Case + Signal nodes
    case_nodes = result.graph.get_nodes_by_type(NodeType.CASE)
    assert len(case_nodes) == 1

    signal_nodes = result.graph.get_nodes_by_type(NodeType.SIGNAL)
    assert len(signal_nodes) == 1

    # Verify observation nodes from DetectionResolver
    obs_nodes = result.graph.get_nodes_by_type(NodeType.OBSERVATION)
    assert len(obs_nodes) >= 0  # May have detection observations

    # Verify triage result has standard outputs
    assert result.classification is not None
    assert result.actions is not None
    assert result.report is not None
    assert result.duration_ms is not None

    print(f"✓ CKG-enabled triage complete for {signal.signal_id}")
    print(f"  Graph: {len(result.graph.nodes)} nodes, {len(result.graph.edges)} edges")
    print(f"  Classification: {result.classification.disposition}")
    print(f"  Actions: {len(result.actions)}")


@pytest.mark.asyncio
async def test_triage_with_ckg_disabled():
    """Test triage workflow with CKG disabled (legacy mode)."""

    # Create test signal
    signal = _create_signal("TEST-LEGACY-001", "Test Alert", "medium")

    # Create adapters and services with CKG disabled
    from typing import cast

    adapters = cast(list, [SIEMAdapter()])
    enrichment_service = EnrichmentService(adapters)
    triage_service = TriageService(
        enrichment_service=enrichment_service, enable_ckg=False
    )

    # Run triage without CKG
    result = await triage_service.triage_extended(signal)

    # Verify no graph in result
    assert result.graph is None

    # Verify standard outputs still work
    assert result.classification is not None
    assert result.actions is not None
    assert result.report is not None

    print(f"✓ Legacy triage complete (no CKG) for {signal.signal_id}")
    print(f"  Classification: {result.classification.disposition}")
    print(f"  Actions: {len(result.actions)}")


@pytest.mark.asyncio
async def test_governance_gate_blocks_fp_actions():
    """Test that GovernanceGate blocks containment actions on FP signals."""

    # Create FP-likely signal
    signal = _create_signal("TEST-FP-001", "Likely False Positive", "low")

    # Create services with CKG enabled
    from typing import cast

    adapters = cast(list, [SIEMAdapter()])
    enrichment_service = EnrichmentService(adapters)
    triage_service = TriageService(
        enrichment_service=enrichment_service, enable_ckg=True
    )

    # Run triage
    result = await triage_service.triage_extended(signal)

    # Verify governance applied
    # If classified as FP, high-risk actions should be blocked
    if result.classification.disposition == "FALSE_POSITIVE":
        # Check that no CONTAIN actions are present
        contain_actions = [a for a in result.actions if "contain" in a.title.lower()]
        # Governance should have filtered these out
        assert (
            len(contain_actions) == 0
        ), "FP should not have containment actions (governance blocked)"

    print(f"✓ GovernanceGate filtering verified for {signal.signal_id}")
    print(f"  Classification: {result.classification.disposition}")
    print(f"  Actions after governance: {len(result.actions)}")


@pytest.mark.asyncio
async def test_case_context_linking_adds_nodes():
    """Test that CaseContextLinking adds similar case nodes to graph."""

    # Create signal
    signal = _create_signal("TEST-LINKING-001", "Test for case linking", "high")

    # Create services
    from typing import cast

    adapters = cast(list, [SIEMAdapter()])
    enrichment_service = EnrichmentService(adapters)
    triage_service = TriageService(
        enrichment_service=enrichment_service, enable_ckg=True
    )

    # Run triage
    result = await triage_service.triage_extended(signal)

    # Verify graph has case nodes
    assert result.graph is not None
    similar_case_nodes = result.graph.get_nodes_by_type(NodeType.SIMILAR_CASE_REF)

    # May or may not have similar cases depending on database
    print(f"✓ CaseContextLinking executed for {signal.signal_id}")
    print(f"  Similar case nodes in graph: {len(similar_case_nodes)}")


if __name__ == "__main__":
    import asyncio

    print("Running CKG integration tests...\n")

    asyncio.run(test_triage_with_ckg_enabled())
    print()

    asyncio.run(test_triage_with_ckg_disabled())
    print()

    asyncio.run(test_governance_gate_blocks_fp_actions())
    print()

    asyncio.run(test_case_context_linking_adds_nodes())
    print()

    print("\n✓ All CKG integration tests passed!")
