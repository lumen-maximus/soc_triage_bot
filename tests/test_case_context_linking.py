"""Test CaseContextLinkingService."""

import asyncio
from datetime import datetime, timezone

from soc_triage_bot.models import Signal, SignalSource, SignalType
from soc_triage_bot.models.case_graph import NodeType, TriageMode
from soc_triage_bot.models.signal import EntityBehaviorContext
from soc_triage_bot.services.case_bootstrap import CaseBootstrapService
from soc_triage_bot.services.case_context_linking import CaseContextLinkingService


async def test_case_context_linking():
    """Test CaseContextLinkingService links cases to graph."""

    # Create test signal
    signal = Signal(
        signal_id="ALERT-003",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(system="SIEM", rule_id="R-789"),
        title="Ransomware detected",
        description="Suspicious encryption activity",
        severity="critical",
        entities={},
        tags=["ransomware", "malware"],
        raw_data={},
        metadata={},
        entity_context=EntityBehaviorContext(
            hostname="fileserver-01.corp.local",
            username="admin",
        ),
    )

    # Bootstrap graph
    bootstrap = CaseBootstrapService()
    graph = bootstrap.bootstrap(signal, mode=TriageMode.MIN_DELTA)

    # Create mock case database for similarity service
    mock_cases = [
        {
            "case_id": "CASE-2024-001",
            "title": "Ransomware outbreak",
            "description": "Encryption detected",
            "signal_type": "siem_alert",
            "tags": ["ransomware"],
            "entities": {"hostname": ["fileserver-01.corp.local"]},
            "outcome": "TP",
            "rule_id": "R-789",
        },
        {
            "case_id": "CASE-2024-002",
            "title": "Malware infection",
            "description": "Suspicious activity",
            "signal_type": "siem_alert",
            "tags": ["malware"],
            "entities": {"hostname": ["fileserver-02.corp.local"]},
            "outcome": "TP",
        },
    ]

    # Initialize services
    linking_service = CaseContextLinkingService(case_database=mock_cases)

    # Link cases using retrieve_rank_hydrate
    result = await linking_service.retrieve_rank_hydrate(signal, graph)
    links_added = result.links_added_to_graph

    # Verify links added to graph
    assert links_added > 0

    # Check similar case nodes
    case_nodes = graph.get_nodes_by_type(NodeType.SIMILAR_CASE_REF)
    assert len(case_nodes) > 0

    # Check edges
    from soc_triage_bot.models.case_graph import EdgeType

    similar_edges = graph.get_edges_by_type(EdgeType.SIMILAR_TO)
    assert len(similar_edges) > 0

    # Extract cases for downstream use
    linked_cases = linking_service.get_linked_cases_from_graph(graph)
    assert len(linked_cases) > 0
    assert linked_cases[0]["similarity"] > 0

    print(f"✓ CaseContextLinking added {links_added} case links")
    print(f"  Similar case nodes: {len(case_nodes)}")
    print(f"  Similar edges: {len(similar_edges)}")
    print(
        f"  Top case: {linked_cases[0]['case_id']} (similarity: {linked_cases[0]['similarity']:.2f})"
    )


async def test_conditional_linking():
    """Test conditional linking for IOC signals."""

    # Create IOC signal
    signal = Signal(
        signal_id="IOC-002",
        signal_type=SignalType.IOC,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(system="ThreatFeed"),
        title="Malicious IP",
        description="Known C2",
        severity="high",
        entities={},
        tags=["ioc"],
        raw_data={},
        metadata={},
    )

    # Bootstrap graph
    bootstrap = CaseBootstrapService()
    graph = bootstrap.bootstrap(signal, mode=TriageMode.MIN_DELTA)

    # Add detection presence observation (simulates DetectionResolver found hits)
    from soc_triage_bot.models.case_graph import (
        ObservationNode,
        ObservationType,
        Provenance,
    )

    obs_node = ObservationNode(
        node_id="obs_detection_present",
        node_type=NodeType.OBSERVATION,
        observation_type=ObservationType.DETECTION_PRESENCE,
        provenance=Provenance(
            source_system="DetectionResolver",
            query_fingerprint="test_detection",
            ttl_seconds=3600,
        ),
        hit_count=5,
    )
    graph.add_node(obs_node)

    # Initialize linking service
    linking_service = CaseContextLinkingService(case_database=[])

    # Should NOT run linking (detection present = no hunting needed)
    result = await linking_service.retrieve_rank_hydrate(signal, graph)
    links_added = result.links_added_to_graph

    assert links_added == 0
    print("✓ Conditional linking skipped for IOC with detection present")
    print(f"  Links added: {links_added} (expected 0)")


async def main():
    await test_case_context_linking()
    print()
    await test_conditional_linking()
    print("\n✅ All CaseContextLinking tests passed!")


if __name__ == "__main__":
    asyncio.run(main())
