"""Quick validation test for CKG models."""

from datetime import datetime, timezone

from soc_triage_bot.models.case_graph import (
    CaseNode,
    EdgeType,
    EntityNode,
    EntityType,
    EvidenceEdge,
    NodeType,
    ObservationNode,
    ObservationType,
    OutcomeNode,
    Provenance,
    SignalNode,
    TriageContextGraph,
    TriageMode,
)


def test_graph_creation():
    """Test basic graph creation and operations."""

    # Create graph
    graph = TriageContextGraph(case_id="CASE-001", mode=TriageMode.MIN_DELTA)

    # Create provenance
    prov = Provenance(
        source_system="SIEM",
        query_fingerprint="hash123",
        ttl_seconds=3600,
        confidence=0.9,
        evidence_refs=["alert-001", "event-123"],
    )

    # Add case node
    case_node = CaseNode(
        node_id="case_001", node_type=NodeType.CASE, case_id="CASE-001", provenance=prov
    )
    graph.add_node(case_node)

    # Add signal node
    signal_node = SignalNode(
        node_id="signal_001",
        node_type=NodeType.SIGNAL,
        signal_id="SIG-001",
        signal_type="ALERT",
        first_seen=datetime.now(timezone.utc),
        provenance=prov,
    )
    graph.add_node(signal_node)

    # Add entity node
    entity_node = EntityNode(
        node_id="entity_host_001",
        node_type=NodeType.ENTITY,
        entity_type=EntityType.HOST,
        canonical_id="host_workstation_42",
        entity_value="workstation-42.corp.local",
        provenance=prov,
    )
    graph.add_node(entity_node)

    # Add observation
    obs_node = ObservationNode(
        node_id="obs_ti_001",
        node_type=NodeType.OBSERVATION,
        observation_type=ObservationType.THREAT_INTEL,
        provenance=prov,
    )
    graph.add_node(obs_node)

    # Add outcome
    outcome_node = OutcomeNode(
        node_id="outcome_001",
        node_type=NodeType.OUTCOME,
        disposition="Likely True Positive",
        severity="high",
        confidence="medium",
        tp_likelihood=0.75,
        provenance=prov,
    )
    graph.add_node(outcome_node)

    # Add edges
    case_signal_edge = EvidenceEdge(
        edge_id="edge_001",
        edge_type=EdgeType.HAS_SIGNAL,
        source_node_id="case_001",
        target_node_id="signal_001",
        provenance=prov,
    )
    graph.add_edge(case_signal_edge)

    signal_entity_edge = EvidenceEdge(
        edge_id="edge_002",
        edge_type=EdgeType.MENTIONS,
        source_node_id="signal_001",
        target_node_id="entity_host_001",
        provenance=prov,
    )
    graph.add_edge(signal_entity_edge)

    supports_edge = EvidenceEdge(
        edge_id="edge_003",
        edge_type=EdgeType.SUPPORTS,
        source_node_id="obs_ti_001",
        target_node_id="outcome_001",
        provenance=prov,
        weight=0.8,
    )
    graph.add_edge(supports_edge)

    # Test queries
    assert len(graph.nodes) == 5
    assert len(graph.edges) == 3

    # Get nodes by type
    entity_nodes = graph.get_nodes_by_type(NodeType.ENTITY)
    assert len(entity_nodes) == 1
    # Cast to EntityNode to access entity_value (EntityNode already imported at top)
    entity_node_typed = entity_nodes[0]
    assert isinstance(entity_node_typed, EntityNode)
    assert entity_node_typed.entity_value == "workstation-42.corp.local"

    # Get connected nodes
    connected = graph.get_connected_nodes("case_001", EdgeType.HAS_SIGNAL)
    assert len(connected) == 1
    assert connected[0].node_id == "signal_001"

    # Get evidence chain
    chain = graph.get_evidence_chain("outcome_001")
    assert len(chain["supporting"]) == 1
    assert chain["support_weight"] == 0.8

    # Compute connectivity
    score = graph.compute_connectivity_score()
    assert score > 0.0

    # Export
    export = graph.to_dict()
    assert export["case_id"] == "CASE-001"
    assert len(export["nodes"]) == 5

    print("✅ All CKG model tests passed!")
    print(f"Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    print(f"Connectivity score: {score:.3f}")


if __name__ == "__main__":
    test_graph_creation()
    test_graph_creation()
    test_graph_creation()
