"""Test CKG Phase 2 services: Bootstrap, SignalRouter, GovernanceGate."""

from datetime import datetime, timezone

from soc_triage_bot.models import Action, ActionType, Signal, SignalSource, SignalType
from soc_triage_bot.models.case_graph import EdgeType, NodeType, TriageMode
from soc_triage_bot.models.enrichment import EnrichmentResult, EnrichmentStatus
from soc_triage_bot.models.triage_report import ClassificationResult
from soc_triage_bot.services.case_bootstrap import CaseBootstrapService
from soc_triage_bot.services.governance_gate import GovernanceGate
from soc_triage_bot.services.signal_router import SignalRouter


def test_case_bootstrap():
    """Test CaseBootstrapService creates graph with correct mode and budgets."""

    # Create test signal
    signal = Signal(
        signal_id="TEST-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(system="SIEM", rule_id="R-123"),
        title="Test Alert",
        description="Test alert for bootstrap",
        severity="high",
        entities={},
        tags=["test"],
        raw_data={},
        metadata={},
    )

    # Bootstrap with MIN_DELTA mode
    bootstrap = CaseBootstrapService()
    graph = bootstrap.bootstrap(signal, mode=TriageMode.MIN_DELTA)

    # Verify graph structure
    assert graph.case_id.startswith("CASE-")
    assert graph.mode == TriageMode.MIN_DELTA
    assert len(graph.nodes) == 2  # Case + Signal
    assert len(graph.edges) == 1  # Case → Signal

    # Verify budgets
    assert graph.budget.max_case_candidates == 10
    assert graph.budget.max_enrichment_adapters == 3

    # Verify nodes
    case_nodes = graph.get_nodes_by_type(NodeType.CASE)
    signal_nodes = graph.get_nodes_by_type(NodeType.SIGNAL)
    assert len(case_nodes) == 1
    assert len(signal_nodes) == 1

    # Verify edge
    edges = graph.get_edges_by_type(EdgeType.HAS_SIGNAL)
    assert len(edges) == 1

    print(f"✓ Bootstrap created graph: {graph.case_id}")
    print(f"  Mode: {graph.mode.value}")
    print(f"  Nodes: {len(graph.nodes)}, Edges: {len(graph.edges)}")


def test_signal_router():
    """Test SignalRouter normalizes signal and extracts entities."""

    # Create signal with entity_context
    from soc_triage_bot.models.signal import EntityBehaviorContext

    signal = Signal(
        signal_id="TEST-002",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(system="SIEM", rule_id="R-456"),
        title="Suspicious PowerShell",
        description="Malicious PowerShell detected on endpoint",
        severity="critical",
        entities={},
        tags=["powershell", "malware"],
        raw_data={},
        metadata={},
        entity_context=EntityBehaviorContext(
            hostname="workstation-99.corp.local",
            username="jdoe",
            src_ip="10.0.0.42",
        ),
    )

    # Route signal
    router = SignalRouter()
    routed_signal = router.route(signal)

    # Verify entity extraction
    assert "hostname" in routed_signal.entities
    assert "workstation-99.corp.local" in routed_signal.entities["hostname"]

    # Verify metadata enrichment
    assert "signal_subtype" in routed_signal.metadata
    assert routed_signal.metadata["signal_subtype"] == "endpoint"
    assert "entity_focus_primary" in routed_signal.metadata

    print(f"✓ SignalRouter normalized signal: {routed_signal.signal_id}")
    print(f"  Subtype: {routed_signal.metadata['signal_subtype']}")
    print(f"  Entities: {list(routed_signal.entities.keys())}")


def test_governance_gate():
    """Test GovernanceGate evaluates actions against policies."""

    # Create test actions
    actions = [
        Action(
            action_id="A1",
            action_type=ActionType.INVESTIGATE,
            priority=1,
            title="Review logs",
            description="Check SIEM logs",
            steps=["Open SIEM", "Query logs"],
            reasoning="Standard investigation",
            source="template",
            confidence=0.9,
        ),
        Action(
            action_id="A2",
            action_type=ActionType.ISOLATE,
            priority=2,
            title="Isolate host",
            description="Network isolation",
            steps=["Contact IR", "Execute isolation"],
            reasoning="High risk containment",
            source="contextual",
            confidence=0.85,
        ),
        Action(
            action_id="A3",
            action_type=ActionType.BLOCK,
            priority=2,
            title="Block IOC",
            description="Add to firewall blocklist",
            steps=["Update FW rules"],
            reasoning="Prevent further impact",
            source="contextual",
            confidence=0.6,  # Low confidence
        ),
    ]

    # Create classification (TRUE_POSITIVE)
    classification = ClassificationResult(
        disposition="TRUE_POSITIVE",
        tp_likelihood=0.85,
        severity="high",
        confidence="high",
        incident_type="Malware",
        triage_judgment="Confirmed malware",
    )

    # Create enrichments
    enrichments = {
        "threat_intel": EnrichmentResult(
            adapter="threat_intel",
            status=EnrichmentStatus.SUCCESS,
            data={"verdict": "malicious"},
        ),
        "cmdb": EnrichmentResult(
            adapter="cmdb",
            status=EnrichmentStatus.SUCCESS,
            data={"asset": "workstation"},
        ),
    }

    # Evaluate with governance gate
    gate = GovernanceGate()
    result = gate.evaluate(actions, classification, enrichments)

    # Verify categorization
    assert len(result.auto_execute) >= 1  # Investigate should auto-execute
    assert len(result.requires_approval) >= 1  # Isolate requires approval (high risk)
    assert len(result.blocked) == 0  # No blocks for TP

    # Check approval marking
    for action in result.requires_approval:
        assert "[APPROVAL:" in action.title or action.action_type == ActionType.ISOLATE

    print(f"✓ GovernanceGate evaluated {len(actions)} actions")
    print(f"  Auto-execute: {len(result.auto_execute)}")
    print(f"  Requires approval: {len(result.requires_approval)}")
    print(f"  Blocked: {len(result.blocked)}")


def test_governance_gate_fp_blocking():
    """Test GovernanceGate blocks containment on FALSE_POSITIVE."""

    # Containment action
    actions = [
        Action(
            action_id="A1",
            action_type=ActionType.ISOLATE,
            priority=2,
            title="Isolate host",
            description="Network isolation",
            steps=["Execute isolation"],
            reasoning="Containment",
            source="contextual",
            confidence=0.9,
        ),
    ]

    # FALSE_POSITIVE classification
    classification = ClassificationResult(
        disposition="FALSE_POSITIVE",
        tp_likelihood=0.08,
        severity="low",
        confidence="high",
        incident_type="Benign",
        triage_judgment="Benign activity",
    )

    enrichments = {
        "cmdb": EnrichmentResult(
            adapter="cmdb",
            status=EnrichmentStatus.SUCCESS,
            data={},
        ),
    }

    # Evaluate
    gate = GovernanceGate(auto_close_fp=True)
    result = gate.evaluate(actions, classification, enrichments)

    # Should auto-close FP
    assert result.auto_close is True
    assert "FP" in result.auto_close_reason

    print(f"✓ GovernanceGate auto-close FP: {result.auto_close_reason}")


if __name__ == "__main__":
    test_case_bootstrap()
    print()
    test_signal_router()
    print()
    test_governance_gate()
    print()
    test_governance_gate_fp_blocking()
    print("\n✅ All Phase 2 CKG tests passed!")
    print()
    test_governance_gate_fp_blocking()
    print("\n✅ All Phase 2 CKG tests passed!")
    print()
    test_governance_gate_fp_blocking()
    print("\n✅ All Phase 2 CKG tests passed!")
