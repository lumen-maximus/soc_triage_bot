"""Test CKG Phase 3 services: DetectionResolver, FetchPlanner."""

import asyncio
from datetime import datetime, timezone

from soc_triage_bot.models import Signal, SignalSource, SignalType
from soc_triage_bot.models.case_graph import NodeType, TriageMode
from soc_triage_bot.models.signal import ArtifactContext, EntityBehaviorContext
from soc_triage_bot.services.case_bootstrap import CaseBootstrapService
from soc_triage_bot.services.detection_resolver import DetectionResolver
from soc_triage_bot.services.fetch_planner import FetchPlanner


async def test_detection_resolver():
    """Test DetectionResolver checks for detection presence."""

    # Create IOC signal
    signal = Signal(
        signal_id="IOC-001",
        signal_type=SignalType.IOC,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(system="ThreatFeed", rule_id="IOC-Feed"),
        title="Malicious IP detected",
        description="Known C2 IP observed",
        severity="high",
        entities={},
        tags=["ioc", "c2"],
        raw_data={},
        metadata={},
        artifact_context=ArtifactContext(
            ip="192.0.2.1",
        ),
    )

    # Bootstrap graph
    bootstrap = CaseBootstrapService()
    graph = bootstrap.bootstrap(signal, mode=TriageMode.MIN_DELTA)

    # Resolve detection
    resolver = DetectionResolver()
    result = await resolver.resolve(signal, graph)

    # Verify observation added to graph
    obs_nodes = graph.get_nodes_by_type(NodeType.OBSERVATION)
    assert len(obs_nodes) >= 1

    print(f"✓ DetectionResolver checked IOC: {signal.signal_id}")
    print(f"  Detection present: {result.detection_present}")
    print(f"  Observations in graph: {len(obs_nodes)}")


def test_fetch_planner():
    """Test FetchPlanner computes delta enrichment plan."""

    # Create signal with entities
    signal = Signal(
        signal_id="ALERT-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(system="SIEM", rule_id="R-123"),
        title="Suspicious activity",
        description="Malware detected",
        severity="high",
        entities={},
        tags=["malware"],
        raw_data={},
        metadata={},
        entity_context=EntityBehaviorContext(
            hostname="workstation-50.corp.local",
            username="alice",
            src_ip="10.0.0.50",
        ),
        artifact_context=ArtifactContext(
            sha256="abc123def456",
        ),
    )

    # Bootstrap graph
    bootstrap = CaseBootstrapService()
    graph = bootstrap.bootstrap(signal, mode=TriageMode.MIN_DELTA)

    # Plan enrichment
    planner = FetchPlanner()
    plan = planner.plan(signal, graph)

    # Verify plan has delta fetches
    assert plan.total_calls() > 0
    print("✓ FetchPlanner computed enrichment plan")
    print(f"  TI lookups: {len(plan.ti_lookups)}")
    print(f"  CMDB queries: {len(plan.cmdb_queries)}")
    print(f"  Total calls: {plan.total_calls()}")


def test_fetch_planner_budget():
    """Test FetchPlanner respects budget constraints."""

    # Create signal with many entities
    signal = Signal(
        signal_id="ALERT-002",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(system="SIEM", rule_id="R-456"),
        title="Mass scanning",
        description="Port scan detected",
        severity="medium",
        entities={
            "hostname": ["host1", "host2", "host3"],
            "ip": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        },
        tags=["scan"],
        raw_data={},
        metadata={},
    )

    # Bootstrap with REUSE_ONLY mode (strict budget)
    bootstrap = CaseBootstrapService()
    graph = bootstrap.bootstrap(signal, mode=TriageMode.REUSE_ONLY)

    # Plan enrichment
    planner = FetchPlanner()
    plan = planner.plan(signal, graph)

    # Verify budget constraints applied
    assert len(plan.ti_lookups) <= graph.budget.max_ti_lookups
    print("✓ FetchPlanner respected budget constraints")
    print(
        f"  Budget max TI: {graph.budget.max_ti_lookups}, Planned: {len(plan.ti_lookups)}"
    )
    print(f"  Budget max adapters: {graph.budget.max_enrichment_adapters}")


async def main():
    await test_detection_resolver()
    print()
    test_fetch_planner()
    print()
    test_fetch_planner_budget()
    print("\n✅ All Phase 3 CKG tests passed!")


if __name__ == "__main__":
    asyncio.run(main())
