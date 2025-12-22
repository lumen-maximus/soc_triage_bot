"""Test CKG Phase 3 services: DetectionResolver."""

import asyncio
from datetime import datetime, timezone

from soc_triage_bot.models import Signal, SignalSource, SignalType
from soc_triage_bot.models.case_graph import NodeType, TriageMode
from soc_triage_bot.models.signal import ArtifactContext
from soc_triage_bot.services.case_bootstrap import CaseBootstrapService
from soc_triage_bot.services.detection_resolver import DetectionResolver


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


async def main():
    await test_detection_resolver()
    print("\n✅ All Phase 3 CKG tests passed!")


if __name__ == "__main__":
    asyncio.run(main())
