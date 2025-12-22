"""DetectionResolver - Validate telemetry presence for IOC/CVE signals.

Checks if telemetry exists in SIEM/EDR for IOCs and vulnerabilities before
triggering expensive hunting queries. Conditional gate: only run hunting if
detection is absent.
"""

from datetime import datetime, timedelta
from typing import List, Optional

from soc_triage_bot.adapters.edr import EDRAdapter
from soc_triage_bot.adapters.siem import SIEMAdapter
from soc_triage_bot.models.case_graph import (
    EdgeType,
    EvidenceEdge,
    NodeType,
    ObservationNode,
    ObservationType,
    Provenance,
    Scope,
    TriageContextGraph,
)
from soc_triage_bot.models.signal import Signal, SignalType


class DetectionResult:
    """Result of detection resolution."""

    def __init__(
        self,
        detection_present: bool,
        hit_count: int = 0,
        sensor_coverage: Optional[List[str]] = None,
        time_window_start: Optional[datetime] = None,
        time_window_end: Optional[datetime] = None,
        evidence_refs: Optional[List[str]] = None,
    ):
        self.detection_present = detection_present
        self.hit_count = hit_count
        self.sensor_coverage = sensor_coverage or []
        self.time_window_start = time_window_start
        self.time_window_end = time_window_end
        self.evidence_refs = evidence_refs or []


class DetectionResolver:
    """Resolve whether detection telemetry exists for IOC/vuln signals.

    For IOC signals: Check if IOC triggered any detections in SIEM/EDR
    For CVE signals: Check if vulnerable host shows exploitation attempts

    Adds ObservationNode to graph with detection presence/absence.
    """

    def __init__(
        self,
        siem_adapter: Optional[SIEMAdapter] = None,
        edr_adapter: Optional[EDRAdapter] = None,
        lookback_hours: int = 72,
    ):
        """Initialize detection resolver.

        Args:
            siem_adapter: SIEM adapter for querying detections
            edr_adapter: EDR adapter for endpoint telemetry
            lookback_hours: How far back to search for detections
        """
        self.siem_adapter = siem_adapter
        self.edr_adapter = edr_adapter
        self.lookback_hours = lookback_hours

    async def resolve(
        self,
        signal: Signal,
        graph: TriageContextGraph,
    ) -> DetectionResult:
        """Resolve detection presence for signal.

        Args:
            signal: Signal to check
            graph: Case knowledge graph to update

        Returns:
            DetectionResult with presence info
        """
        # Only apply to IOC and CVE signals
        if signal.signal_type not in [SignalType.IOC, SignalType.CVE]:
            return DetectionResult(detection_present=True)  # N/A for ALERT signals

        result = DetectionResult(detection_present=False)

        if signal.signal_type == SignalType.IOC:
            result = await self._resolve_ioc_detection(signal)
        elif signal.signal_type == SignalType.CVE:
            result = await self._resolve_cve_exploitation(signal)

        # Add observation to graph
        self._add_observation_to_graph(signal, graph, result)

        return result

    async def _resolve_ioc_detection(self, signal: Signal) -> DetectionResult:
        """Check if IOC has triggered detections."""
        if not self.siem_adapter:
            return DetectionResult(detection_present=False)

        # Extract IOC from signal
        ioc_value = None

        if signal.artifact_context:
            for attr in ["sha256", "md5", "ip", "domain", "url"]:
                val = getattr(signal.artifact_context, attr, None)
                if val:
                    ioc_value = val
                    break

        if not ioc_value:
            return DetectionResult(detection_present=False)

        # Query SIEM for detections matching IOC
        time_window_end = datetime.utcnow()
        time_window_start = time_window_end - timedelta(hours=self.lookback_hours)

        try:
            # Mock query - real implementation would call SIEM adapter
            # hits = await self.siem_adapter.query_ioc_detections(
            #     ioc_value=ioc_value,
            #     ioc_type=ioc_type,
            #     start_time=time_window_start,
            #     end_time=time_window_end,
            # )

            # Placeholder: assume no detection for now
            hits = []

            if hits:
                return DetectionResult(
                    detection_present=True,
                    hit_count=len(hits),
                    sensor_coverage=["SIEM"],
                    time_window_start=time_window_start,
                    time_window_end=time_window_end,
                    evidence_refs=[f"siem_hit_{i}" for i in range(len(hits))],
                )
        except Exception:
            pass

        return DetectionResult(
            detection_present=False,
            sensor_coverage=[],
            time_window_start=time_window_start,
            time_window_end=time_window_end,
        )

    async def _resolve_cve_exploitation(self, signal: Signal) -> DetectionResult:
        """Check if vulnerable host shows exploitation attempts."""
        if not self.siem_adapter and not self.edr_adapter:
            return DetectionResult(detection_present=False)

        # Extract CVE and hostname
        cve_id = None
        hostname = None

        if signal.vuln_context:
            cve_id = signal.vuln_context.cve_id

        if signal.entity_context:
            hostname = signal.entity_context.hostname

        if not cve_id or not hostname:
            return DetectionResult(detection_present=False)

        # Query for exploitation indicators
        time_window_end = datetime.utcnow()
        time_window_start = time_window_end - timedelta(hours=self.lookback_hours)

        try:
            # Mock query - real implementation would search for exploitation patterns
            # exploitation_events = await self.siem_adapter.query_cve_exploitation(
            #     cve_id=cve_id,
            #     hostname=hostname,
            #     start_time=time_window_start,
            #     end_time=time_window_end,
            # )

            exploitation_events = []

            if exploitation_events:
                return DetectionResult(
                    detection_present=True,
                    hit_count=len(exploitation_events),
                    sensor_coverage=["SIEM", "EDR"],
                    time_window_start=time_window_start,
                    time_window_end=time_window_end,
                    evidence_refs=[
                        f"exploit_{i}" for i in range(len(exploitation_events))
                    ],
                )
        except Exception:
            pass

        return DetectionResult(
            detection_present=False,
            sensor_coverage=[],
            time_window_start=time_window_start,
            time_window_end=time_window_end,
        )

    def _add_observation_to_graph(
        self,
        signal: Signal,
        graph: TriageContextGraph,
        result: DetectionResult,
    ) -> None:
        """Add detection observation to graph."""
        provenance = Provenance(
            source_system="DetectionResolver",
            query_fingerprint=f"detection_check_{signal.signal_id}",
            ttl_seconds=3600,
            confidence=1.0 if result.detection_present else 0.0,
            evidence_refs=result.evidence_refs,
        )

        scope = Scope(
            time_window_start=result.time_window_start,
            time_window_end=result.time_window_end,
            sensor_coverage=result.sensor_coverage,
        )

        obs_type = (
            ObservationType.DETECTION_PRESENCE
            if result.detection_present
            else ObservationType.SIEM_HIT  # Use SIEM_HIT for absence context
        )

        obs_node = ObservationNode(
            node_id=f"obs_detection_{signal.signal_id}",
            node_type=NodeType.OBSERVATION,
            observation_type=obs_type,
            provenance=provenance,
            scope=scope,
            hit_count=result.hit_count,
        )

        graph.add_node(obs_node)

        # Link signal → observation
        signal_node_id = f"signal_{signal.signal_id}"
        edge = EvidenceEdge(
            edge_id=f"edge_{signal_node_id}_has_obs",
            edge_type=EdgeType.HAS_OBSERVATION,
            source_node_id=signal_node_id,
            target_node_id=obs_node.node_id,
            provenance=provenance,
        )
        graph.add_edge(edge)
