"""Enrichment orchestration service."""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..adapters import BaseAdapter
from ..models import EnrichmentResult, Signal
from ..models.case_graph import (
    ObservationNode,
    ObservationType,
    Provenance,
    Scope,
    TriageContextGraph,
)
from ..models.enrichment import EnrichmentStatus


class EnrichmentService:
    """Service for orchestrating concurrent enrichments."""

    def __init__(self, adapters: List[BaseAdapter]):
        """Initialize with list of adapters.

        Args:
            adapters: List of enrichment adapters to use
        """
        self.adapters = adapters

    async def enrich_signal(self, signal: Signal) -> Dict[str, EnrichmentResult]:
        """Enrich a signal using all adapters concurrently.

        Args:
            signal: The signal to enrich

        Returns:
            Dictionary mapping adapter name to enrichment result
        """  # OPTIMIZATION: Extract baseline enrichments once, before calling adapters
        # This avoids parsing SOAR artifacts 5 times (once per adapter)
        from .case_artifact_harvester import CaseArtifactHarvester

        baseline_cache = CaseArtifactHarvester.extract_baseline_enrichments(signal)

        # Store baseline in signal metadata for adapters to access
        if baseline_cache and not signal.metadata.get("_baseline_cache"):
            signal.metadata["_baseline_cache"] = baseline_cache
            # Run all enrichments concurrently
        tasks = [adapter.enrich(signal) for adapter in self.adapters]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Map results to adapter names
        enrichments = {}
        for adapter, result in zip(self.adapters, results):
            if isinstance(result, Exception):
                # Handle adapter failures gracefully
                enrichments[adapter.name] = EnrichmentResult(
                    adapter=adapter.name,
                    status=EnrichmentStatus.FAILED,
                    error=str(result),
                    timestamp=datetime.utcnow(),
                )
            else:
                enrichments[adapter.name] = result

        return enrichments

    async def enrich_signal_ckg(
        self, signal: Signal, graph: Optional[TriageContextGraph] = None
    ) -> Dict[str, EnrichmentResult]:
        """Enrich a signal and write observation nodes to graph.

        Args:
            signal: The signal to enrich
            graph: Optional graph to write observations to

        Returns:
            Dictionary mapping adapter name to enrichment result
        """
        # Run standard enrichment
        enrichments = await self.enrich_signal(signal)

        # Write observation nodes to graph if provided
        if graph:
            self._write_observations_to_graph(signal, enrichments, graph)

        return enrichments

    def _write_observations_to_graph(
        self,
        signal: Signal,
        enrichments: Dict[str, EnrichmentResult],
        graph: TriageContextGraph,
    ) -> None:
        """Write enrichment results as observation nodes to graph.

        Args:
            signal: The signal that was enriched
            enrichments: Enrichment results to write
            graph: Graph to write observations to
        """
        for adapter_name, result in enrichments.items():
            if result.status == EnrichmentStatus.SUCCESS:
                # Map adapter names to observation types
                observation_type = self._map_adapter_to_observation_type(adapter_name)

                observation_node = ObservationNode(
                    node_id=f"obs_{adapter_name}_{signal.signal_id}_{int(datetime.now().timestamp())}",
                    observation_type=observation_type,
                    scope=Scope(
                        time_window_start=result.timestamp,
                        time_window_end=result.timestamp,
                    ),
                    provenance=Provenance(
                        source_system=adapter_name,
                        confidence=0.8,
                        evidence_refs=[f"signal_id:{signal.signal_id}"],
                        fetched_at=result.timestamp,
                        query_fingerprint=f"enrich_{adapter_name}",
                        ttl_seconds=3600,
                    ),
                    properties={
                        "adapter_name": adapter_name,
                        "enrichment_data": (
                            result.data if hasattr(result, "data") else {}
                        ),
                        "status": result.status.value,
                    },
                )

                graph.add_node(observation_node)

                # Add edge from case to observation
                from ..models.case_graph import NodeType

                case_nodes = graph.get_nodes_by_type(NodeType.CASE)
                if case_nodes:
                    from ..models.case_graph import EdgeType, EvidenceEdge

                    edge = EvidenceEdge(
                        edge_id=f"case_obs_{observation_node.node_id}",
                        edge_type=EdgeType.HAS_OBSERVATION,
                        source_node_id=case_nodes[0].node_id,
                        target_node_id=observation_node.node_id,
                        provenance=Provenance(
                            source_system="EnrichmentService",
                            confidence=0.9,
                            query_fingerprint="case_observation_link",
                            ttl_seconds=3600,
                        ),
                    )
                    graph.add_edge(edge)

    def _map_adapter_to_observation_type(self, adapter_name: str) -> ObservationType:
        """Map adapter name to observation type.

        Args:
            adapter_name: Name of the adapter

        Returns:
            Corresponding observation type
        """
        adapter_lower = adapter_name.lower()

        if (
            "threat" in adapter_lower
            or "intel" in adapter_lower
            or "ti" in adapter_lower
        ):
            return ObservationType.THREAT_INTEL
        elif (
            "vuln" in adapter_lower
            or "vulnerability" in adapter_lower
            or "cve" in adapter_lower
        ):
            return ObservationType.VULNERABILITY
        elif "cmdb" in adapter_lower or "asset" in adapter_lower:
            return ObservationType.CMDB_ASSET
        elif (
            "identity" in adapter_lower
            or "user" in adapter_lower
            or "ad" in adapter_lower
        ):
            return ObservationType.IDENTITY_CONTEXT
        elif "edr" in adapter_lower or "endpoint" in adapter_lower:
            return ObservationType.EDR_TELEMETRY
        elif "siem" in adapter_lower:
            return ObservationType.SIEM_HIT
        elif "network" in adapter_lower or "ndr" in adapter_lower:
            return ObservationType.NETWORK_TELEMETRY
        else:
            return ObservationType.SIEM_HIT  # Default

    async def health_check(self) -> Dict[str, bool]:
        """Check health of all adapters.

        Returns:
            Dictionary mapping adapter name to health status
        """
        tasks = [adapter.health_check() for adapter in self.adapters]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        health_status = {}
        for adapter, result in zip(self.adapters, results):
            if isinstance(result, Exception):
                health_status[adapter.name] = False
            else:
                health_status[adapter.name] = result

        return health_status
        return health_status
        return health_status
