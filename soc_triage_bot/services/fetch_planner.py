"""FetchPlanner - Compute delta-only enrichment plan.

Analyzes what enrichment data already exists in graph and computes
minimal delta to fetch. Avoids redundant API calls.
"""

from datetime import datetime
from typing import Dict, List, Set

from soc_triage_bot.models.case_graph import (
    EntityNode,
    EntityType,
    NodeType,
    TriageContextGraph,
)
from soc_triage_bot.models.signal import Signal


class EnrichmentPlan:
    """Enrichment plan with delta computation."""

    def __init__(self):
        self.ti_lookups: List[Dict[str, str]] = []  # {ioc_type, ioc_value}
        self.cmdb_queries: List[str] = []  # hostnames
        self.vuln_scans: List[str] = []  # hostnames
        self.edr_queries: List[str] = []  # hostnames
        self.skip_reason: Dict[str, str] = {}  # adapter -> reason

    def total_calls(self) -> int:
        """Total API calls planned."""
        return (
            len(self.ti_lookups)
            + len(self.cmdb_queries)
            + len(self.vuln_scans)
            + len(self.edr_queries)
        )


class FetchPlanner:
    """Compute delta-only enrichment plan.

    Checks graph for existing enrichment data and only plans fetches
    for missing data. Respects budget constraints from graph.
    """

    def __init__(self, ttl_seconds: int = 3600):
        """Initialize fetch planner.

        Args:
            ttl_seconds: Consider cached data valid if fresher than this
        """
        self.ttl_seconds = ttl_seconds

    def plan(
        self,
        signal: Signal,
        graph: TriageContextGraph,
    ) -> EnrichmentPlan:
        """Compute enrichment plan for signal.

        Args:
            signal: Signal to enrich
            graph: Current graph state

        Returns:
            EnrichmentPlan with delta fetches
        """
        plan = EnrichmentPlan()

        # Extract entities from graph
        existing_entities = self._get_existing_entities(graph)

        # Extract entities from signal
        signal_entities = self._extract_signal_entities(signal)

        # Plan TI lookups for IOCs
        plan.ti_lookups = self._plan_ti_lookups(signal, existing_entities, graph)

        # Plan CMDB queries for hosts
        plan.cmdb_queries = self._plan_cmdb_queries(
            signal_entities.get("hostnames", []),
            existing_entities.get(EntityType.HOST, set()),
            graph,
        )

        # Plan vulnerability scans
        plan.vuln_scans = self._plan_vuln_scans(
            signal_entities.get("hostnames", []),
            existing_entities.get(EntityType.HOST, set()),
            graph,
        )

        # Plan EDR queries
        plan.edr_queries = self._plan_edr_queries(
            signal_entities.get("hostnames", []),
            existing_entities.get(EntityType.HOST, set()),
            graph,
        )

        # Apply budget constraints
        plan = self._apply_budget(plan, graph)

        return plan

    def _get_existing_entities(
        self, graph: TriageContextGraph
    ) -> Dict[EntityType, Set[str]]:
        """Get entities already in graph."""
        entities: Dict[EntityType, Set[str]] = {}

        entity_nodes = graph.get_nodes_by_type(NodeType.ENTITY)

        for node in entity_nodes:
            if isinstance(node, EntityNode):
                entity_type = node.entity_type
                entity_value = node.entity_value

                # Check if data is fresh
                if hasattr(node, "provenance"):
                    age = (
                        datetime.utcnow() - node.provenance.fetched_at
                    ).total_seconds()
                    if age > self.ttl_seconds:
                        continue  # Stale data

                entities.setdefault(entity_type, set()).add(entity_value)

        return entities

    def _extract_signal_entities(self, signal: Signal) -> Dict[str, List[str]]:
        """Extract entities from signal."""
        entities: Dict[str, List[str]] = {
            "hostnames": [],
            "iocs": [],
            "users": [],
            "ips": [],
        }

        # Extract from entity_context
        if signal.entity_context:
            if signal.entity_context.hostname:
                entities["hostnames"].append(signal.entity_context.hostname)
            if signal.entity_context.username:
                entities["users"].append(signal.entity_context.username)
            if signal.entity_context.src_ip:
                entities["ips"].append(signal.entity_context.src_ip)

        # Extract IOCs from artifact_context
        if signal.artifact_context:
            for attr in ["sha256", "md5", "ip", "domain", "url"]:
                val = getattr(signal.artifact_context, attr, None)
                if val:
                    entities["iocs"].append(val)

        # Extract from entities dict
        for entity_type, values in signal.entities.items():
            if entity_type == "hostname":
                entities["hostnames"].extend(values)
            elif entity_type in ["hash", "ip", "domain", "url"]:
                entities["iocs"].extend(values)
            elif entity_type == "username":
                entities["users"].extend(values)

        return entities

    def _plan_ti_lookups(
        self,
        signal: Signal,
        existing_entities: Dict[EntityType, Set[str]],
        graph: TriageContextGraph,
    ) -> List[Dict[str, str]]:
        """Plan threat intel lookups for IOCs."""
        lookups = []

        # Get existing IOCs (file_hash, domain, url, ip)
        existing_iocs = (
            existing_entities.get(EntityType.FILE_HASH, set())
            | existing_entities.get(EntityType.DOMAIN, set())
            | existing_entities.get(EntityType.URL, set())
            | existing_entities.get(EntityType.IP, set())
        )

        # Extract IOCs from signal
        if signal.artifact_context:
            for attr in ["sha256", "md5", "ip", "domain", "url"]:
                val = getattr(signal.artifact_context, attr, None)
                if val and val not in existing_iocs:
                    lookups.append({"ioc_type": attr, "ioc_value": val})

        return lookups

    def _plan_cmdb_queries(
        self,
        hostnames: List[str],
        existing_hosts: Set[str],
        graph: TriageContextGraph,
    ) -> List[str]:
        """Plan CMDB queries for asset data."""
        queries = []

        for hostname in hostnames:
            if hostname not in existing_hosts:
                queries.append(hostname)

        return queries

    def _plan_vuln_scans(
        self,
        hostnames: List[str],
        existing_hosts: Set[str],
        graph: TriageContextGraph,
    ) -> List[str]:
        """Plan vulnerability scans."""
        scans = []

        # Only scan hosts we don't have vuln data for
        for hostname in hostnames:
            # Check if we have recent vuln observations
            has_vuln_data = False
            obs_nodes = graph.get_nodes_by_type(NodeType.OBSERVATION)

            for node in obs_nodes:
                # Type check for ObservationNode
                from soc_triage_bot.models.case_graph import ObservationNode

                if isinstance(node, ObservationNode):
                    if "vuln" in str(node.observation_type).lower():
                        has_vuln_data = True
                        break

            if not has_vuln_data:
                scans.append(hostname)

        return scans

    def _plan_edr_queries(
        self,
        hostnames: List[str],
        existing_hosts: Set[str],
        graph: TriageContextGraph,
    ) -> List[str]:
        """Plan EDR queries for endpoint data."""
        queries = []

        for hostname in hostnames:
            # Check if we have recent EDR observations
            has_edr_data = False
            obs_nodes = graph.get_nodes_by_type(NodeType.OBSERVATION)

            for node in obs_nodes:
                if hasattr(node, "provenance"):
                    if "EDR" in node.provenance.source_system:
                        age = (
                            datetime.utcnow() - node.provenance.fetched_at
                        ).total_seconds()
                        if age <= self.ttl_seconds:
                            has_edr_data = True
                            break

            if not has_edr_data:
                queries.append(hostname)

        return queries

    def _apply_budget(
        self, plan: EnrichmentPlan, graph: TriageContextGraph
    ) -> EnrichmentPlan:
        """Apply budget constraints to plan."""
        budget = graph.budget

        # Cap TI lookups
        if len(plan.ti_lookups) > budget.max_ti_lookups:
            plan.ti_lookups = plan.ti_lookups[: budget.max_ti_lookups]
            plan.skip_reason["threat_intel"] = f"Budget limit: {budget.max_ti_lookups}"

        # Cap enrichment adapters
        active_adapters = sum(
            [
                1 if plan.ti_lookups else 0,
                1 if plan.cmdb_queries else 0,
                1 if plan.vuln_scans else 0,
                1 if plan.edr_queries else 0,
            ]
        )

        if active_adapters > budget.max_enrichment_adapters:
            # Prioritize: TI > CMDB > VULN > EDR
            if not plan.ti_lookups:
                plan.edr_queries = []
            if active_adapters > budget.max_enrichment_adapters:
                plan.vuln_scans = []

        return plan
