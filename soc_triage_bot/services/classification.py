"""Classification service for TP/FP determination.

Supports multi-track forecast consumption with per-track anomaly checks.
Generates ClassificationResult with MITRE mapping and structured reasoning.
"""

from typing import Any, Dict, List, Optional

from ..models import ClassificationLabel, EnrichmentResult, Signal
from ..models.case_graph import (
    EdgeType,
    EvidenceEdge,
    NodeType,
    OutcomeNode,
    Provenance,
    TriageContextGraph,
)
from ..models.triage_report import ClassificationResult, ForecastBundle, MitreMapping


class ClassificationService:
    """Service for deterministic TP/FP classification.

    Multi-track forecasting support:
    - Consumes ForecastBundle with tracks (rule, ioc, entity)
    - Per-track anomaly scoring with weighted combination
    - Evidence ID citations in reasoning
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize classification service.

        Args:
            config: Configuration for classification rules
        """
        self.config = config or {}
        self.tp_confidence_threshold = self.config.get("tp_confidence", 0.7)
        self.fp_confidence_threshold = self.config.get("fp_confidence", 0.7)

        # Track anomaly weights (priority: rule > ioc > entity)
        self.track_weights = self.config.get(
            "track_weights",
            {"rule": 1.5, "ioc": 1.2, "entity": 1.0},
        )

    def classify_extended(
        self,
        signal: Signal,
        enrichments: Dict[str, EnrichmentResult],
        similar_cases: List[tuple],
        forecast: Optional[ForecastBundle] = None,
    ) -> ClassificationResult:
        """Classify signal with extended multi-track support.

        Args:
            signal: The signal to classify
            enrichments: Enrichment results with evidence_ids
            similar_cases: List of (case_id, similarity, outcome) tuples
            forecast: Multi-track ForecastBundle

        Returns:
            ClassificationResult with MITRE mapping and reasons_tp/reasons_fp
        """
        reasons_tp: List[str] = []
        reasons_fp: List[str] = []
        factors: Dict[str, float] = {}

        # Check threat intelligence (with evidence_id)
        ti_factor = self._check_threat_intel_extended(
            enrichments, reasons_tp, reasons_fp
        )
        factors["threat_intel"] = ti_factor

        # Check vulnerability data
        vuln_factor = self._check_vulnerabilities_extended(
            enrichments, reasons_tp, reasons_fp
        )
        factors["vulnerability"] = vuln_factor

        # Check multi-track forecast anomaly
        if forecast and forecast.enabled:
            anomaly_factor = self._check_multi_track_anomaly(
                forecast, reasons_tp, reasons_fp
            )
            factors["anomaly"] = anomaly_factor

        # Check historical FP rate
        fp_rate = self._check_historical_fp_rate_extended(enrichments, reasons_fp)
        factors["historical_fp_rate"] = 1.0 - fp_rate

        # Check similar cases (with outcome analysis)
        similar_factor = self._check_similar_cases_extended(
            similar_cases, reasons_tp, reasons_fp
        )
        factors["similar_cases"] = similar_factor

        # Check asset criticality
        criticality_factor = self._check_asset_criticality_extended(
            enrichments, reasons_tp
        )
        factors["asset_criticality"] = criticality_factor

        # Calculate overall TP likelihood
        tp_likelihood = self._calculate_tp_likelihood(factors)

        # Determine disposition
        disposition = self._determine_disposition(tp_likelihood, factors)

        # Generate MITRE mapping (simplified - would use detection rule metadata)
        mitre = self._generate_mitre_mapping(signal)

        # Determine severity
        severity = self._determine_severity(signal, factors)

        # Generate triage judgment
        triage_judgment = self._generate_triage_judgment(
            disposition, tp_likelihood, reasons_tp, reasons_fp
        )

        return ClassificationResult(
            disposition=disposition,
            tp_likelihood=tp_likelihood,
            severity=severity,
            confidence=self._likelihood_to_confidence(tp_likelihood),
            reasons_tp=reasons_tp,
            reasons_fp=reasons_fp,
            mitre=mitre,
            incident_type=self._determine_incident_type(signal, mitre),
            triage_judgment=triage_judgment,
        )

    def classify_extended_ckg(
        self,
        signal: Signal,
        enrichments: Dict[str, EnrichmentResult],
        similar_cases: List[tuple],
        forecast: Optional[ForecastBundle] = None,
        graph: Optional[TriageContextGraph] = None,
    ) -> ClassificationResult:
        """Classify signal with CKG graph writing.

        Args:
            signal: The signal to classify
            enrichments: Enrichment results with evidence_ids
            similar_cases: List of (case_id, similarity, outcome) tuples
            forecast: Multi-track ForecastBundle
            graph: Optional graph to write outcome node to

        Returns:
            ClassificationResult with outcome written to graph
        """
        # Run standard classification
        result = self.classify_extended(signal, enrichments, similar_cases, forecast)

        # Write outcome node to graph if provided
        if graph:
            self._write_outcome_to_graph(signal, result, graph)

        return result

    def _check_threat_intel_extended(
        self,
        enrichments: Dict[str, EnrichmentResult],
        reasons_tp: List[str],
        reasons_fp: List[str],
    ) -> float:
        """Check threat intelligence with evidence_id citation."""
        ti_result = enrichments.get("threat_intel")
        if not ti_result or ti_result.status.value != "success":
            return 0.5

        evidence_id = ti_result.evidence_id or "TI-001"
        data = ti_result.data
        reputation = data.get("reputation", "unknown")
        matches = data.get("matches_found", 0)

        if reputation == "malicious" or matches > 0:
            reasons_tp.append(
                f"Threat intel: {matches} malicious indicators found [{evidence_id}]"
            )
            return 0.9
        elif reputation == "suspicious":
            reasons_tp.append(
                f"Threat intel: suspicious indicators detected [{evidence_id}]"
            )
            return 0.7
        elif reputation == "clean":
            reasons_fp.append(
                f"Threat intel: indicators are clean/benign [{evidence_id}]"
            )
            return 0.3

        return 0.5

    def _check_vulnerabilities_extended(
        self,
        enrichments: Dict[str, EnrichmentResult],
        reasons_tp: List[str],
        reasons_fp: List[str],
    ) -> float:
        """Check vulnerability enrichment with evidence citation."""
        vuln_result = enrichments.get("vulnerability")
        if not vuln_result or vuln_result.status.value != "success":
            return 0.5

        evidence_id = vuln_result.evidence_id or "VULN-001"
        data = vuln_result.data
        critical_vulns = data.get("critical_vulns", 0)
        exploits = data.get("exploits_available", 0)

        if critical_vulns > 0 and exploits > 0:
            reasons_tp.append(
                f"{critical_vulns} critical vulns with public exploits [{evidence_id}]"
            )
            return 0.8
        elif critical_vulns > 0:
            reasons_tp.append(
                f"{critical_vulns} critical vulnerabilities present [{evidence_id}]"
            )
            return 0.7
        elif critical_vulns == 0:
            reasons_fp.append(f"No critical vulnerabilities on target [{evidence_id}]")
            return 0.4

        return 0.5

    def _check_multi_track_anomaly(
        self,
        forecast: ForecastBundle,
        reasons_tp: List[str],
        reasons_fp: List[str],
    ) -> float:
        """Check anomaly scores across all forecast tracks.

        Weighted combination: rule > ioc > entity
        """
        track_scores = []
        weights_used = []

        tracks = forecast.tracks
        for track_name, track in [
            ("rule", tracks.rule),
            ("ioc", tracks.ioc),
            ("entity", tracks.entity),
        ]:
            if track and track.latest and track.latest.anomaly_score is not None:
                score = track.latest.anomaly_score
                weight = self.track_weights.get(track_name, 1.0)
                track_scores.append(score * weight)
                weights_used.append(weight)

                # Add reasoning based on anomaly level
                if score > 0.8:
                    reasons_tp.append(
                        f"Track {track_name}: highly anomalous ({score:.2f}) - {track.latest.current_vs_expected}"
                    )
                elif score > 0.5:
                    reasons_tp.append(
                        f"Track {track_name}: moderately elevated ({score:.2f})"
                    )
                elif score < 0.2:
                    reasons_fp.append(
                        f"Track {track_name}: within normal range ({score:.2f})"
                    )

        if not track_scores:
            return 0.5

        # Weighted average
        combined_score = sum(track_scores) / sum(weights_used)
        return min(max(combined_score, 0.0), 1.0)

    def _check_historical_fp_rate_extended(
        self,
        enrichments: Dict[str, EnrichmentResult],
        reasons_fp: List[str],
    ) -> float:
        """Check historical false positive rate."""
        siem_result = enrichments.get("siem")
        if not siem_result or siem_result.status.value != "success":
            return 0.5

        evidence_id = siem_result.evidence_id or "SIEM-001"
        fp_rate = siem_result.data.get("historical_fp_rate", 0.5)

        if fp_rate > 0.7:
            reasons_fp.append(
                f"High historical FP rate ({fp_rate*100:.0f}%) for this rule [{evidence_id}]"
            )
        elif fp_rate > 0.5:
            reasons_fp.append(
                f"Moderate historical FP rate ({fp_rate*100:.0f}%) [{evidence_id}]"
            )

        return fp_rate

    def _check_similar_cases_extended(
        self,
        similar_cases: List[tuple],
        reasons_tp: List[str],
        reasons_fp: List[str],
    ) -> float:
        """Check similar historical cases with outcome analysis."""
        if not similar_cases:
            return 0.5

        # Analyze outcomes if available (case_id, similarity, outcome)
        tp_count = 0
        fp_count = 0
        total_sim = 0

        for case in similar_cases:
            case_id = case[0]
            similarity = case[1]
            outcome = case[2] if len(case) > 2 else None

            total_sim += similarity
            if outcome == "TP":
                tp_count += 1
            elif outcome == "FP":
                fp_count += 1

        avg_similarity = total_sim / len(similar_cases)

        if tp_count > fp_count and avg_similarity > 0.7:
            reasons_tp.append(
                f"Similar to {tp_count} past TP cases (avg similarity: {avg_similarity:.2f})"
            )
            return 0.8
        elif fp_count > tp_count and avg_similarity > 0.7:
            reasons_fp.append(
                f"Similar to {fp_count} past FP cases (avg similarity: {avg_similarity:.2f})"
            )
            return 0.3
        elif len(similar_cases) > 0:
            reasons_tp.append(f"Similar to {len(similar_cases)} past cases")
            return 0.6

        return 0.5

    def _check_asset_criticality_extended(
        self,
        enrichments: Dict[str, EnrichmentResult],
        reasons_tp: List[str],
    ) -> float:
        """Check asset criticality from CMDB."""
        cmdb_result = enrichments.get("cmdb")
        if not cmdb_result or cmdb_result.status.value != "success":
            return 0.5

        evidence_id = cmdb_result.evidence_id or "CMDB-001"
        data = cmdb_result.data
        host_assets = data.get("host_assets", {})

        for hostname, asset_data in host_assets.items():
            criticality = asset_data.get("business_criticality", "medium")
            if criticality in ["critical", "high"]:
                reasons_tp.append(
                    f"Critical asset involved: {hostname} [{evidence_id}]"
                )
                return 0.7

        return 0.5

    def _calculate_tp_likelihood(self, factors: Dict[str, float]) -> float:
        """Calculate TP likelihood from weighted factors."""
        if not factors:
            return 0.5

        weights = {
            "threat_intel": 1.5,
            "vulnerability": 1.2,
            "anomaly": 1.0,
            "historical_fp_rate": 0.8,
            "similar_cases": 1.0,
            "asset_criticality": 0.8,
        }

        weighted_sum = sum(factors.get(k, 0.5) * weights.get(k, 1.0) for k in weights)
        total_weight = sum(weights.values())

        return min(max(weighted_sum / total_weight, 0.0), 1.0)

    def _determine_disposition(
        self, tp_likelihood: float, factors: Dict[str, float]
    ) -> str:
        """Determine disposition string."""
        if tp_likelihood >= 0.8:
            return "Likely True Positive"
        elif tp_likelihood >= 0.6:
            return "Possible True Positive"
        elif tp_likelihood <= 0.3:
            return "Likely False Positive"
        elif tp_likelihood <= 0.5:
            return "Possible False Positive"
        else:
            return "Inconclusive"

    def _likelihood_to_confidence(self, tp_likelihood: float) -> str:
        """Convert likelihood to confidence string."""
        if tp_likelihood >= 0.8 or tp_likelihood <= 0.2:
            return "high"
        elif tp_likelihood >= 0.6 or tp_likelihood <= 0.4:
            return "medium"
        else:
            return "low"

    def _determine_severity(self, signal: Signal, factors: Dict[str, float]) -> str:
        """Determine severity based on signal and factors."""
        base_severity = signal.severity.lower()
        if factors.get("asset_criticality", 0.5) > 0.6:
            # Bump severity for critical assets
            if base_severity == "medium":
                return "high"
            elif base_severity == "low":
                return "medium"
        return base_severity

    def _generate_mitre_mapping(self, signal: Signal) -> MitreMapping:
        """Generate MITRE mapping from signal using signal_subtype for accuracy.

        Uses signal_subtype (derived from content analysis) to provide more accurate
        MITRE mapping. For example, a SOAR case containing IOC data will have
        signal_subtype="ioc" and get C2-related MITRE tactics.
        """
        # Subtype-based mapping (more accurate for SOAR cases with mixed content)
        subtype_mitre_map = {
            "auth": (
                ["TA0006", "TA0003"],
                ["T1110", "T1078"],
            ),  # Credential Access + Persistence
            "endpoint": (
                ["TA0002", "TA0005"],
                ["T1059", "T1055"],
            ),  # Execution + Defense Evasion
            "network": (["TA0011", "TA0010"], ["T1071", "T1041"]),  # C2 + Exfiltration
            "email": (["TA0001"], ["T1566"]),  # Initial Access (Phishing)
            "ioc": (["TA0011"], ["T1071", "T1102"]),  # C2 indicators
            "vuln": (["TA0001"], ["T1190"]),  # Initial Access (Exploitation)
            "hunt": (["TA0007"], ["T1083", "T1082"]),  # Discovery
        }

        # Type-based mapping (fallback)
        type_mitre_map = {
            "siem_alert": (["TA0001"], ["T1190"]),  # Initial Access
            "ioc": (["TA0011"], ["T1071"]),  # C2
            "cve": (["TA0001"], ["T1190"]),  # Initial Access
            "edr_detection": (["TA0002"], ["T1059"]),  # Execution
            "email_security_alert": (["TA0001"], ["T1566"]),  # Phishing
        }

        # Prefer subtype mapping for more accurate results
        signal_subtype = signal.metadata.get("signal_subtype", "")
        if signal_subtype in subtype_mitre_map:
            tactics, techniques = subtype_mitre_map[signal_subtype]
        else:
            # Fallback to type-based mapping
            signal_type = signal.signal_type.value.lower()
            tactics, techniques = type_mitre_map.get(signal_type, ([], []))

        return MitreMapping(tactics=tactics, techniques=techniques)

    def _determine_incident_type(self, signal: Signal, mitre: MitreMapping) -> str:
        """Determine incident type using signal_subtype for accuracy.

        Uses signal_subtype (derived from content analysis) to provide more accurate
        incident type. For example, a SOAR case containing IOC data will have
        signal_subtype="ioc" and be classified as "Indicator Match".
        """
        # Subtype-based incident type (more accurate for mixed-content signals)
        subtype_type_map = {
            "auth": "Authentication Security Event",
            "endpoint": "Endpoint Detection",
            "network": "Network Security Event",
            "email": "Email Threat",
            "ioc": "Indicator Match",
            "vuln": "Vulnerability Exploitation",
            "hunt": "Threat Hunt Finding",
            "user": "User Report",
        }

        # Type-based mapping (fallback)
        type_map = {
            "siem_alert": "Security Alert",
            "ioc": "Indicator Match",
            "cve": "Vulnerability Exploitation",
            "edr_detection": "Endpoint Detection",
            "email_security_alert": "Email Threat",
            "hunt": "Threat Hunt Finding",
        }

        # Prefer subtype for more accurate classification
        signal_subtype = signal.metadata.get("signal_subtype", "")
        if signal_subtype in subtype_type_map:
            return subtype_type_map[signal_subtype]

        return type_map.get(signal.signal_type.value.lower(), "Security Incident")

    def _generate_triage_judgment(
        self,
        disposition: str,
        tp_likelihood: float,
        reasons_tp: List[str],
        reasons_fp: List[str],
    ) -> str:
        """Generate human-readable triage judgment."""
        if tp_likelihood >= 0.7:
            return (
                f"Signal assessed as {disposition} ({tp_likelihood*100:.0f}% TP likelihood). "
                f"{len(reasons_tp)} factors favor TP, {len(reasons_fp)} favor FP. "
                "Recommend escalation to Tier 2 or IR."
            )
        elif tp_likelihood <= 0.3:
            return (
                f"Signal assessed as {disposition} ({tp_likelihood*100:.0f}% TP likelihood). "
                f"{len(reasons_fp)} factors favor FP. "
                "Recommend closing as false positive with tuning review."
            )
        else:
            return (
                f"Signal assessed as {disposition} ({tp_likelihood*100:.0f}% TP likelihood). "
                "Evidence is inconclusive - additional investigation recommended."
            )

    def _write_outcome_to_graph(
        self,
        signal: Signal,
        classification: ClassificationResult,
        graph: TriageContextGraph,
    ) -> None:
        """Write classification result as outcome node to graph.

        Args:
            signal: The signal that was classified
            classification: Classification result
            graph: Graph to write outcome to
        """
        from datetime import datetime

        outcome_node = OutcomeNode(
            node_id=f"outcome_{signal.signal_id}_{int(datetime.now().timestamp())}",
            disposition=classification.disposition,
            severity=classification.severity,
            confidence=classification.confidence,
            tp_likelihood=classification.tp_likelihood,
            top_drivers=classification.reasons_tp,
            contradictions=classification.reasons_fp,
            provenance=Provenance(
                source_system="ClassificationService",
                confidence=0.95,
                evidence_refs=[f"signal_id:{signal.signal_id}"],
                query_fingerprint="classification_result",
                ttl_seconds=86400,  # 24 hours
            ),
            properties={
                "incident_type": classification.incident_type,
                "triage_judgment": classification.triage_judgment,
                "mitre_tactics": (
                    classification.mitre.tactics
                    if hasattr(classification, "mitre")
                    else []
                ),
                "mitre_techniques": (
                    classification.mitre.techniques
                    if hasattr(classification, "mitre")
                    else []
                ),
            },
        )

        graph.add_node(outcome_node)

        # Add edge from case to outcome
        case_nodes = graph.get_nodes_by_type(NodeType.CASE)
        if case_nodes:
            edge = EvidenceEdge(
                edge_id=f"case_outcome_{outcome_node.node_id}",
                edge_type=EdgeType.HAS_OUTCOME,
                source_node_id=case_nodes[0].node_id,
                target_node_id=outcome_node.node_id,
                provenance=Provenance(
                    source_system="ClassificationService",
                    confidence=1.0,
                    query_fingerprint="case_outcome_link",
                    ttl_seconds=86400,
                ),
                weight=classification.tp_likelihood,
            )
            graph.add_edge(edge)
