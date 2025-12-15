"""Classification service for TP/FP determination."""

from typing import Any, Dict, List, Optional

from ..models import Classification, ClassificationLabel, EnrichmentResult, Signal


class ClassificationService:
    """Service for deterministic TP/FP classification."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize classification service.

        Args:
            config: Configuration for classification rules
        """
        self.config = config or {}
        self.tp_confidence_threshold = self.config.get("tp_confidence", 0.7)
        self.fp_confidence_threshold = self.config.get("fp_confidence", 0.7)

    def classify(
        self,
        signal: Signal,
        enrichments: Dict[str, EnrichmentResult],
        similar_cases: List[tuple],
        forecast_data: Optional[Dict[str, Any]] = None,
    ) -> Classification:
        """Classify signal as TP/FP using deterministic rules.

        Args:
            signal: The signal to classify
            enrichments: Enrichment results
            similar_cases: List of (case_id, similarity) tuples
            forecast_data: Optional forecast data

        Returns:
            Classification result
        """
        factors = {}
        reasoning = []

        # Check threat intelligence
        ti_factor = self._check_threat_intel(enrichments, reasoning)
        factors["threat_intel"] = ti_factor

        # Check vulnerability data
        vuln_factor = self._check_vulnerabilities(enrichments, reasoning)
        factors["vulnerability"] = vuln_factor

        # Check anomaly/forecast data
        if forecast_data:
            anomaly_factor = self._check_anomaly(forecast_data, reasoning)
            factors["anomaly"] = anomaly_factor

        # Check historical FP rate
        fp_rate = self._check_historical_fp_rate(enrichments, reasoning)
        factors["historical_fp_rate"] = 1.0 - fp_rate  # Invert for scoring

        # Check similar cases
        similar_factor = self._check_similar_cases(similar_cases, reasoning)
        factors["similar_cases"] = similar_factor

        # Check asset criticality
        criticality_factor = self._check_asset_criticality(enrichments, reasoning)
        factors["asset_criticality"] = criticality_factor

        # Calculate overall confidence
        confidence = self._calculate_confidence(factors)

        # Determine label based on factors
        label = self._determine_label(factors, confidence)

        return Classification(
            label=label,
            confidence=confidence,
            reasoning=reasoning,
            factors=factors,
            similar_cases=[case_id for case_id, _ in similar_cases],
            forecast_data=forecast_data,
        )

    def _check_threat_intel(
        self, enrichments: Dict[str, EnrichmentResult], reasoning: List[str]
    ) -> float:
        """Check threat intelligence enrichment.

        Returns factor score 0-1 (higher = more likely TP).
        """
        ti_result = enrichments.get("threat_intel")
        if not ti_result or ti_result.status.value != "success":
            return 0.5  # Neutral

        data = ti_result.data
        reputation = data.get("reputation", "unknown")
        matches = data.get("matches_found", 0)

        if reputation == "malicious" or matches > 0:
            reasoning.append(
                f"Threat intelligence: {matches} malicious indicators found"
            )
            return 0.9
        elif reputation == "suspicious":
            reasoning.append("Threat intelligence: suspicious indicators detected")
            return 0.7

        return 0.5

    def _check_vulnerabilities(
        self, enrichments: Dict[str, EnrichmentResult], reasoning: List[str]
    ) -> float:
        """Check vulnerability enrichment."""
        vuln_result = enrichments.get("vulnerability")
        if not vuln_result or vuln_result.status.value != "success":
            return 0.5

        data = vuln_result.data
        critical_vulns = data.get("critical_vulns", 0)
        exploits = data.get("exploits_available", 0)

        if critical_vulns > 0 and exploits > 0:
            reasoning.append(
                f"{critical_vulns} critical vulnerabilities with available exploits"
            )
            return 0.8
        elif critical_vulns > 0:
            reasoning.append(f"{critical_vulns} critical vulnerabilities found")
            return 0.7

        return 0.5

    def _check_anomaly(
        self, forecast_data: Dict[str, Any], reasoning: List[str]
    ) -> float:
        """Check anomaly/forecast data."""
        if not forecast_data or not forecast_data.get("forecast_available"):
            return 0.5

        anomaly_score = forecast_data.get("anomaly_score", 0)
        exceeds_threshold = forecast_data.get("exceeds_threshold", False)

        if exceeds_threshold:
            reasoning.append(
                f"Anomalous activity detected (score: {anomaly_score:.2f})"
            )
            return min(anomaly_score, 1.0)

        return 0.5

    def _check_historical_fp_rate(
        self, enrichments: Dict[str, EnrichmentResult], reasoning: List[str]
    ) -> float:
        """Check historical false positive rate."""
        siem_result = enrichments.get("siem")
        if not siem_result or siem_result.status.value != "success":
            return 0.5

        fp_rate = siem_result.data.get("historical_fp_rate", 0.5)

        if fp_rate > 0.7:
            reasoning.append(
                f"High historical false positive rate ({fp_rate*100:.0f}%)"
            )
        elif fp_rate < 0.2:
            reasoning.append(f"Low historical false positive rate ({fp_rate*100:.0f}%)")

        return fp_rate

    def _check_similar_cases(
        self, similar_cases: List[tuple], reasoning: List[str]
    ) -> float:
        """Check similar historical cases."""
        if not similar_cases:
            return 0.5

        # For now, just count similar cases
        # In production, would check if they were TPs or FPs
        count = len(similar_cases)
        avg_similarity = sum(sim for _, sim in similar_cases) / count

        if count >= 3 and avg_similarity > 0.7:
            reasoning.append(
                f"Similar to {count} past cases (avg similarity: {avg_similarity:.2f})"
            )
            return 0.8
        elif count > 0:
            reasoning.append(f"Similar to {count} past cases")
            return 0.6

        return 0.5

    def _check_asset_criticality(
        self, enrichments: Dict[str, EnrichmentResult], reasoning: List[str]
    ) -> float:
        """Check asset criticality from CMDB."""
        cmdb_result = enrichments.get("cmdb")
        if not cmdb_result or cmdb_result.status.value != "success":
            return 0.5

        data = cmdb_result.data
        host_assets = data.get("host_assets", {})

        for hostname, asset_data in host_assets.items():
            criticality = asset_data.get("business_criticality", "medium")
            if criticality in ["critical", "high"]:
                reasoning.append(f"Critical asset involved: {hostname}")
                return 0.7

        return 0.5

    def _calculate_confidence(self, factors: Dict[str, float]) -> float:
        """Calculate overall confidence score."""
        if not factors:
            return 0.5

        # Weighted average of factors
        weights = {
            "threat_intel": 1.5,
            "vulnerability": 1.2,
            "anomaly": 1.0,
            "historical_fp_rate": 0.8,
            "similar_cases": 1.0,
            "asset_criticality": 0.8,
        }

        total_weight = 0
        weighted_sum = 0

        for factor, value in factors.items():
            weight = weights.get(factor, 1.0)
            weighted_sum += value * weight
            total_weight += weight

        confidence = weighted_sum / total_weight if total_weight > 0 else 0.5
        return min(max(confidence, 0.0), 1.0)

    def _determine_label(
        self, factors: Dict[str, float], confidence: float
    ) -> ClassificationLabel:
        """Determine classification label."""
        # If high threat intel or vulnerability with high confidence -> TP
        if (
            factors.get("threat_intel", 0) > 0.8
            or factors.get("vulnerability", 0) > 0.8
        ):
            if confidence >= self.tp_confidence_threshold:
                return ClassificationLabel.TRUE_POSITIVE

        # If high FP rate and low confidence -> FP
        fp_rate = 1.0 - factors.get("historical_fp_rate", 0.5)
        if fp_rate > 0.7 and confidence < 0.6:
            return ClassificationLabel.FALSE_POSITIVE

        # Overall confidence-based classification
        if confidence >= self.tp_confidence_threshold:
            return ClassificationLabel.TRUE_POSITIVE
        elif confidence <= (1.0 - self.fp_confidence_threshold):
            return ClassificationLabel.FALSE_POSITIVE
        else:
            return ClassificationLabel.UNKNOWN
