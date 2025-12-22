"""Threat Intelligence adapter for enrichment."""

from datetime import datetime
from typing import Any, Dict, Optional

from ..models import EnrichmentResult, EnrichmentStatus, Signal
from .base import BaseAdapter


class ThreatIntelAdapter(BaseAdapter):
    """Generic Threat Intelligence adapter."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the adapter."""
        super().__init__(config)
        self.name = "threat_intel"  # Override to use underscore

    async def enrich(self, signal: Signal) -> EnrichmentResult:
        """Enrich signal with threat intelligence data.

        This is a generic implementation. In production, this would
        connect to TI feeds (VirusTotal, AlienVault, etc.)

        For SOAR signals, augments fresh queries with baseline data.

        Args:
            signal: The signal to enrich

        Returns:
            EnrichmentResult with threat intel context (merged with SOAR baseline)
        """
        start_time = datetime.utcnow()

        try:
            # Extract SOAR baseline if available
            from ..services.case_artifact_harvester import CaseArtifactHarvester

            soar_ti = CaseArtifactHarvester.extract_baseline_enrichments(signal).get(
                "threatintel", {}
            )

            # Mock enrichment - in production, query TI sources for:
            # - IP/domain/hash reputation
            # - Known campaigns
            # - Threat actor attribution
            # - CVE details

            enrichment_data: Dict[str, Any] = {
                "feeds_checked": ["feed1", "feed2", "feed3"],
                "matches_found": 0,
                "reputation": "unknown",
            }

            # Check IPs
            if "ip" in signal.entities:
                for ip in signal.entities["ip"]:
                    # Mock check - in production, query TI feeds
                    if self._is_suspicious_ip(ip):
                        enrichment_data["matches_found"] += 1
                        enrichment_data["reputation"] = "suspicious"
                        enrichment_data["ip_intel"] = {
                            ip: {
                                "reputation": "malicious",
                                "threat_score": 85,
                                "categories": ["malware", "c2"],
                                "first_seen": "2024-11-20",
                                "last_seen": "2025-12-14",
                                "references": ["campaign-xyz"],
                            }
                        }

            # Check domains
            if "domain" in signal.entities:
                enrichment_data["domain_intel"] = {}
                for domain in signal.entities["domain"]:
                    enrichment_data["domain_intel"][domain] = {
                        "reputation": "unknown",
                        "age_days": 730,
                        "registrar": "example-registrar",
                    }

            # Check file hashes
            if "file_hash" in signal.entities:
                enrichment_data["file_intel"] = {}
                for hash_val in signal.entities["file_hash"]:
                    enrichment_data["file_intel"][hash_val] = {
                        "known_malware": False,
                        "detection_rate": 0,
                        "family": None,
                    }

            # Augment with SOAR context if available
            if soar_ti:
                enrichment_data["soar_context"] = {
                    "had_previous_analysis": True,
                    "previous_reputation": soar_ti.get("soar_reputation"),
                    "first_analyzed": soar_ti.get("soar_first_seen"),
                    "reputation_changed": (
                        soar_ti.get("soar_reputation")
                        != enrichment_data.get("reputation")
                        if soar_ti.get("soar_reputation")
                        else False
                    ),
                }

                # Merge tags (deduplicated)
                soar_tags = soar_ti.get("soar_tags", [])
                if soar_tags:
                    enrichment_data["tags"] = list(
                        set(enrichment_data.get("tags", []) + soar_tags)
                    )

                # Merge sources (deduplicated)
                soar_sources = soar_ti.get("soar_sources", [])
                if soar_sources:
                    enrichment_data["sources"] = list(
                        set(enrichment_data.get("sources", []) + soar_sources)
                    )

            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            return EnrichmentResult(
                adapter=self.name,
                status=EnrichmentStatus.SUCCESS,
                data=enrichment_data,
                duration_ms=duration_ms,
            )

        except Exception as e:
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            return EnrichmentResult(
                adapter=self.name,
                status=EnrichmentStatus.FAILED,
                error=str(e),
                duration_ms=duration_ms,
            )

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Mock function to check if IP is suspicious.

        In production, this would query actual TI feeds.
        """
        # Simple mock: IPs starting with 10. are suspicious (for demo)
        return ip.startswith("192.0.2.") or ip.startswith("198.51.100.")
