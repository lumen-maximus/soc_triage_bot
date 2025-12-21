"""SOAR baseline data extractor for enrichment augmentation."""

from typing import Any, Dict, List

from ..models import Signal


class SOARDataExtractor:
    """Extract baseline enrichment data from SOAR container artifacts.
    
    This service parses SOAR artifacts to extract pre-existing enrichment data
    that can be used to augment fresh enrichment queries, providing context
    about what was previously known at the time of SOAR analysis.
    """
    
    @staticmethod
    def extract_baseline_enrichments(signal: Signal) -> Dict[str, Dict[str, Any]]:
        """Extract pre-existing enrichment data from SOAR artifacts.
        
        Parses artifact names and data to identify threat intelligence, CMDB,
        EDR, vulnerability, and SIEM correlation data that was captured during
        the original SOAR investigation.
        
        Args:
            signal: Signal with SOAR container data in raw_data
            
        Returns:
            Dictionary with baseline data for each adapter:
            {
                "threatintel": {...},
                "cmdb": {...},
                "edr": {...},
                "vulnerability": {...},
                "siem": {...}
            }
        """
        # Return empty if not a SOAR signal
        if not signal.metadata.get("soar_id"):
            return {}
        
        baseline = {
            "threatintel": {},
            "cmdb": {},
            "edr": {},
            "vulnerability": {},
            "siem": {}
        }
        
        # Extract artifacts from raw_data
        artifacts = signal.raw_data.get("data", {}).get("artifacts", [])
        
        for artifact in artifacts:
            name = artifact.get("name", "").lower()
            data = artifact.get("data", {})
            cef = artifact.get("cef", {})
            timestamp = artifact.get("create_time")
            
            # Extract threat intelligence baseline
            if any(kw in name for kw in ["threat", "virustotal", "reputation", "ti_", "intelligence"]):
                baseline["threatintel"].update({
                    "soar_reputation": data.get("reputation"),
                    "soar_confidence": data.get("confidence"),
                    "soar_malicious_score": data.get("malicious_score"),
                    "soar_tags": data.get("tags", []),
                    "soar_sources": data.get("sources", []),
                    "soar_first_seen": timestamp,
                    "soar_categories": data.get("categories", [])
                })
            
            # Extract CMDB/asset baseline
            if any(kw in name for kw in ["asset", "cmdb", "host_info", "inventory"]):
                baseline["cmdb"].update({
                    "soar_owner": data.get("owner") or cef.get("deviceOwner"),
                    "soar_criticality": data.get("criticality") or data.get("business_criticality"),
                    "soar_business_unit": data.get("business_unit"),
                    "soar_department": data.get("department"),
                    "soar_os": cef.get("deviceOsName"),
                    "soar_asset_tag": data.get("asset_tag"),
                    "soar_last_updated": timestamp
                })
            
            # Extract EDR/endpoint baseline
            if any(kw in name for kw in ["edr", "endpoint", "process", "telemetry"]):
                baseline["edr"].update({
                    "soar_process_tree": data.get("process_tree", []),
                    "soar_parent_process": cef.get("parentProcessName"),
                    "soar_command_line": cef.get("deviceProcessName"),
                    "soar_network_connections": data.get("network_connections", []),
                    "soar_file_modifications": data.get("file_modifications", []),
                    "soar_registry_changes": data.get("registry_changes", []),
                    "soar_agent_version": data.get("agent_version"),
                    "soar_containment_status": data.get("containment_status")
                })
            
            # Extract vulnerability baseline
            if any(kw in name for kw in ["vuln", "cve", "patch", "scanner"]):
                baseline["vulnerability"].update({
                    "soar_cves": data.get("cves", []),
                    "soar_cvss_score": data.get("cvss_score"),
                    "soar_patch_status": data.get("patch_status"),
                    "soar_exploit_available": data.get("exploit_available"),
                    "soar_scan_date": timestamp
                })
            
            # Extract SIEM correlation baseline
            if any(kw in name for kw in ["siem", "correlation", "related_events"]):
                baseline["siem"].update({
                    "soar_related_events": data.get("related_events", []),
                    "soar_event_count": data.get("event_count"),
                    "soar_first_seen": data.get("first_seen"),
                    "soar_last_seen": data.get("last_seen")
                })
        
        # Clean up empty dictionaries
        return {k: v for k, v in baseline.items() if v}
