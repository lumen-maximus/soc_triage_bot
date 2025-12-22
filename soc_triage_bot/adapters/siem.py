"""SIEM adapter for enrichment."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from ..models import (
    EnrichmentResult,
    EnrichmentStatus,
    Signal,
    SignalSource,
    SignalType,
)
from .base import BaseAdapter, BucketedSeriesResult


class SIEMAdapter(BaseAdapter):
    """Generic SIEM adapter for additional context."""

    # Default late arrival window for backfill (spec Section 2)
    LATE_ARRIVAL_WINDOW_MINUTES = 120

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize SIEM adapter with configuration.

        Args:
            config: Configuration dict with keys:
                - enabled: bool
                - provider: str (mock, splunk, qradar, etc.)
                - api_url: str
                - api_key: str
                - username: str
                - password: str
                - timeout: int
                - verify_ssl: bool
                - default_index: str
                - max_results: int
                - search_timeout: int
        """
        super().__init__(config)
        self.name = "siem"

        # Store commonly used config values as properties for easy access
        self.enabled = self.config.get("enabled", False)
        self.provider = self.config.get("provider", "mock")
        self.api_url = self.config.get("api_url")
        self.api_key = self.config.get("api_key")
        self.username = self.config.get("username")
        self.password = self.config.get("password")
        self.timeout = self.config.get("timeout", 30)
        self.verify_ssl = self.config.get("verify_ssl", True)
        self.default_index = self.config.get("default_index")
        self.max_results = self.config.get("max_results", 1000)
        self.search_timeout = self.config.get("search_timeout", 60)

    async def enrich(self, signal: Signal) -> EnrichmentResult:
        """Enrich signal with SIEM data.

        This is a generic implementation. In production, this would
        connect to specific SIEM systems (Splunk, QRadar, etc.)

        Args:
            signal: The signal to enrich

        Returns:
            EnrichmentResult with SIEM context
        """
        start_time = datetime.utcnow()

        try:
            # Extract SOAR baseline if available (use cached version if present)
            baseline_cache = signal.metadata.get("_baseline_cache")
            if baseline_cache:
                soar_siem = baseline_cache.get("siem", {})
            else:
                # Fallback: extract if not cached
                from ..services.case_artifact_harvester import CaseArtifactHarvester

                soar_siem = CaseArtifactHarvester.extract_baseline_enrichments(
                    signal
                ).get("siem", {})

            # Mock enrichment - in production, query SIEM for:
            # - Historical alerts for same entities
            # - Related events in time window
            # - Alert frequency for this rule

            enrichment_data: Dict[str, Any] = {
                "alert_frequency_24h": 5,
                "related_alerts": [],
                "historical_fp_rate": 0.15,
                "rule_first_seen": "2024-01-15T10:00:00Z",
                "entity_history": {"user_alerts_30d": 2, "host_alerts_30d": 8},
            }

            # If entities exist, add entity-specific data
            if signal.entities:
                if "ip" in signal.entities:
                    enrichment_data["ip_history"] = {
                        "total_alerts": 3,
                        "unique_hosts": 1,
                    }

            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000

            # Merge SOAR baseline with fresh data
            if soar_siem:
                enrichment_data["soar_baseline"] = soar_siem

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

    async def get_bucketed_series(
        self,
        track_key: str,
        entity_id: str,
        start_utc: datetime,
        end_utc: datetime,
        bucket_minutes: int = 15,
    ) -> BucketedSeriesResult:
        """Get bucketed time series for SIEM data.

        Per forecasting spec Section 9:
        - Returns complete, zero-filled time buckets
        - Supports late arrival backfill

        Args:
            track_key: One of 'A_detection_rule', 'B_indicator_artifact', 'C_entity_behavior'
            entity_id: Entity identifier (e.g., 'rule_id=123', 'hostname=WS-01')
            start_utc: Start of time range
            end_utc: End of time range
            bucket_minutes: Bucket size in minutes (default 15)

        Returns:
            BucketedSeriesResult with zero-filled buckets and metadata.
        """
        # Calculate expected buckets
        total_minutes = int((end_utc - start_utc).total_seconds() / 60)
        expected_buckets = total_minutes // bucket_minutes

        # Generate zero-filled bucket structure
        buckets: List[Tuple[datetime, int]] = []
        current = start_utc
        while current < end_utc:
            buckets.append((current, 0))
            current += timedelta(minutes=bucket_minutes)

        # In production, this would:
        # 1. Query SIEM for events matching track_key + entity_id
        # 2. Aggregate into bucket counts
        # 3. Merge with zero-filled structure

        # Mock: fill with sample data based on track_key
        buckets = self._fill_mock_data(buckets, track_key, entity_id)

        # Calculate data quality metrics
        non_zero_count = sum(1 for _, count in buckets if count > 0)
        missing_buckets = 0  # In production, track truly missing data
        missing_pct = (
            missing_buckets / expected_buckets if expected_buckets > 0 else 0.0
        )

        return BucketedSeriesResult(
            buckets=buckets,
            track_key=track_key,
            entity_id=entity_id,
            bucket_minutes=bucket_minutes,
            start_utc=start_utc,
            end_utc=end_utc,
            total_buckets=len(buckets),
            missing_buckets=missing_buckets,
            missing_pct=missing_pct,
            data_completeness="COMPLETE",
            late_arrival_backfill_supported=True,
            last_backfill_utc=datetime.utcnow(),
        )

    def _fill_mock_data(
        self,
        buckets: List[Tuple[datetime, int]],
        track_key: str,
        entity_id: str,
    ) -> List[Tuple[datetime, int]]:
        """Fill buckets with mock data for testing.

        In production, this data comes from SIEM queries.
        """
        import random

        # Base rate depends on track type
        if track_key == "A_detection_rule":
            base_rate = 2  # alerts per bucket on average
        elif track_key == "B_indicator_artifact":
            base_rate = 5  # sightings per bucket
        else:  # C_entity_behavior
            base_rate = 3  # behavior events per bucket

        # Generate poisson-like counts with occasional spikes
        filled = []
        for bucket_time, _ in buckets:
            # Simulate daily pattern with some randomness
            hour = bucket_time.hour
            daily_factor = 1.0 + 0.5 * (1 if 8 <= hour <= 18 else 0.3)

            # Base count with noise
            count = max(0, int(random.gauss(base_rate * daily_factor, base_rate * 0.5)))

            # Occasional spike (5% chance)
            if random.random() < 0.05:
                count = int(count * random.uniform(3, 8))

            filled.append((bucket_time, count))

        return filled

    # =========================================================================
    # RUNBOOK/PLAYBOOK FUNCTIONS (for SOAR integration)
    # =========================================================================

    async def list_runbooks(
        self, signal_type: Optional[str] = None, category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List available runbooks from SOAR.

        Args:
            signal_type: Optional filter by signal type
            category: Optional filter by category

        Returns:
            List of runbook metadata dictionaries
        """
        # In production, query SOAR API for runbooks
        # Mock implementation for demonstration
        mock_runbooks = [
            {
                "id": "SOAR-RB-001",
                "title": "Phishing Email Triage",
                "category": "investigation",
                "signal_types": ["EMAIL_SECURITY_ALERT"],
                "version": "2.1",
                "last_updated": "2024-11-15",
                "action_count": 6,
            },
            {
                "id": "SOAR-RB-002",
                "title": "Malware Alert Response",
                "category": "containment",
                "signal_types": ["EDR_DETECTION", "SIEM_ALERT"],
                "version": "3.0",
                "last_updated": "2024-12-01",
                "action_count": 8,
            },
            {
                "id": "SOAR-PB-001",
                "title": "Incident Response Workflow",
                "category": "incident_response",
                "signal_types": ["SIEM_ALERT", "EDR_DETECTION", "IOC"],
                "version": "1.5",
                "last_updated": "2024-10-20",
                "action_count": 12,
            },
        ]

        # Apply filters
        results = mock_runbooks
        if signal_type:
            results = [r for r in results if signal_type in r.get("signal_types", [])]
        if category:
            results = [r for r in results if r.get("category") == category]

        return results

    async def get_runbook(self, runbook_id: str) -> Dict[str, Any]:
        """Fetch a specific runbook from SOAR by ID.

        Args:
            runbook_id: The runbook or playbook ID

        Returns:
            Complete runbook with actions, or None if not found
        """
        # In production, query SOAR API for runbook details
        # Mock implementation
        mock_runbooks = {
            "SOAR-RB-001": {
                "id": "SOAR-RB-001",
                "title": "Phishing Email Triage",
                "description": "Standard playbook for triaging phishing emails",
                "category": "investigation",
                "signal_types": ["EMAIL_SECURITY_ALERT"],
                "version": "2.1",
                "author": "SOC Engineering",
                "approved_by": "SOC Manager",
                "approval_date": "2024-11-01",
                "actions": [
                    {
                        "id": "step-1",
                        "intent": "investigate",
                        "tool": "Email Security",
                        "owner": "SOC",
                        "title": "Analyze Email Headers",
                        "description": "Review email headers for spoofing indicators",
                        "steps": ["Check SPF/DKIM/DMARC", "Review sender reputation"],
                        "priority": 1,
                    },
                    {
                        "id": "step-2",
                        "intent": "contain",
                        "tool": "Email Security",
                        "owner": "SOC",
                        "title": "Quarantine Email",
                        "description": "Remove email from all mailboxes",
                        "steps": ["Search by Message-ID", "Quarantine copies"],
                        "priority": 1,
                    },
                ],
            },
            "SOAR-RB-002": {
                "id": "SOAR-RB-002",
                "title": "Malware Alert Response",
                "description": "Response playbook for malware detections",
                "category": "containment",
                "signal_types": ["EDR_DETECTION", "SIEM_ALERT"],
                "version": "3.0",
                "author": "IR Team",
                "approved_by": "CISO",
                "approval_date": "2024-12-01",
                "actions": [
                    {
                        "id": "step-1",
                        "intent": "investigate",
                        "tool": "EDR",
                        "owner": "SOC",
                        "title": "Verify Detection",
                        "description": "Confirm malware detection is valid",
                        "steps": ["Review EDR alert", "Check file reputation"],
                        "priority": 1,
                    },
                    {
                        "id": "step-2",
                        "intent": "contain",
                        "tool": "EDR",
                        "owner": "SOC",
                        "title": "Isolate Host",
                        "description": "Network isolate the affected host",
                        "steps": ["Verify host status", "Initiate isolation"],
                        "priority": 1,
                    },
                ],
            },
        }

        return mock_runbooks.get(runbook_id) or {}

    def get_runbook_actions(self, runbook_id: str) -> List[Dict[str, Any]]:
        """Get actions from a runbook (synchronous wrapper).

        Args:
            runbook_id: The runbook ID

        Returns:
            List of action dictionaries
        """
        import asyncio

        # Use asyncio to run the async method
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        if loop.is_running():
            # If we're in an async context, just do it synchronously with mock data
            mock_runbooks = {
                "SOAR-RB-001": [
                    {
                        "id": "step-1",
                        "intent": "investigate",
                        "tool": "Email Security",
                        "owner": "SOC",
                        "title": "Analyze Email Headers",
                        "description": "Review email headers for spoofing indicators",
                        "steps": ["Check SPF/DKIM/DMARC", "Review sender reputation"],
                        "priority": 1,
                    },
                ],
                "SOAR-RB-002": [
                    {
                        "id": "step-1",
                        "intent": "investigate",
                        "tool": "EDR",
                        "owner": "SOC",
                        "title": "Verify Detection",
                        "description": "Confirm malware detection is valid",
                        "steps": ["Review EDR alert", "Check file reputation"],
                        "priority": 1,
                    },
                ],
            }
            return mock_runbooks.get(runbook_id, [])

        runbook = loop.run_until_complete(self.get_runbook(runbook_id))
        if runbook:
            return runbook.get("actions", [])
        return []

    # =========================================================================
    # CASE AND ARTIFACT RETRIEVAL (for CaseArtifactHarvester)
    # =========================================================================

    async def get_case(self, case_id: str) -> Dict[str, Any]:
        """Fetch a case from SOAR by ID.

        Returns complete case data including:
        - runbook_refs: References to playbooks/runbooks used
        - tasks_template_id: Template used for tasks
        - attachments_metadata: Attached files/artifacts
        - actions_taken: Actions performed on the case

        Args:
            case_id: The SOAR case ID

        Returns:
            Complete case dictionary or None if not found
        """
        # In production, query SOAR API for case details
        # Mock implementation for demonstration
        mock_cases = {
            "CASE-2024-001": {
                "case_id": "CASE-2024-001",
                "title": "Malware Detection on WS-FINANCE-01",
                "signal_type": "EDR_DETECTION",
                "created_at": "2024-11-20T10:30:00Z",
                "resolved_at": "2024-11-20T14:45:00Z",
                "disposition": "TP",
                "outcome": "TP",
                "severity": "high",
                "runbook_refs": [
                    {
                        "ref_id": "SOAR-RB-002",
                        "ref_type": "runbook",
                        "source": "soar",
                        "title": "Malware Alert Response",
                        "url": "https://soar.internal/runbooks/SOAR-RB-002",
                        "whitelisted": True,
                    }
                ],
                "tasks_template_id": "TPL-MALWARE-001",
                "attachments_metadata": [
                    {
                        "attachment_id": "ATT-001",
                        "filename": "malware_sample.zip",
                        "content_type": "application/zip",
                        "size_bytes": 45678,
                        "is_playbook": False,
                    },
                    {
                        "attachment_id": "ATT-002",
                        "filename": "containment_steps.yaml",
                        "content_type": "application/yaml",
                        "size_bytes": 2048,
                        "is_playbook": True,
                    },
                ],
                "actions_taken": [
                    "Isolated host WS-FINANCE-01 via EDR",
                    "Collected forensic artifacts",
                    "Blocked malicious hash at EDR policy",
                    "Notified IT for reimaging",
                ],
                "entities": {
                    "hostname": ["WS-FINANCE-01"],
                    "ip": ["10.1.50.23"],
                    "indicator": ["abc123hash"],
                },
                "notes": "Emotet dropper detected via behavioral detection. Host isolated within 15 minutes.",
            },
            "CASE-2024-002": {
                "case_id": "CASE-2024-002",
                "title": "Phishing Email Campaign",
                "signal_type": "EMAIL_SECURITY_ALERT",
                "created_at": "2024-11-22T08:15:00Z",
                "resolved_at": "2024-11-22T11:30:00Z",
                "disposition": "TP",
                "outcome": "TP",
                "severity": "medium",
                "runbook_refs": [
                    {
                        "ref_id": "SOAR-RB-001",
                        "ref_type": "runbook",
                        "source": "soar",
                        "title": "Phishing Email Triage",
                        "url": "https://soar.internal/runbooks/SOAR-RB-001",
                        "whitelisted": True,
                    }
                ],
                "tasks_template_id": "TPL-PHISH-001",
                "attachments_metadata": [
                    {
                        "attachment_id": "ATT-003",
                        "filename": "email_headers.txt",
                        "content_type": "text/plain",
                        "size_bytes": 1024,
                        "is_playbook": False,
                    },
                ],
                "actions_taken": [
                    "Quarantined phishing email from all mailboxes",
                    "Blocked sender domain",
                    "Reset credentials for 3 users who clicked",
                    "Sent awareness reminder to affected users",
                ],
                "entities": {
                    "email": ["phishing@malicious.com"],
                    "domain": ["malicious.com"],
                    "username": ["jsmith", "bjones", "mwilson"],
                },
                "notes": "BEC attempt impersonating CFO. 3 users clicked, none entered credentials.",
            },
            "CASE-2024-003": {
                "case_id": "CASE-2024-003",
                "title": "IOC Hit - Known C2 Domain",
                "signal_type": "IOC",
                "created_at": "2024-12-01T14:00:00Z",
                "resolved_at": "2024-12-01T16:00:00Z",
                "disposition": "FP",
                "outcome": "FP",
                "severity": "low",
                "runbook_refs": [],  # No runbook used - was FP
                "tasks_template_id": None,
                "attachments_metadata": [],
                "actions_taken": [
                    "Investigated DNS request",
                    "Confirmed domain sinkholed - benign",
                    "Closed as false positive",
                ],
                "entities": {
                    "domain": ["known-c2.example.com"],
                    "hostname": ["WS-DEV-05"],
                },
                "notes": "DNS sinkhole traffic, not actual C2 communication.",
            },
        }

        return mock_cases.get(case_id) or {}

    async def get_case_artifacts(self, case_id: str) -> Dict[str, Any]:
        """Fetch artifacts from a SOAR case.

        Returns structured artifact data including:
        - runbook_refs: All runbook/playbook references
        - attachments: Attachment metadata (not content)
        - tasks_template_id: Template ID if used

        Args:
            case_id: The SOAR case ID

        Returns:
            Artifacts dictionary
        """
        case = await self.get_case(case_id)
        if not case:
            return {
                "case_id": case_id,
                "found": False,
                "runbook_refs": [],
                "attachments_metadata": [],
                "tasks_template_id": None,
            }

        return {
            "case_id": case_id,
            "found": True,
            "runbook_refs": case.get("runbook_refs", []),
            "attachments_metadata": case.get("attachments_metadata", []),
            "tasks_template_id": case.get("tasks_template_id"),
        }

    async def fetch_attachment(
        self, case_id: str, attachment_id: str
    ) -> Dict[str, Any]:
        """Fetch attachment content from SOAR (policy-controlled).

        NOTE: In production, this should be policy-controlled.
        Only whitelisted attachment types should be fetchable.

        Args:
            case_id: The SOAR case ID
            attachment_id: The attachment ID

        Returns:
            Attachment content and metadata
        """
        # Mock - in production, this would fetch from SOAR
        # and check against content policies
        mock_attachments = {
            "ATT-002": {
                "attachment_id": "ATT-002",
                "case_id": "CASE-2024-001",
                "filename": "containment_steps.yaml",
                "content_type": "application/yaml",
                "content": """
steps:
  - name: Isolate host
    tool: EDR
    owner: SOC
  - name: Collect artifacts
    tool: EDR
    owner: IR
  - name: Block hash
    tool: EDR
    owner: SOC
""",
            }
        }

        return mock_attachments.get(attachment_id, {"error": "Not found"})

    def get_case_sync(self, case_id: str) -> Dict[str, Any]:
        """Synchronous wrapper for get_case.

        Args:
            case_id: The SOAR case ID

        Returns:
            Complete case dictionary or None
        """
        import asyncio

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        if loop.is_running():
            # Return mock data directly if in async context
            return self._get_mock_case(case_id)

        return loop.run_until_complete(self.get_case(case_id))

    def _get_mock_case(self, case_id: str) -> Dict[str, Any]:
        """Get mock case data for synchronous access."""
        mock_cases = {
            "CASE-2024-001": {
                "case_id": "CASE-2024-001",
                "title": "Malware Detection on WS-FINANCE-01",
                "signal_type": "EDR_DETECTION",
                "disposition": "TP",
                "runbook_refs": [
                    {
                        "ref_id": "SOAR-RB-002",
                        "ref_type": "runbook",
                        "source": "soar",
                        "title": "Malware Alert Response",
                        "whitelisted": True,
                    }
                ],
                "tasks_template_id": "TPL-MALWARE-001",
                "attachments_metadata": [],
                "actions_taken": [
                    "Isolated host via EDR",
                    "Collected forensic artifacts",
                ],
            },
            "CASE-2024-002": {
                "case_id": "CASE-2024-002",
                "title": "Phishing Email Campaign",
                "signal_type": "EMAIL_SECURITY_ALERT",
                "disposition": "TP",
                "runbook_refs": [
                    {
                        "ref_id": "SOAR-RB-001",
                        "ref_type": "runbook",
                        "source": "soar",
                        "title": "Phishing Email Triage",
                        "whitelisted": True,
                    }
                ],
                "tasks_template_id": "TPL-PHISH-001",
                "attachments_metadata": [],
                "actions_taken": [
                    "Quarantined email",
                    "Blocked sender domain",
                ],
            },
        }
        return mock_cases.get(case_id) or {}

    async def fetch_alert_by_id(self, alert_id: str) -> Optional[Signal]:
        """Fetch a SIEM alert/notable event by ID and convert to Signal.

        In production, this would:
        1. Query SIEM API for alert by ID
        2. Fetch associated raw events, context
        3. Parse into Signal format

        Args:
            alert_id: SIEM alert/notable event ID

        Returns:
            Signal object if found, None otherwise
        """
        import uuid

        from ..models.signal import (
            ArtifactContext,
            DetectionContext,
            EntityBehaviorContext,
        )

        # Mock implementation - returns sample SIEM alert
        # In production, replace with actual SIEM API call:
        # response = requests.get(f"{self.api_url}/services/saved/searches/alert/{alert_id}",
        #                         headers={"Authorization": f"Bearer {self.api_token}"})

        mock_alert = self._generate_mock_alert(alert_id)

        # Parse into Signal
        signal = Signal(
            signal_id=f"siem-{alert_id}",
            signal_type=SignalType.SIEM_ALERT,
            timestamp=mock_alert["timestamp"],
            source=SignalSource(
                system="siem",
                rule_id=mock_alert["rule_id"],
                rule_name=mock_alert["rule_name"],
            ),
            title=mock_alert["title"],
            description=mock_alert["description"],
            severity=mock_alert["severity"],
            entities=mock_alert["entities"],
            tags=mock_alert["tags"],
            raw_data=mock_alert["raw_data"],
            detection_context=DetectionContext(
                rule_id=mock_alert["rule_id"],
                detection_name=mock_alert["rule_name"],
                mitre_tactics=mock_alert.get("mitre_tactics", []),
                mitre_techniques=mock_alert.get("mitre_techniques", []),
            ),
            entity_context=EntityBehaviorContext(
                hostname=(
                    mock_alert["entities"].get("hostname", [""])[0]
                    if "hostname" in mock_alert["entities"]
                    else None
                ),
                username=(
                    mock_alert["entities"].get("user", [""])[0]
                    if "user" in mock_alert["entities"]
                    else None
                ),
                src_ip=(
                    mock_alert["entities"].get("ip", [""])[0]
                    if "ip" in mock_alert["entities"]
                    else None
                ),
            ),
            artifact_context=ArtifactContext(
                domain=mock_alert.get("indicators", {}).get("domain"),
                ip=mock_alert.get("indicators", {}).get("ip"),
                process_name=mock_alert["raw_data"].get("process_name"),
            ),
        )

        return signal

    def _generate_mock_alert(self, alert_id: str) -> Dict[str, Any]:
        """Generate mock SIEM alert for testing.

        In production, this data comes from SIEM API.

        Args:
            alert_id: Alert ID to generate data for

        Returns:
            Mock alert dictionary
        """
        return {
            "alert_id": alert_id,
            "rule_id": f"rule-{alert_id[:8]}",
            "rule_name": "Suspicious Process Execution",
            "timestamp": datetime.utcnow(),
            "title": f"Suspicious Activity Detected - Alert {alert_id}",
            "description": f"SIEM alert {alert_id}: Suspicious process execution detected on endpoint",
            "severity": "high",
            "entities": {
                "hostname": [f"workstation-{alert_id[:4]}"],
                "user": ["analyst-user"],
                "ip": ["192.0.2.100"],
                "process": ["powershell.exe"],
            },
            "indicators": {
                "domain": "suspicious-domain.com",
                "ip": "198.51.100.50",
            },
            "tags": ["malware", "process-execution", "edr"],
            "mitre_tactics": ["execution", "defense_evasion"],
            "mitre_techniques": ["T1059.001", "T1140"],
            "raw_data": {
                "process_name": "powershell.exe",
                "command_line": "powershell -enc BASE64_ENCODED_COMMAND",
                "parent_process": "explorer.exe",
                "event_count": 15,
                "first_seen": datetime.utcnow().isoformat(),
                "last_seen": datetime.utcnow().isoformat(),
            },
        }
