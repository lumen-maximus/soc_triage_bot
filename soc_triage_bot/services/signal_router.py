"""SignalRouter - Route signals and normalize entity extraction.

Refactored from CLI normalize_signal_cli() to be reusable across CLI/API.
Determines signal subtype, extracts entities, and selects entity focus.
Also handles SOAR container detection and parsing.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from soc_triage_bot.models.signal import Signal, SignalSource, SignalType


class SignalRouter:
    """Routes signals and normalizes entity extraction.

    Responsibilities:
    - Detect and parse SOAR containers from raw JSON
    - Extract entities from signal fields (entity_context, artifact_context, SOAR CEF)
    - Determine signal_subtype (auth/endpoint/network/email/vuln/ioc/hunt/other)
    - Select entity_focus.primary for entity behavior tracking
    - Store metadata in signal for downstream use
    """

    def detect_and_parse_soar_container(self, data: dict) -> Optional[Signal]:
        """Auto-detect if JSON is a SOAR container and parse it.

        Detects SOAR containers by checking for distinctive fields:
        - source_data_identifier (unique to SOAR)
        - container_update_time (unique to SOAR)
        - artifact_count (unique to SOAR)
        - Container label field with SOAR-style labels

        If 2+ of these fields are present, treat as SOAR container.

        Args:
            data: JSON dictionary to check

        Returns:
            Signal if SOAR container detected, None otherwise
        """
        # Check for SOAR-specific fields
        soar_indicators = 0

        if "source_data_identifier" in data:
            soar_indicators += 1
        if "container_update_time" in data:
            soar_indicators += 1
        if "artifact_count" in data:
            soar_indicators += 1
        if "label" in data:
            soar_indicators += 1

        # Need at least 2 indicators to be confident it's a SOAR container
        if soar_indicators < 2:
            return None

        # Extract container fields
        container_id = data.get("id")
        container_name = data.get("name", "Untitled SOAR Container")
        container_description = data.get("description", "")
        container_severity = data.get("severity", "medium").lower()
        container_tags = data.get("tags", [])
        container_label = data.get("label", "incident")

        # Map SOAR label to signal_type
        label_to_signal_type = {
            "incident": SignalType.SIEM_ALERT,
            "intelligence": SignalType.IOC,
            "vulnerabilities": SignalType.CVE,
            "email": SignalType.USER_REPORT,
        }
        signal_type = label_to_signal_type.get(container_label, SignalType.SIEM_ALERT)

        # Parse timestamp
        timestamp_str = data.get("create_time")
        if timestamp_str:
            # Handle ISO8601 timestamps with 'Z' suffix more robustly
            timestamp = datetime.fromisoformat(timestamp_str.rstrip("Z") + "+00:00")
        else:
            timestamp = datetime.utcnow()

        # Build source
        source = SignalSource(
            system="soar",
            rule_id=data.get("source_data_identifier"),
            rule_name=container_name,
        )

        # Extract entities from artifacts
        entities = {}
        artifacts_data = []

        # Check for artifacts in data.artifacts or data.data.artifacts
        artifacts = data.get("artifacts", [])
        if not artifacts and "data" in data:
            artifacts = data.get("data", {}).get("artifacts", [])

        # Process artifacts and extract CEF fields
        if artifacts:
            for artifact in artifacts:
                artifact_info = {
                    "id": artifact.get("id"),
                    "name": artifact.get("name"),
                    "cef": artifact.get("cef", {}),
                }
                artifacts_data.append(artifact_info)

                # Extract CEF fields to entities using a mapping dictionary
                cef = artifact.get("cef", {})

                # CEF field to entity type mapping
                cef_field_mapping = {
                    # Network entities
                    "sourceAddress": "ip",
                    "destinationAddress": "ip",
                    "destinationHostName": "hostname",
                    "sourceHostName": "hostname",
                    "destinationDnsDomain": "domain",
                    "sourceDnsDomain": "domain",
                    "requestURL": "url",
                    # User entities
                    "suser": "user",
                    "duser": "user",
                    # File/Hash entities
                    "fileHashSha256": "hash",
                    "fileHashSha1": "hash",
                    "fileHashMd5": "hash",
                    "filePath": "file",
                    "fileName": "file",
                    # Process entities
                    "deviceProcessName": "process",
                    "sourceProcessName": "process",
                    # Email entities
                    "senderAddress": "email",
                    "recipientAddress": "email",
                }

                # Extract entities based on mapping
                for cef_field, entity_type in cef_field_mapping.items():
                    value = cef.get(cef_field)
                    if value is not None and value != "":
                        entities.setdefault(entity_type, []).append(value)

        # Deduplicate entities
        for entity_type in entities:
            entities[entity_type] = list(set(entities[entity_type]))

        # Build metadata with all SOAR-specific fields
        metadata = {
            "soar_id": container_id,
            "soar_label": container_label,
            "soar_status": data.get("status"),
            "soar_sensitivity": data.get("sensitivity"),
            "soar_owner": data.get("owner"),
            "soar_hash": data.get("hash"),
            "soar_asset_name": data.get("asset_name"),
            "soar_open_time": data.get("open_time"),
            "soar_close_time": data.get("close_time"),
            "soar_due_time": data.get("due_time"),
            "soar_kill_chain": data.get("kill_chain"),
            "artifact_count": data.get("artifact_count"),
            "source_data_identifier": data.get("source_data_identifier"),
            "soar_related_cases": data.get("related_cases", []),
            "soar_playbook_history": data.get("playbook_history", []),
        }

        # Store artifacts in metadata
        if artifacts_data:
            metadata["artifacts"] = artifacts_data

        # Note if artifacts are missing but expected
        artifact_count = data.get("artifact_count", 0)
        if artifact_count > 0 and not artifacts:
            metadata["artifacts_note"] = (
                f"Container indicates {artifact_count} artifacts but none included in JSON"
            )

        # Build signal
        signal = Signal(
            signal_id=(
                f"soar-{container_id}"
                if container_id
                else f"soar-{uuid.uuid4().hex[:8]}"
            ),
            signal_type=signal_type,
            timestamp=timestamp,
            source=source,
            title=container_name,
            description=container_description,
            severity=container_severity,
            entities=entities,
            tags=container_tags,
            raw_data=data,  # Preserve full SOAR container data
            metadata=metadata,
        )

        return signal

    def parse_signal_from_json(self, data: dict) -> Signal:
        """Parse a signal from JSON data.

        Attempts to detect and parse SOAR containers first, then falls back
        to standard signal format.

        Args:
            data: Raw JSON dictionary

        Returns:
            Parsed Signal object
        """
        # Try SOAR container detection first
        soar_signal = self.detect_and_parse_soar_container(data)
        if soar_signal:
            return soar_signal

        # Fall back to existing signal parsing logic
        signal_type = SignalType(data.get("signal_type", "siem_alert"))

        # Parse timestamp
        timestamp_str = data.get("timestamp")
        if timestamp_str:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        else:
            timestamp = datetime.utcnow()

        # Parse source
        source_data = data.get("source", {})
        source = SignalSource(
            system=source_data.get("system", "unknown"),
            instance=source_data.get("instance"),
            rule_id=source_data.get("rule_id"),
            rule_name=source_data.get("rule_name"),
        )

        return Signal(
            signal_id=data.get(
                "signal_id", f"sig-{int(datetime.utcnow().timestamp())}"
            ),
            signal_type=signal_type,
            timestamp=timestamp,
            source=source,
            title=data.get("title", "Untitled"),
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            entities=data.get("entities", {}),
            raw_data=data.get("raw_data", {}),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )

    def route(self, signal: Signal) -> Signal:
        """Normalize and route a signal.

        Args:
            signal: Raw signal to normalize

        Returns:
            Normalized signal with extracted entities, subtype, and focus
        """
        # Extract entities from all sources
        entities = self._extract_entities(signal)

        # Extract indicators from artifact_context
        indicators = self._extract_indicators(signal)

        # Determine signal subtype based on content
        signal_subtype = self._determine_signal_subtype(signal)

        # Select entity focus based on signal type and available entities
        entity_focus = self._select_entity_focus(signal, entities)

        # Update signal metadata with routing info
        updated_metadata = dict(signal.metadata)
        updated_metadata["signal_subtype"] = signal_subtype
        updated_metadata["entity_focus_primary"] = entity_focus

        return Signal(
            signal_id=signal.signal_id,
            signal_type=signal.signal_type,
            timestamp=signal.timestamp,
            source=signal.source,
            title=signal.title,
            description=signal.description,
            severity=signal.severity,
            entities=entities,
            indicators=indicators,
            tags=signal.tags,
            raw_data=signal.raw_data,
            metadata=updated_metadata,
            detection_context=signal.detection_context,
            entity_context=signal.entity_context,
            artifact_context=signal.artifact_context,
            vuln_context=signal.vuln_context,
        )

    def _extract_entities(self, signal: Signal) -> Dict[str, Any]:
        """Extract entities from entity_context and existing entities."""
        entities = dict(signal.entities)  # Copy existing

        # Extract from entity_context
        if signal.entity_context:
            if signal.entity_context.hostname and "hostname" not in entities:
                entities["hostname"] = [signal.entity_context.hostname]
            if signal.entity_context.username and "username" not in entities:
                entities["username"] = [signal.entity_context.username]
            if signal.entity_context.src_ip and "ip" not in entities:
                entities["ip"] = [signal.entity_context.src_ip]

        return entities

    def _extract_indicators(self, signal: Signal) -> Dict[str, str]:
        """Extract indicators from artifact_context."""
        indicators = dict(signal.indicators)

        if signal.artifact_context:
            for attr in ["domain", "ip", "sha256", "md5", "url"]:
                val = getattr(signal.artifact_context, attr, None)
                if val and attr not in indicators:
                    indicators[attr] = val

        return indicators

    def _determine_signal_subtype(self, signal: Signal) -> str:
        """Determine signal subtype based on content analysis.

        Returns one of: auth, endpoint, network, email, vuln, ioc, hunt, user, other
        """
        signal_type = signal.signal_type.value.lower()

        # Direct mapping for some signal types
        if signal_type == "cve":
            return "vuln"
        if signal_type == "ioc":
            return "ioc"
        if signal_type == "hunt":
            return "hunt"
        if signal_type == "user_report":
            return "user"

        # Content-based detection for SIEM alerts
        description_lower = signal.description.lower()
        title_lower = signal.title.lower()
        tags = [t.lower() for t in signal.tags]
        searchable_text = f"{description_lower} {title_lower} {' '.join(tags)}"

        # Check for authentication-related
        if any(
            kw in searchable_text
            for kw in ["login", "auth", "password", "credential", "brute"]
        ):
            return "auth"

        # Check for email-related
        if any(
            kw in searchable_text for kw in ["email", "phishing", "spam", "attachment"]
        ):
            return "email"

        # Check for network-related
        if any(
            kw in searchable_text
            for kw in ["network", "firewall", "dns", "c2", "beacon"]
        ):
            return "network"

        # Check for endpoint-related (default for many detections)
        if any(
            kw in searchable_text
            for kw in ["process", "powershell", "script", "malware", "execution"]
        ):
            return "endpoint"

        return "other"

    def _select_entity_focus(self, signal: Signal, entities: Dict[str, Any]) -> str:
        """Select primary entity focus based on signal type and available entities.

        Returns the primary entity type to focus on for entity behavior tracking.
        """
        signal_type = signal.signal_type.value.lower()

        # Signal type specific preferences
        focus_preferences = {
            "siem_alert": ["hostname", "username", "ip"],
            "ioc": ["hostname", "ip", "domain"],
            "cve": ["hostname", "asset_group"],
            "hunt": ["hostname", "username"],
            "user_report": ["username", "hostname"],
        }

        preferences = focus_preferences.get(signal_type, ["hostname", "username", "ip"])

        # Return first available entity type
        for entity_type in preferences:
            if entity_type in entities and entities[entity_type]:
                return entity_type

        return "hostname"  # Default fallback
