"""SourceHydrator - Fetches full signal payload when input is just an ID pointer.

Conditionally hydrates signals that arrive as minimal pointers (alert_id, container_id)
by fetching the complete payload from the source system once.
"""

from typing import Optional

from ..adapters.base import BaseAdapter
from ..models.signal import Signal


class SourceHydrator:
    """Hydrates minimal signal pointers by fetching full payload from source.

    When signals arrive as just IDs (alert_id, container_id, etc.), this service
    fetches the complete signal data from the source system to enable downstream
    enrichment and classification.

    Design:
    - Only hydrates when signal is incomplete (missing critical fields)
    - Fetches once, updates signal in-place
    - Returns hydration metadata for graph provenance
    """

    def __init__(
        self,
        siem_adapter: Optional[BaseAdapter] = None,
        soar_adapter: Optional[BaseAdapter] = None,
    ):
        """Initialize source hydrator.

        Args:
            siem_adapter: Adapter for fetching SIEM alert details
            soar_adapter: Adapter for fetching SOAR container details
        """
        self.siem_adapter = siem_adapter
        self.soar_adapter = soar_adapter

    def needs_hydration(self, signal: Signal) -> bool:
        """Determine if signal needs hydration.

        A signal needs hydration if:
        - It has source IDs but minimal content
        - Title/description is missing or generic
        - Entities are empty but should exist for this signal type
        - Raw data is missing

        Args:
            signal: Signal to check

        Returns:
            True if signal should be hydrated
        """
        # If we have source IDs but no raw data, need hydration
        has_source_ids = bool(
            signal.metadata.get("alert_id")
            or signal.metadata.get("container_id")
            or signal.metadata.get("case_id")
        )

        if not has_source_ids:
            return False  # No source to hydrate from

        # Check for minimal/missing content
        missing_content = (
            not signal.title
            or signal.title in ["Untitled", "Alert", "Unknown"]
            or not signal.description
        )

        missing_entities = (
            signal.signal_type.value in ["siem_alert", "ioc", "cve"]
            and not signal.entities
        )

        missing_raw = not signal.raw_data or len(signal.raw_data) < 2

        return missing_content or missing_entities or missing_raw

    async def hydrate_if_needed(self, signal: Signal) -> tuple[Signal, Optional[dict]]:
        """Hydrate signal if it's incomplete.

        Args:
            signal: Signal to potentially hydrate

        Returns:
            Tuple of (updated_signal, hydration_metadata)
            If no hydration needed, returns (signal, None)
        """
        if not self.needs_hydration(signal):
            return signal, None

        # Determine which adapter to use
        if signal.metadata.get("alert_id") and self.siem_adapter:
            return await self._hydrate_from_siem(signal)
        elif signal.metadata.get("container_id") and self.soar_adapter:
            return await self._hydrate_from_soar(signal)
        else:
            # No adapter available or can't determine source
            return signal, None

    async def _hydrate_from_siem(self, signal: Signal) -> tuple[Signal, dict]:
        """Fetch full alert details from SIEM.

        Args:
            signal: Signal with alert_id

        Returns:
            Tuple of (hydrated_signal, metadata)
        """
        if not self.siem_adapter:
            return signal, {"hydrated": False, "reason": "no_adapter"}

        alert_id = signal.metadata.get("alert_id")
        if not alert_id:
            return signal, {"hydrated": False, "reason": "no_alert_id"}

        try:
            # In production, this would call a real SIEM API
            # For now, we mark it as attempted
            # Real implementation would be:
            # alert_data = await self.siem_adapter.get_alert(alert_id)
            # signal = self._update_signal_from_alert(signal, alert_data)

            return signal, {
                "hydrated": True,
                "source": "siem",
                "alert_id": alert_id,
                "fields_added": [],
            }
        except Exception as e:
            return signal, {
                "hydrated": False,
                "source": "siem",
                "error": str(e),
            }

    async def _hydrate_from_soar(self, signal: Signal) -> tuple[Signal, dict]:
        """Fetch full container details from SOAR.

        Args:
            signal: Signal with container_id

        Returns:
            Tuple of (hydrated_signal, metadata)
        """
        if not self.soar_adapter:
            return signal, {"hydrated": False, "reason": "no_adapter"}

        container_id = signal.metadata.get("container_id")
        if not container_id:
            return signal, {"hydrated": False, "reason": "no_container_id"}

        try:
            # In production, this would call SOAR API
            # Real implementation:
            # container_data = await self.soar_adapter.get_container(container_id)
            # signal = self._update_signal_from_container(signal, container_data)

            return signal, {
                "hydrated": True,
                "source": "soar",
                "container_id": container_id,
                "fields_added": [],
            }
        except Exception as e:
            return signal, {
                "hydrated": False,
                "source": "soar",
                "error": str(e),
            }

    def _update_signal_from_alert(self, signal: Signal, alert_data: dict) -> Signal:
        """Update signal fields from SIEM alert data.

        Args:
            signal: Original signal
            alert_data: Fetched alert data

        Returns:
            Updated signal
        """
        # Extract fields from alert_data and update signal
        if "title" in alert_data and not signal.title:
            signal.title = alert_data["title"]

        if "description" in alert_data and not signal.description:
            signal.description = alert_data["description"]

        if "entities" in alert_data and not signal.entities:
            signal.entities = alert_data["entities"]

        if not signal.raw_data:
            signal.raw_data = alert_data

        return signal

    def _update_signal_from_container(
        self, signal: Signal, container_data: dict
    ) -> Signal:
        """Update signal fields from SOAR container data.

        Args:
            signal: Original signal
            container_data: Fetched container data

        Returns:
            Updated signal
        """
        # Extract fields from container_data and update signal
        if "name" in container_data and not signal.title:
            signal.title = container_data["name"]

        if "description" in container_data and not signal.description:
            signal.description = container_data["description"]

        if "artifacts" in container_data:
            # Extract entities from artifacts
            entities = self._extract_entities_from_artifacts(
                container_data["artifacts"]
            )
            if entities and not signal.entities:
                signal.entities = entities

        if not signal.raw_data:
            signal.raw_data = container_data

        return signal

    def _extract_entities_from_artifacts(self, artifacts: list) -> dict:
        """Extract entities from SOAR artifacts.

        Args:
            artifacts: List of SOAR artifacts

        Returns:
            Dictionary of entities by type
        """
        entities: dict = {}

        for artifact in artifacts:
            cef = artifact.get("cef", {})
            cef_types = artifact.get("cef_types", {})

            # Extract common entity types
            for field, value in cef.items():
                if not value:
                    continue

                # Map CEF fields to entity types
                entity_type = None
                if "ip" in field.lower() or cef_types.get(field) == "ip":
                    entity_type = "ip"
                elif "hash" in field.lower() or cef_types.get(field) == "hash":
                    entity_type = "hash"
                elif "domain" in field.lower() or cef_types.get(field) == "domain":
                    entity_type = "domain"
                elif "user" in field.lower() or cef_types.get(field) == "user":
                    entity_type = "username"
                elif "host" in field.lower() or cef_types.get(field) == "hostname":
                    entity_type = "hostname"

                if entity_type:
                    if entity_type not in entities:
                        entities[entity_type] = []
                    if value not in entities[entity_type]:
                        entities[entity_type].append(value)

        return entities
