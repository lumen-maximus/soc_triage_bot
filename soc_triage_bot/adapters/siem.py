"""SIEM adapter for enrichment."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

from ..models import EnrichmentResult, EnrichmentStatus, Signal
from .base import BaseAdapter, BucketedSeriesResult


class SIEMAdapter(BaseAdapter):
    """Generic SIEM adapter for additional context."""

    # Default late arrival window for backfill (spec Section 2)
    LATE_ARRIVAL_WINDOW_MINUTES = 120

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
