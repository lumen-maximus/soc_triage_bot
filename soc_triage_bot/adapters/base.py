"""Base adapter interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ..models import EnrichmentResult, Signal


@dataclass
class BucketedSeriesResult:
    """Result from get_bucketed_series query.

    Contains zero-filled time series buckets and metadata about data quality.
    Per forecasting spec Section 2 (Data requirements and backfill contract).
    """

    # Time series data: list of (bucket_start_utc, count) tuples
    buckets: List[Tuple[datetime, int]] = field(default_factory=list)

    # Metadata
    track_key: str = (
        ""  # 'A_detection_rule', 'B_indicator_artifact', 'C_entity_behavior'
    )
    entity_id: str = ""  # e.g., 'rule_id=123', 'domain=evil.com'
    bucket_minutes: int = 15
    start_utc: Optional[datetime] = None
    end_utc: Optional[datetime] = None

    # Data quality
    total_buckets: int = 0
    missing_buckets: int = 0
    missing_pct: float = 0.0
    data_completeness: str = "COMPLETE"  # 'COMPLETE' or 'PARTIAL'
    missing_ranges: List[Tuple[datetime, datetime]] = field(default_factory=list)

    # Backfill support
    late_arrival_backfill_supported: bool = False
    last_backfill_utc: Optional[datetime] = None


class BaseAdapter(ABC):
    """Base class for all enrichment adapters."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the adapter with configuration.

        Args:
            config: Adapter-specific configuration
        """
        self.config = config or {}
        self.name = self.__class__.__name__.replace("Adapter", "").lower()

    @abstractmethod
    async def enrich(self, signal: Signal) -> EnrichmentResult:
        """Enrich a signal with additional context.

        Args:
            signal: The signal to enrich

        Returns:
            EnrichmentResult with enrichment data
        """
        pass

    async def get_bucketed_series(
        self,
        track_key: str,
        entity_id: str,
        start_utc: datetime,
        end_utc: datetime,
        bucket_minutes: int = 15,
    ) -> BucketedSeriesResult:
        """Get bucketed time series for forecasting.

        This method must return **zero-filled continuous buckets** from start_utc
        to end_utc. If no events in a bucket, count = 0.

        Per forecasting spec Section 9 (Adapter query contract):
        - Returns complete, zero-filled time buckets
        - Includes meta: completeness, late_arrival_backfill_supported
        - Computes missing_pct = buckets_missing / total_buckets

        Args:
            track_key: One of 'A_detection_rule', 'B_indicator_artifact', 'C_entity_behavior'
            entity_id: Entity identifier (e.g., 'rule_id=123', 'domain=evil.com')
            start_utc: Start of time range
            end_utc: End of time range
            bucket_minutes: Bucket size in minutes (default 15)

        Returns:
            BucketedSeriesResult with zero-filled buckets and metadata.
        """
        # Default implementation returns empty result
        # Subclasses should override for their data source
        return BucketedSeriesResult(
            track_key=track_key,
            entity_id=entity_id,
            bucket_minutes=bucket_minutes,
            start_utc=start_utc,
            end_utc=end_utc,
            data_completeness="PARTIAL",
            late_arrival_backfill_supported=False,
        )

    async def health_check(self) -> bool:
        """Check if the adapter is healthy and can be used.

        Returns:
            True if adapter is healthy, False otherwise
        """
        return True
