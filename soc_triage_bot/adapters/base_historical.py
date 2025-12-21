"""Historical query protocol and types."""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Protocol


@dataclass
class TimeSeriesPoint:
    """Single point in a time series."""
    timestamp: datetime
    value: float


@dataclass
class TimeSeriesResult:
    """Result from a historical time-series query."""
    entity_key: str
    entity_value: str
    metric_name: str
    points: List[TimeSeriesPoint]
    bucket_minutes: int = 15
    source_system: str = ""
    missing_buckets: int = 0
    total_buckets: int = 0


class HistoricalQueryCapable(Protocol):
    """Protocol for adapters that support historical queries."""
    
    @property
    def name(self) -> str: ...
    
    def supports_historical_query(self) -> bool: ...
    
    async def query_time_series(
        self,
        entity_key: str,
        entity_value: str,
        metric_name: str,
        start_time: datetime,
        end_time: datetime,
        bucket_minutes: int = 15,
    ) -> Optional[TimeSeriesResult]: ...
