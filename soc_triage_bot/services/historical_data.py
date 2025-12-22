"""Historical data service for automatic data fetching.

Fetches historical time series data from adapters that support historical queries.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from ..adapters.base_historical import HistoricalQueryCapable, TimeSeriesResult
from ..config import get_forecast_config, get_signal_type_config
from ..models import Signal
from .forecasting import MultiTrackHistoricalData, TrackTimeSeries


class HistoricalDataService:
    """Service for fetching historical data for forecasting.

    Uses YAML configuration to determine which entity keys and metrics to query
    for each track based on signal type.
    """

    def __init__(self, adapters: List[HistoricalQueryCapable]):
        """Initialize historical data service.

        Args:
            adapters: List of adapters that support historical queries
        """
        self.adapters = adapters
        self.forecast_config = get_forecast_config()

    async def fetch_for_signal(
        self, signal: Signal
    ) -> Optional[MultiTrackHistoricalData]:
        """Fetch historical data for all tracks of a signal.

        Args:
            signal: Signal to fetch historical data for

        Returns:
            MultiTrackHistoricalData or None if insufficient data
        """
        # Get signal type config from YAML
        signal_type = signal.signal_type.value
        st_config = get_signal_type_config(signal_type)

        # Calculate time range from YAML config
        history_days = self.forecast_config.history_window_days_default
        bucket_minutes = self.forecast_config.bucket_minutes_default

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=history_days)

        # Fetch each track
        track_a = await self._fetch_track(
            signal,
            st_config.track_a,
            "A_detection_rule",
            start_time,
            end_time,
            bucket_minutes,
        )

        track_b = await self._fetch_track(
            signal,
            st_config.track_b,
            "B_indicator_artifact",
            start_time,
            end_time,
            bucket_minutes,
        )

        track_c = await self._fetch_track(
            signal,
            st_config.track_c,
            "C_entity_behavior",
            start_time,
            end_time,
            bucket_minutes,
        )

        # Return None if no tracks have data
        if not track_a and not track_b and not track_c:
            return None

        return MultiTrackHistoricalData(
            track_a=track_a, track_b=track_b, track_c=track_c
        )

    async def _fetch_track(
        self,
        signal: Signal,
        track_config,
        track_name: str,
        start_time: datetime,
        end_time: datetime,
        bucket_minutes: int,
    ) -> Optional[TrackTimeSeries]:
        """Fetch historical data for a single track.

        Args:
            signal: Signal to extract entity from
            track_config: TrackConfig from YAML
            track_name: Track identifier (for error messages)
            start_time: Start of time range
            end_time: End of time range
            bucket_minutes: Bucket size in minutes

        Returns:
            TrackTimeSeries or None if no data available
        """
        # Check if track is enabled
        if not track_config.enabled:
            return None

        # Extract entity key and value using YAML config
        entity_key, entity_value = self._extract_entity(signal, track_config)
        if not entity_key or not entity_value:
            return None

        # Get metric name from YAML config
        metrics = track_config.metrics_preferred
        if not metrics:
            return None
        metric_name = metrics[0]  # Use first preferred metric

        # Query adapters in order until one returns data
        for adapter in self.adapters:
            if not adapter.supports_historical_query():
                continue

            try:
                result = await adapter.query_time_series(
                    entity_key=entity_key,
                    entity_value=entity_value,
                    metric_name=metric_name,
                    start_time=start_time,
                    end_time=end_time,
                    bucket_minutes=bucket_minutes,
                )

                if result and result.points:
                    return self._convert_to_track_series(result, track_name)
            except Exception:
                # Graceful failure - try next adapter
                continue

        return None

    def _extract_entity(
        self, signal: Signal, track_config
    ) -> Tuple[Optional[str], Optional[str]]:
        """Extract entity key and value from signal using YAML config.

        Args:
            signal: Signal to extract from
            track_config: TrackConfig with keys_preferred and fallbacks

        Returns:
            Tuple of (entity_key, entity_value) or (None, None)
        """
        all_keys = track_config.keys_preferred + track_config.fallbacks

        for key in all_keys:
            # Check in signal entities
            if key in signal.entities and signal.entities[key]:
                values = signal.entities[key]
                value = values[0] if isinstance(values, list) else values
                return (key, value)

            # Check in indicators
            if key in signal.indicators:
                return (key, signal.indicators[key])

            # Check in detection_context
            if signal.detection_context:
                if key == "rule_id" and signal.detection_context.rule_id:
                    return (key, signal.detection_context.rule_id)
                if key == "detection_name" and signal.detection_context.detection_name:
                    return (key, signal.detection_context.detection_name)

            # Check in artifact_context
            if signal.artifact_context:
                artifact_val = getattr(signal.artifact_context, key, None)
                if artifact_val:
                    return (key, artifact_val)

            # Check in entity_context
            if signal.entity_context:
                entity_val = getattr(signal.entity_context, key, None)
                if entity_val:
                    return (key, entity_val)

            # Check in vuln_context
            if signal.vuln_context:
                if key == "cve" and signal.vuln_context.cve:
                    return (key, signal.vuln_context.cve)
                if key == "asset_group" and signal.vuln_context.asset_group:
                    return (key, signal.vuln_context.asset_group)

        return (None, None)

    def _convert_to_track_series(
        self, result: TimeSeriesResult, track_name: str
    ) -> TrackTimeSeries:
        """Convert TimeSeriesResult to TrackTimeSeries.

        Args:
            result: TimeSeriesResult from adapter
            track_name: Track identifier

        Returns:
            TrackTimeSeries for forecasting service
        """
        timestamps = [point.timestamp for point in result.points]
        values = [point.value for point in result.points]

        # Calculate data quality metrics
        missing_pct = 0.0
        if result.total_buckets > 0:
            missing_pct = result.missing_buckets / result.total_buckets

        data_completeness = "COMPLETE" if missing_pct < 0.05 else "PARTIAL"

        return TrackTimeSeries(
            track_name=track_name,
            entity_key=result.entity_key,
            entity_value=result.entity_value,
            metric_name=result.metric_name,
            timestamps=timestamps,
            values=values,
            bucket_minutes=result.bucket_minutes,
            history_start_utc=timestamps[0] if timestamps else None,
            history_end_utc=timestamps[-1] if timestamps else None,
            total_buckets=result.total_buckets,
            missing_buckets=result.missing_buckets,
            missing_pct=missing_pct,
            data_completeness=data_completeness,
            late_arrival_backfill_supported=False,
        )
