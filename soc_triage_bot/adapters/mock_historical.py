"""Mock historical adapter for demo mode ONLY.

Generates realistic historical data with daily and weekly patterns.
"""

from datetime import datetime, timedelta
from typing import Optional

import numpy as np

from .base_historical import HistoricalQueryCapable, TimeSeriesPoint, TimeSeriesResult


class MockHistoricalAdapter:
    """Mock adapter for generating realistic historical time series data.
    
    Used ONLY in demo mode to provide historical data for forecasting demonstrations.
    """
    
    def __init__(self):
        """Initialize mock historical adapter."""
        self._name = "mock_historical"
    
    @property
    def name(self) -> str:
        """Adapter name."""
        return self._name
    
    def supports_historical_query(self) -> bool:
        """Always supports historical queries."""
        return True
    
    async def query_time_series(
        self,
        entity_key: str,
        entity_value: str,
        metric_name: str,
        start_time: datetime,
        end_time: datetime,
        bucket_minutes: int = 15,
    ) -> Optional[TimeSeriesResult]:
        """Generate realistic time series data with patterns.
        
        Args:
            entity_key: Entity key (e.g., 'rule_id', 'hostname')
            entity_value: Entity value (e.g., 'RULE-001', 'workstation-01')
            metric_name: Metric name (e.g., 'alert_count', 'sighting_count')
            start_time: Start of time range
            end_time: End of time range
            bucket_minutes: Bucket size in minutes
            
        Returns:
            TimeSeriesResult with generated data
        """
        # Determine base rate based on track type (inferred from entity_key)
        if "rule" in entity_key.lower() or "detection" in entity_key.lower():
            base_rate = 2.0  # Track A: ~2 alerts per hour
        elif "domain" in entity_key.lower() or "ip" in entity_key.lower() or "hash" in entity_key.lower():
            base_rate = 0.5  # Track B: ~0.5 sightings per hour
        else:
            base_rate = 5.0  # Track C: ~5 events per hour
        
        # Generate time series points
        points = []
        current_time = start_time
        
        while current_time <= end_time:
            # Daily pattern: higher during work hours (9-17), lower at night
            hour = current_time.hour
            if 9 <= hour <= 17:
                daily_factor = 1.5
            elif 0 <= hour <= 6:
                daily_factor = 0.3
            else:
                daily_factor = 0.8
            
            # Weekly pattern: lower on weekends
            weekday = current_time.weekday()
            if weekday >= 5:  # Saturday=5, Sunday=6
                weekly_factor = 0.4
            else:
                weekly_factor = 1.0
            
            # Calculate expected rate with patterns
            expected_rate = base_rate * daily_factor * weekly_factor
            
            # Convert to rate per bucket (bucket_minutes / 60 gives hours)
            bucket_rate = expected_rate * (bucket_minutes / 60.0)
            
            # Generate realistic count using Poisson distribution
            value = float(np.random.poisson(bucket_rate))
            
            # Occasional spikes (~2% probability)
            if np.random.random() < 0.02:
                value *= np.random.uniform(3.0, 5.0)
            
            points.append(TimeSeriesPoint(
                timestamp=current_time,
                value=value
            ))
            
            current_time += timedelta(minutes=bucket_minutes)
        
        return TimeSeriesResult(
            entity_key=entity_key,
            entity_value=entity_value,
            metric_name=metric_name,
            points=points,
            bucket_minutes=bucket_minutes,
            source_system="mock_historical",
            missing_buckets=0,
            total_buckets=len(points)
        )
