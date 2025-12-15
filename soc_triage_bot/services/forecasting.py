"""ETS (Exponential Smoothing) forecasting service."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

import numpy as np


class ForecastingService:
    """Service for ETS multi-horizon forecasting with rolling backtest."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize forecasting service.

        Args:
            config: Configuration including thresholds and parameters
        """
        self.config = config or {}
        self.threshold = self.config.get("threshold", 0.8)
        self.horizons = self.config.get("horizons", [1, 7, 30])  # 1h, 7d, 30d
        self.backtest_window = self.config.get("backtest_window", 90)  # days

    def forecast(
        self, historical_data: List[Dict[str, Any]], signal_type: str
    ) -> Dict[str, Any]:
        """Generate multi-horizon forecast using ETS.

        This is a simplified implementation. In production, this would use
        statsmodels ExponentialSmoothing with proper parameter tuning.

        Args:
            historical_data: Historical signal data points
            signal_type: Type of signal to forecast

        Returns:
            Dictionary with forecast values and metrics
        """
        if not historical_data or len(historical_data) < 3:
            # Not enough data for forecasting
            return {
                "forecast_available": False,
                "reason": "insufficient_data",
                "data_points": len(historical_data),
            }

        try:
            # Extract time series values
            values = [d.get("count", 0) for d in historical_data]
            timestamps = [d.get("timestamp") for d in historical_data]

            # Simple exponential smoothing (mock implementation)
            alpha = 0.3  # Smoothing parameter
            forecast_result = self._simple_ets(values, alpha)

            # Calculate anomaly score
            recent_value = values[-1] if values else 0
            anomaly_score = self._calculate_anomaly_score(
                recent_value, forecast_result["forecast"]
            )

            # Rolling backtest
            backtest_results = self._rolling_backtest(values, alpha)

            return {
                "forecast_available": True,
                "signal_type": signal_type,
                "current_value": recent_value,
                "forecast": forecast_result["forecast"],
                "forecast_horizons": {
                    "1h": forecast_result["forecast"],
                    "7d": forecast_result["forecast"] * 7,
                    "30d": forecast_result["forecast"] * 30,
                },
                "anomaly_score": anomaly_score,
                "exceeds_threshold": anomaly_score > self.threshold,
                "backtest_mape": backtest_results["mape"],
                "backtest_rmse": backtest_results["rmse"],
                "confidence": backtest_results["confidence"],
            }
        except Exception as e:
            return {
                "forecast_available": False,
                "reason": str(e),
                "data_points": len(historical_data),
            }

    def _simple_ets(self, values: List[float], alpha: float) -> Dict[str, Any]:
        """Simple exponential smoothing.

        Args:
            values: Time series values
            alpha: Smoothing parameter (0-1)

        Returns:
            Dictionary with smoothed values and forecast
        """
        if not values:
            return {"forecast": 0, "level": 0}

        # Initialize level with first value
        level = values[0]
        smoothed = [level]

        # Smooth the series
        for value in values[1:]:
            level = alpha * value + (1 - alpha) * level
            smoothed.append(level)

        # Forecast is the last level
        return {"forecast": level, "level": level, "smoothed": smoothed}

    def _calculate_anomaly_score(self, actual: float, forecast: float) -> float:
        """Calculate anomaly score based on deviation from forecast.

        Args:
            actual: Actual observed value
            forecast: Forecasted value

        Returns:
            Anomaly score between 0 and 1
        """
        if forecast == 0:
            return 1.0 if actual > 0 else 0.0

        deviation = abs(actual - forecast) / (forecast + 1)
        # Normalize to 0-1 range using sigmoid
        score = 2 / (1 + np.exp(-deviation)) - 1
        return min(max(score, 0.0), 1.0)

    def _rolling_backtest(self, values: List[float], alpha: float) -> Dict[str, Any]:
        """Perform rolling backtest to estimate forecast accuracy.

        Args:
            values: Historical time series values
            alpha: Smoothing parameter

        Returns:
            Dictionary with backtest metrics
        """
        if len(values) < 5:
            return {"mape": 0.0, "rmse": 0.0, "confidence": 0.5}

        # Use last 20% of data for backtesting
        split_point = int(len(values) * 0.8)
        train_data = values[:split_point]
        test_data = values[split_point:]

        errors = []
        abs_errors = []

        for i, actual in enumerate(test_data):
            # Train on data up to this point
            forecast_result = self._simple_ets(train_data + test_data[:i], alpha)
            forecast = forecast_result["forecast"]

            # Calculate errors
            error = actual - forecast
            errors.append(error**2)
            if actual != 0:
                abs_errors.append(abs(error) / abs(actual))

        # Calculate metrics
        rmse = np.sqrt(np.mean(errors)) if errors else 0.0
        mape = np.mean(abs_errors) * 100 if abs_errors else 0.0

        # Confidence based on accuracy (inverse of MAPE)
        confidence = max(0.0, min(1.0, 1.0 - (mape / 100)))

        return {
            "mape": round(mape, 2),
            "rmse": round(rmse, 2),
            "confidence": round(confidence, 2),
        }
