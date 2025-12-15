"""ETS (Exponential Smoothing) multi-track forecasting service.

Implements Track A (rule/detection), Track B (indicator/IOC), Track C (entity behavior)
forecasting with H1/H6/H24 horizons and rolling backtest validation.

Per forecasting spec:
- Section 3: Multi-horizon totals (H1, H6, H24)
- Section 4: ETS model selection
- Section 5: Rolling-origin backtesting with MASE/sMAPE/RMSE
- Section 6: Spike threshold calibration from residuals
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from ..models import Signal
from ..models.triage_report import (
    ForecastBacktest,
    ForecastBundle,
    ForecastHorizonMetrics,
    ForecastHorizonResult,
    ForecastHorizonThresholds,
    ForecastLatest,
    ForecastModelMeta,
    ForecastSeasonality,
    ForecastSeriesMeta,
    ForecastTrack,
    ForecastTracks,
    get_track_config,
)


@dataclass
class TrackTimeSeries:
    """Time series data for a single track.

    Per spec Section 2: Data requirements and backfill contract.
    """

    track_name: str  # 'rule', 'ioc', 'entity'
    entity_key: str  # e.g., 'rule_id', 'domain', 'hostname'
    entity_value: str  # e.g., 'RULE-001', 'evil.com', 'workstation-01'
    metric_name: str  # e.g., 'alert_count', 'sighting_count'
    timestamps: List[datetime] = field(default_factory=list)
    values: List[float] = field(default_factory=list)
    bucket_minutes: int = 15  # Default per spec

    # Data quality metadata (spec Section 2)
    history_start_utc: Optional[datetime] = None
    history_end_utc: Optional[datetime] = None
    total_buckets: int = 0
    missing_buckets: int = 0
    missing_pct: float = 0.0
    data_completeness: str = "COMPLETE"  # 'COMPLETE' or 'PARTIAL'
    late_arrival_backfill_supported: bool = False


@dataclass
class MultiTrackHistoricalData:
    """Structured historical data for multi-track forecasting."""

    track_a: Optional[TrackTimeSeries] = None  # Rule/detection
    track_b: Optional[TrackTimeSeries] = None  # Indicator/IOC
    track_c: Optional[TrackTimeSeries] = None  # Entity behavior


# Reliability level constants
RELIABILITY_LOW = "LOW"
RELIABILITY_MEDIUM = "MEDIUM"
RELIABILITY_HIGH = "HIGH"


class ForecastingService:
    """Service for multi-track ETS forecasting with H1/H6/H24 horizons.

    Implements:
    - Track A: Rule/detection frequency trends
    - Track B: Indicator/IOC sighting trends
    - Track C: Entity behavior anomaly trends

    Each track produces forecasts for H1 (1 hour), H6 (6 hours), H24 (24 hours).

    Per forecasting spec:
    - Section 5: Quality gates for reliability (MASE, coverage, missing_pct)
    - Section 6: Spike threshold calibration from backtest residuals
    - Section 8: Policy gates for triage influence
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize forecasting service.

        Args:
            config: Configuration including thresholds and parameters
        """
        self.config = config or {}
        self.threshold = self.config.get("threshold", 0.8)
        self.bucket_minutes = self.config.get("bucket_minutes", 15)  # Spec default
        self.min_history_points = self.config.get("min_history_points", 24)
        self.backtest_window_days = self.config.get("backtest_window_days", 14)
        self.backtest_splits = self.config.get("backtest_splits", 5)
        self.alpha = self.config.get("alpha", 0.3)  # ETS smoothing parameter

        # Quality gate thresholds (spec Section 5)
        self.mase_medium_threshold = self.config.get("mase_medium_threshold", 1.3)
        self.mase_high_threshold = self.config.get("mase_high_threshold", 1.1)
        self.coverage_high_min = self.config.get("coverage_high_min", 0.85)
        self.coverage_high_max = self.config.get("coverage_high_max", 0.98)
        self.missing_pct_medium_max = self.config.get("missing_pct_medium_max", 0.05)
        self.missing_pct_high_max = self.config.get("missing_pct_high_max", 0.02)

        # Minimum history requirements (spec Section 2)
        self.min_history_days_rule = self.config.get("min_history_days_rule", 28)
        self.min_history_days_ioc = self.config.get("min_history_days_ioc", 14)
        self.min_history_days_entity = self.config.get("min_history_days_entity", 28)

    def forecast_multi_track(
        self,
        signal: Signal,
        historical_data: MultiTrackHistoricalData,
    ) -> ForecastBundle:
        """Generate multi-track ETS forecast for a signal.

        Args:
            signal: The signal being triaged
            historical_data: Structured historical data with track_a/b/c series

        Returns:
            ForecastBundle with all three tracks populated
        """
        # Get track config for this signal type
        track_config = get_track_config(signal.signal_type.value)

        tracks = ForecastTracks(
            rule=self._forecast_track(historical_data.track_a, "rule", track_config),
            ioc=self._forecast_track(historical_data.track_b, "ioc", track_config),
            entity=self._forecast_track(
                historical_data.track_c, "entity", track_config
            ),
        )

        return ForecastBundle(
            enabled=True,
            bucket_minutes=self.bucket_minutes,
            seasonality=ForecastSeasonality(mode="auto"),
            tracks=tracks,
        )

    def _forecast_track(
        self,
        series: Optional[TrackTimeSeries],
        track_name: str,
        track_config: Optional[Any],
    ) -> Optional[ForecastTrack]:
        """Generate forecast for a single track.

        Args:
            series: Time series data for this track
            track_name: 'rule', 'ioc', or 'entity'
            track_config: Track configuration from signal type

        Returns:
            ForecastTrack or None if insufficient data
        """
        if not series or len(series.values) < self.min_history_points:
            return None

        values = series.values
        history_points = len(values)

        # Run ETS forecast
        ets_result = self._simple_ets(values, self.alpha)
        forecast_value = ets_result["forecast"]
        current_value = values[-1] if values else 0

        # Calculate horizons (H1, H6, H24)
        horizons = self._calculate_horizons(forecast_value)

        # Run backtest with MASE calculation
        backtest = self._rolling_backtest(values)

        # Calibrate thresholds from backtest residuals
        calibrated_thresholds = self._calibrate_thresholds(backtest)
        if calibrated_thresholds:
            backtest.thresholds = calibrated_thresholds

        # Calculate latest metrics
        latest = self._calculate_latest(current_value, forecast_value, values)

        # Get H1 thresholds for interpretation (primary horizon)
        h1_thresholds = (
            calibrated_thresholds.get("H1") if calibrated_thresholds else None
        )

        # Determine interpretation based on anomaly and calibrated thresholds
        interpretation = self._generate_interpretation(
            track_name,
            current_value,
            forecast_value,
            latest.anomaly_score or 0,
            thresholds=h1_thresholds,
        )

        # Build series metadata from TrackTimeSeries
        series_meta = ForecastSeriesMeta(
            history_start_utc=(
                series.history_start_utc.isoformat()
                if series.history_start_utc
                else None
            ),
            history_end_utc=(
                series.history_end_utc.isoformat() if series.history_end_utc else None
            ),
            bucket_minutes=series.bucket_minutes,
            missing_pct=series.missing_pct,
            data_completeness=series.data_completeness,
        )

        # Build model metadata from ETS config used
        model_meta = ForecastModelMeta(
            ets_variant=ets_result.get("variant", "SES"),
            alpha=self.alpha,
            beta=ets_result.get("beta"),
            gamma=ets_result.get("gamma"),
            seasonal_period=ets_result.get("seasonal_period"),
            damped=ets_result.get("damped", False),
        )

        # Calculate reliability from backtest metrics and data quality
        reliability = self._calculate_reliability(
            backtest, series.missing_pct, track_name
        )

        return ForecastTrack(
            metric_key=f"{series.entity_key}:{series.entity_value}",
            metric_name=series.metric_name,
            series_window=f"{history_points * series.bucket_minutes // 60}h",
            history_points=history_points,
            horizons=horizons,
            latest=latest,
            backtest=backtest,
            interpretation=interpretation,
            confidence=backtest.notes[0] if backtest.notes else "medium",
            reliability=reliability,
            series_meta=series_meta,
            model_meta=model_meta,
        )

    def _calculate_horizons(
        self, base_forecast: float
    ) -> Dict[str, ForecastHorizonResult]:
        """Calculate H1, H6, H24 horizon forecasts."""
        return {
            "H1": ForecastHorizonResult(
                total=round(base_forecast, 2),
                lower=round(base_forecast * 0.7, 2),
                upper=round(base_forecast * 1.3, 2),
            ),
            "H6": ForecastHorizonResult(
                total=round(base_forecast * 6, 2),
                lower=round(base_forecast * 6 * 0.7, 2),
                upper=round(base_forecast * 6 * 1.3, 2),
            ),
            "H24": ForecastHorizonResult(
                total=round(base_forecast * 24, 2),
                lower=round(base_forecast * 24 * 0.6, 2),
                upper=round(base_forecast * 24 * 1.4, 2),
            ),
        }

    def _calculate_latest(
        self, current: float, forecast: float, values: List[float]
    ) -> ForecastLatest:
        """Calculate latest value metrics."""
        anomaly_score = self._calculate_anomaly_score(current, forecast)

        if forecast > 0:
            ratio = current / forecast
            if ratio > 1.5:
                current_vs_expected = f"{ratio:.1f}x above expected"
            elif ratio < 0.5:
                current_vs_expected = f"{1/ratio:.1f}x below expected"
            else:
                current_vs_expected = "within expected range"
        else:
            current_vs_expected = "baseline" if current == 0 else "above zero baseline"

        # Calculate percentile
        if values:
            sorted_vals = sorted(values)
            percentile = (
                len([v for v in sorted_vals if v <= current]) / len(sorted_vals) * 100
            )
        else:
            percentile = 50.0

        return ForecastLatest(
            value=current,
            percentile=round(percentile, 1),
            anomaly_score=round(anomaly_score, 3),
            current_vs_expected=current_vs_expected,
        )

    def _rolling_backtest(self, values: List[float]) -> ForecastBacktest:
        """Perform rolling backtest to validate forecast accuracy.

        Implements rolling origin cross-validation with MASE calculation
        using naive persistence baseline.
        """
        if len(values) < 10:
            return ForecastBacktest(
                status="insufficient_data",
                notes=["low - insufficient history for reliable backtest"],
            )

        # Split for backtest
        split = int(len(values) * 0.8)
        train, test = values[:split], values[split:]

        if len(test) < 3:
            return ForecastBacktest(
                status="insufficient_data",
                notes=["low - test set too small"],
            )

        # Calculate naive MAE for MASE denominator
        naive_mae_h1 = self._calculate_naive_mae(values)
        # For H6, naive baseline uses 6-step-ahead persistence
        naive_mae_h6 = naive_mae_h1 * 6 if naive_mae_h1 > 0 else 1.0

        # Calculate errors for each horizon simulation
        errors_h1 = []
        errors_h6 = []
        errors_h24 = []

        for i in range(len(test)):
            train_plus = train + test[:i]
            ets = self._simple_ets(train_plus, self.alpha)
            pred = ets["forecast"]

            # H1 error (next point)
            if i < len(test):
                actual_h1 = test[i]
                errors_h1.append((pred, actual_h1))

            # H6 error (average of next 6)
            if i + 6 <= len(test):
                actual_h6 = sum(test[i : i + 6])
                errors_h6.append((pred * 6, actual_h6))

        # Calculate metrics with MASE
        metrics = {}
        if errors_h1:
            metrics["H1"] = self._calc_horizon_metrics(errors_h1, naive_mae_h1)
        if errors_h6:
            metrics["H6"] = self._calc_horizon_metrics(errors_h6, naive_mae_h6)

        # Determine confidence from MASE (prefer) or SMAPE
        h6_mase = metrics.get("H6", ForecastHorizonMetrics()).mase
        if h6_mase is not None:
            if h6_mase <= self.mase_high_threshold:
                confidence_note = (
                    f"high - MASE {h6_mase:.2f} <= {self.mase_high_threshold}"
                )
            elif h6_mase <= self.mase_medium_threshold:
                confidence_note = (
                    f"medium - MASE {h6_mase:.2f} <= {self.mase_medium_threshold}"
                )
            else:
                confidence_note = (
                    f"low - MASE {h6_mase:.2f} > {self.mase_medium_threshold}"
                )
        else:
            # Fall back to SMAPE
            avg_mape = np.mean(
                [m.smape for m in metrics.values() if m.smape is not None]
            )
            if avg_mape < 20:
                confidence_note = "high - SMAPE < 20%"
            elif avg_mape < 40:
                confidence_note = "medium - SMAPE 20-40%"
            else:
                confidence_note = "low - SMAPE > 40%"

        return ForecastBacktest(
            status="ok",
            window_days=self.backtest_window_days,
            splits=self.backtest_splits,
            step_buckets=1,
            metrics=metrics,
            thresholds={
                "H1": ForecastHorizonThresholds(spike_q=0.95, drop_q=0.05),
                "H6": ForecastHorizonThresholds(spike_q=0.95, drop_q=0.05),
                "H24": ForecastHorizonThresholds(spike_q=0.95, drop_q=0.05),
            },
            notes=[confidence_note],
        )

    def _calc_horizon_metrics(
        self, errors: List[Tuple[float, float]], naive_mae: Optional[float] = None
    ) -> ForecastHorizonMetrics:
        """Calculate SMAPE, MASE, RMSE for a horizon.

        Args:
            errors: List of (predicted, actual) tuples
            naive_mae: Mean Absolute Error of naive forecast (for MASE)

        Returns:
            ForecastHorizonMetrics with all computed metrics
        """
        if not errors:
            return ForecastHorizonMetrics()

        smape_vals = []
        squared_errors = []
        absolute_errors = []

        for pred, actual in errors:
            # SMAPE
            denom = (abs(pred) + abs(actual)) / 2
            if denom > 0:
                smape_vals.append(abs(pred - actual) / denom * 100)
            # RMSE
            squared_errors.append((pred - actual) ** 2)
            # MAE for MASE
            absolute_errors.append(abs(pred - actual))

        # Calculate MASE if naive_mae is provided
        mase = None
        if naive_mae and naive_mae > 0 and absolute_errors:
            mae = float(np.mean(absolute_errors))
            mase = round(mae / naive_mae, 3)

        return ForecastHorizonMetrics(
            smape=round(float(np.mean(smape_vals)), 2) if smape_vals else None,
            mase=mase,
            rmse=(
                round(float(np.sqrt(np.mean(squared_errors))), 2)
                if squared_errors
                else None
            ),
            coverage95=None,  # Would need prediction intervals
        )

    def _calculate_naive_mae(self, values: List[float]) -> float:
        """Calculate naive forecast MAE (persistence model: y_t+1 = y_t).

        Used as denominator for MASE calculation.
        """
        if len(values) < 2:
            return 1.0  # Avoid division by zero

        naive_errors = [abs(values[i] - values[i - 1]) for i in range(1, len(values))]
        return float(np.mean(naive_errors)) if naive_errors else 1.0

    def _calculate_reliability(
        self, backtest: ForecastBacktest, missing_pct: float, track_name: str
    ) -> str:
        """Calculate reliability level based on backtest metrics and data quality.

        Reliability levels per spec:
        - LOW: Insufficient history, MASE > 1.3, or missing_pct > 10%
        - MEDIUM: MASE_H6 <= 1.3 and missing_pct < 5%
        - HIGH: MASE_H6 <= 1.1, coverage95 in [0.85, 0.98], missing_pct < 2%

        Args:
            backtest: ForecastBacktest with metrics
            missing_pct: Percentage of missing data points
            track_name: 'rule', 'ioc', or 'entity'

        Returns:
            Reliability level string: 'LOW', 'MEDIUM', or 'HIGH'
        """
        # Check for insufficient data first
        if backtest.status == "insufficient_data":
            return RELIABILITY_LOW

        # Get H6 metrics (primary horizon for reliability)
        h6_metrics = backtest.metrics.get("H6") if backtest.metrics else None

        # Default to LOW if no H6 metrics
        if not h6_metrics:
            return RELIABILITY_LOW

        mase = h6_metrics.mase
        coverage95 = h6_metrics.coverage95

        # Check for HIGH reliability
        if (
            mase is not None
            and mase <= self.mase_high_threshold
            and missing_pct < self.missing_pct_high_threshold
            and coverage95 is not None
            and self.coverage95_low <= coverage95 <= self.coverage95_high
        ):
            return RELIABILITY_HIGH

        # Check for MEDIUM reliability
        if (
            mase is not None
            and mase <= self.mase_medium_threshold
            and missing_pct < self.missing_pct_medium_threshold
        ):
            return RELIABILITY_MEDIUM

        # Default to LOW
        return RELIABILITY_LOW

    def _calibrate_thresholds(
        self, backtest: ForecastBacktest
    ) -> Optional[Dict[str, ForecastHorizonThresholds]]:
        """Calibrate spike/drop thresholds from backtest residuals.

        Uses p95/p99 of positive residuals for spike thresholds,
        and p05 of residuals for drop thresholds.

        Args:
            backtest: ForecastBacktest with metrics

        Returns:
            Dict of horizon -> ForecastHorizonThresholds, or None if insufficient data
        """
        if backtest.status == "insufficient_data" or not backtest.metrics:
            return None

        # For now, return default thresholds
        # Full implementation would compute from stored residuals
        calibrated = {}
        for horizon in ["H1", "H6", "H24"]:
            if horizon in backtest.metrics:
                metrics = backtest.metrics[horizon]
                # Use RMSE to estimate threshold if available
                rmse = metrics.rmse if metrics.rmse else 1.0
                calibrated[horizon] = ForecastHorizonThresholds(
                    spike_q=0.95,
                    drop_q=0.05,
                    spike_threshold_p95=rmse * 1.65,  # ~95th percentile
                    spike_threshold_p99=rmse * 2.33,  # ~99th percentile
                    drop_threshold_p05=-rmse * 1.65,  # ~5th percentile
                )

        return calibrated if calibrated else None

    def _generate_interpretation(
        self,
        track_name: str,
        current: float,
        forecast: float,
        anomaly_score: float,
        thresholds: Optional[ForecastHorizonThresholds] = None,
    ) -> str:
        """Generate human-readable interpretation for track.

        Uses calibrated thresholds if available, otherwise falls back to
        anomaly_score-based classification.

        Args:
            track_name: 'rule', 'ioc', or 'entity'
            current: Current value
            forecast: Expected/forecasted value
            anomaly_score: Normalized anomaly score (0-1)
            thresholds: Optional calibrated thresholds from backtest

        Returns:
            Human-readable interpretation string
        """
        residual = current - forecast

        # Use calibrated thresholds if available
        if thresholds and thresholds.spike_threshold_p99 is not None:
            if residual > thresholds.spike_threshold_p99:
                severity = "significantly elevated (>p99)"
            elif (
                thresholds.spike_threshold_p95
                and residual > thresholds.spike_threshold_p95
            ):
                severity = "moderately elevated (>p95)"
            elif (
                thresholds.drop_threshold_p05
                and residual < thresholds.drop_threshold_p05
            ):
                severity = "unusually low (<p05)"
            else:
                severity = "within expected range"
        else:
            # Fall back to anomaly score
            if anomaly_score > 0.8:
                severity = "significantly elevated"
            elif anomaly_score > 0.5:
                severity = "moderately elevated"
            elif anomaly_score < 0.2:
                severity = "within normal range"
            else:
                severity = "slightly above normal"

        track_labels = {
            "rule": "Detection rule activity",
            "ioc": "Indicator sighting rate",
            "entity": "Entity behavior pattern",
        }
        label = track_labels.get(track_name, "Activity")

        return f"{label} is {severity} (current={current:.1f}, expected={forecast:.1f})"

    # =========================================================================
    # CORE ETS METHODS
    # =========================================================================

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

        level = values[0]
        smoothed = [level]

        for value in values[1:]:
            level = alpha * value + (1 - alpha) * level
            smoothed.append(level)

        return {"forecast": level, "level": level, "smoothed": smoothed}

    def _calculate_anomaly_score(self, actual: float, forecast: float) -> float:
        """Calculate anomaly score based on deviation from forecast."""
        if forecast == 0:
            return 1.0 if actual > 0 else 0.0

        deviation = abs(actual - forecast) / (forecast + 1)
        score = 2 / (1 + np.exp(-deviation)) - 1
        return min(max(score, 0.0), 1.0)

    # =========================================================================
    # LEGACY SINGLE-TRACK METHOD (for backward compatibility during migration)
    # =========================================================================

    def forecast(
        self, historical_data: List[Dict[str, Any]], signal_type: str
    ) -> Dict[str, Any]:
        """Legacy single-track forecast method.

        DEPRECATED: Use forecast_multi_track() for new code.
        """
        if not historical_data or len(historical_data) < 3:
            return {
                "forecast_available": False,
                "reason": "insufficient_data",
                "data_points": len(historical_data),
            }

        try:
            values = [d.get("count", 0) for d in historical_data]
            forecast_result = self._simple_ets(values, self.alpha)
            recent_value = values[-1] if values else 0
            anomaly_score = self._calculate_anomaly_score(
                recent_value, forecast_result["forecast"]
            )
            backtest_results = self._legacy_backtest(values)

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

    def _legacy_backtest(self, values: List[float]) -> Dict[str, Any]:
        """Legacy backtest method."""
        if len(values) < 5:
            return {"mape": 0.0, "rmse": 0.0, "confidence": 0.5}

        split_point = int(len(values) * 0.8)
        train_data = values[:split_point]
        test_data = values[split_point:]

        errors = []
        abs_errors = []

        for i, actual in enumerate(test_data):
            forecast_result = self._simple_ets(train_data + test_data[:i], self.alpha)
            forecast = forecast_result["forecast"]
            error = actual - forecast
            errors.append(error**2)
            if actual != 0:
                abs_errors.append(abs(error) / abs(actual))

        rmse = float(np.sqrt(np.mean(errors))) if errors else 0.0
        mape = float(np.mean(abs_errors) * 100) if abs_errors else 0.0
        confidence = max(0.0, min(1.0, 1.0 - (mape / 100)))

        return {
            "mape": round(mape, 2),
            "rmse": round(rmse, 2),
            "confidence": round(confidence, 2),
        }
