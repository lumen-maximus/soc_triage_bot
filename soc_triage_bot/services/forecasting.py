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

from ..config import get_forecast_config, get_signal_type_config
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

    Now fully integrated with forecasting_entity_map.yaml configuration.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize forecasting service.

        Args:
            config: Configuration including thresholds and parameters (overrides YAML)
        """
        # Load YAML configuration
        yaml_config = get_forecast_config()

        self.config = config or {}
        self.threshold = self.config.get("threshold", 0.8)
        self.bucket_minutes = self.config.get(
            "bucket_minutes", yaml_config.bucket_minutes_default
        )
        self.horizons_hours = self.config.get(
            "horizons_hours", yaml_config.horizons_hours
        )
        self.min_history_points = self.config.get("min_history_points", 24)
        self.backtest_window_days = self.config.get("backtest_window_days", 14)
        self.backtest_splits = self.config.get("backtest_splits", 5)
        self.alpha = self.config.get("alpha", 0.3)  # ETS smoothing parameter
        self.history_window_days = yaml_config.history_window_days_default
        self.late_arrival_window_minutes = yaml_config.late_arrival_window_minutes

        # Quality gate thresholds from YAML (spec Section 5)
        quality_gates = yaml_config.selection_rules.quality_gates
        medium_gate = quality_gates.get("MEDIUM")
        high_gate = quality_gates.get("HIGH")

        self.mase_medium_threshold: float = (
            medium_gate.mase_h6_max
            if medium_gate and medium_gate.mase_h6_max is not None
            else self.config.get("mase_medium_threshold", 1.3) or 1.3
        )
        self.mase_high_threshold: float = (
            high_gate.mase_h6_max
            if high_gate and high_gate.mase_h6_max is not None
            else self.config.get("mase_high_threshold", 1.1) or 1.1
        )
        self.coverage_high_min: float = (
            high_gate.coverage95_min
            if high_gate and high_gate.coverage95_min is not None
            else self.config.get("coverage_high_min", 0.85) or 0.85
        )
        self.coverage_high_max: float = (
            high_gate.coverage95_max
            if high_gate and high_gate.coverage95_max is not None
            else self.config.get("coverage_high_max", 0.98) or 0.98
        )
        self.missing_pct_medium_max: float = (
            medium_gate.missing_pct_max
            if medium_gate and medium_gate.missing_pct_max is not None
            else self.config.get("missing_pct_medium_max", 0.05) or 0.05
        )
        self.missing_pct_high_max: float = (
            high_gate.missing_pct_max
            if high_gate and high_gate.missing_pct_max is not None
            else self.config.get("missing_pct_high_max", 0.02) or 0.02
        )

        # Minimum history requirements from YAML default tracks
        default_tracks = yaml_config.tracks
        rule_track = default_tracks.get("A_detection_rule")
        ioc_track = default_tracks.get("B_indicator_artifact")
        entity_track = default_tracks.get("C_entity_behavior")

        self.min_history_days_rule = (
            rule_track.reliability_min_history_days if rule_track else 28
        )
        self.min_history_days_ioc = (
            ioc_track.reliability_min_history_days if ioc_track else 14
        )
        self.min_history_days_entity = (
            entity_track.reliability_min_history_days if entity_track else 28
        )

        # Store common entities for key extraction
        self.common_entities = yaml_config.common_entities

        # Store selection rules for reliability gating
        self.selection_rules = yaml_config.selection_rules

    def get_entity_keys_for_track(
        self, signal_type: str, track: str, signal_subtype: Optional[str] = None
    ) -> Tuple[List[str], List[str], List[str]]:
        """Get entity keys and metrics for a track from YAML config.

        Uses the forecasting_entity_map.yaml to determine which entity keys
        and metrics to use for each track based on signal type.

        Args:
            signal_type: Signal type (e.g., 'SIEM_ALERT', 'IOC')
            track: Track name ('A_detection_rule', 'B_indicator_artifact', 'C_entity_behavior')
            signal_subtype: Optional subtype for metric selection (e.g., 'auth', 'network')

        Returns:
            Tuple of (keys_preferred, fallbacks, metrics_preferred)
        """
        st_config = get_signal_type_config(signal_type)

        if track == "A_detection_rule":
            track_cfg = st_config.track_a
        elif track == "B_indicator_artifact":
            track_cfg = st_config.track_b
        else:
            track_cfg = st_config.track_c

        keys_preferred = track_cfg.keys_preferred
        fallbacks = track_cfg.fallbacks
        metrics = track_cfg.metrics_preferred

        # Use subtype-specific metrics if available
        if signal_subtype:
            if (
                track_cfg.subtype_metric_map
                and signal_subtype in track_cfg.subtype_metric_map
            ):
                metrics = track_cfg.subtype_metric_map[signal_subtype]
            elif (
                track_cfg.complaint_metric_map
                and signal_subtype in track_cfg.complaint_metric_map
            ):
                metrics = track_cfg.complaint_metric_map[signal_subtype]

        return keys_preferred, fallbacks, metrics

    def extract_entity_from_signal(
        self, signal: Signal, track: str
    ) -> Optional[Tuple[str, str]]:
        """Extract primary entity key:value for a track from signal.

        Uses the priority order from forecasting_entity_map.yaml to find
        the best available entity key in the signal.

        Args:
            signal: The signal to extract entity from
            track: Track name

        Returns:
            Tuple of (entity_key, entity_value) or None if not found
        """
        keys_preferred, fallbacks, _ = self.get_entity_keys_for_track(
            signal.signal_type.value, track
        )

        all_keys = keys_preferred + fallbacks

        # Check signal entities for matching keys
        for key in all_keys:
            if key in signal.entities and signal.entities[key]:
                values = signal.entities[key]
                value = values[0] if isinstance(values, list) else values
                return (key, value)

        return None

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
        # Get track config for this signal type from YAML
        st_config = get_signal_type_config(signal.signal_type.value)

        tracks = ForecastTracks(
            rule=self._forecast_track(
                historical_data.track_a, "rule", st_config.track_a
            ),
            ioc=self._forecast_track(historical_data.track_b, "ioc", st_config.track_b),
            entity=self._forecast_track(
                historical_data.track_c, "entity", st_config.track_c
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
            elif 0 < ratio < 0.5:
                current_vs_expected = f"{1/ratio:.1f}x below expected"
            elif ratio == 0:
                current_vs_expected = "zero (expected non-zero)"
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
            and missing_pct < self.missing_pct_high_max
            and coverage95 is not None
            and self.coverage_high_min <= coverage95 <= self.coverage_high_max
        ):
            return RELIABILITY_HIGH

        # Check for MEDIUM reliability
        if (
            mase is not None
            and mase <= self.mase_medium_threshold
            and missing_pct < self.missing_pct_medium_max
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
