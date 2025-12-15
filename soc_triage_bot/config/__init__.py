"""Forecast configuration loader.

Loads the forecasting_entity_map.yaml and provides typed access to track configs
per signal type. Replaces the hardcoded SIGNAL_TYPE_TRACK_CONFIGS in triage_report.py.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# Default config path
DEFAULT_CONFIG_PATH = Path(__file__).parent / "forecasting_entity_map.yaml"


@dataclass
class TrackConfig:
    """Configuration for a single track (A, B, or C)."""

    enabled: bool = True
    keys_preferred: List[str] = field(default_factory=list)
    fallbacks: List[str] = field(default_factory=list)
    metrics_preferred: List[str] = field(default_factory=list)
    subtype_metric_map: Dict[str, List[str]] = field(default_factory=dict)
    complaint_metric_map: Dict[str, List[str]] = field(default_factory=dict)
    reliability_min_history_days: int = 28


@dataclass
class SignalTypeConfig:
    """Configuration for a signal type's tracks."""

    track_a: TrackConfig = field(default_factory=TrackConfig)
    track_b: TrackConfig = field(default_factory=TrackConfig)
    track_c: TrackConfig = field(default_factory=TrackConfig)


@dataclass
class QualityGate:
    """Quality gate thresholds for reliability levels."""

    description: str = ""
    mase_h6_max: Optional[float] = None
    mase_h24_max: Optional[float] = None
    coverage95_min: Optional[float] = None
    coverage95_max: Optional[float] = None
    missing_pct_max: Optional[float] = None


@dataclass
class SelectionRules:
    """Entity selection rules."""

    primary_entity_priority: List[str] = field(default_factory=list)
    indicator_value_format: str = "<indicator_type>=<indicator_value>"
    min_history_days_default: int = 28
    require_backtest: bool = True
    allow_influence_actions_if_reliability_at_least: str = "MEDIUM"
    quality_gates: Dict[str, QualityGate] = field(default_factory=dict)


@dataclass
class ForecastConfig:
    """Complete forecast configuration from YAML."""

    version: int = 1
    bucket_minutes_default: int = 15
    horizons_hours: List[int] = field(default_factory=lambda: [1, 6, 24])
    history_window_days_default: int = 56
    late_arrival_window_minutes: int = 120

    # Common entity key groups
    common_entities: Dict[str, List[str]] = field(default_factory=dict)

    # Default track configs
    tracks: Dict[str, TrackConfig] = field(default_factory=dict)

    # Signal type specific configs
    signal_types: Dict[str, SignalTypeConfig] = field(default_factory=dict)

    # Selection rules
    selection_rules: SelectionRules = field(default_factory=SelectionRules)


class ForecastConfigLoader:
    """Loads and caches forecast configuration from YAML."""

    _instance: Optional["ForecastConfigLoader"] = None
    _config: Optional[ForecastConfig] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config_path: Optional[Path] = None):
        if self._config is None:
            self._config_path = config_path or DEFAULT_CONFIG_PATH
            self._load_config()

    def _load_config(self) -> None:
        """Load configuration from YAML file."""
        if not self._config_path.exists():
            # Use defaults if config doesn't exist
            self._config = ForecastConfig()
            return

        with open(self._config_path, "r") as f:
            raw = yaml.safe_load(f)

        self._config = self._parse_config(raw)

    def _parse_config(self, raw: Dict[str, Any]) -> ForecastConfig:
        """Parse raw YAML into typed config."""
        config = ForecastConfig(
            version=raw.get("version", 1),
            bucket_minutes_default=raw.get("bucket_minutes_default", 15),
            horizons_hours=raw.get("horizons_hours", [1, 6, 24]),
            history_window_days_default=raw.get("history_window_days_default", 56),
            late_arrival_window_minutes=raw.get("late_arrival_window_minutes", 120),
            common_entities=raw.get("common_entities", {}),
        )

        # Parse default tracks
        if "tracks" in raw:
            for track_name, track_data in raw["tracks"].items():
                config.tracks[track_name] = self._parse_track_config(track_data)

        # Parse signal types
        if "signal_types" in raw:
            for signal_type, st_data in raw["signal_types"].items():
                config.signal_types[signal_type] = self._parse_signal_type_config(
                    st_data
                )

        # Parse selection rules
        if "selection_rules" in raw:
            config.selection_rules = self._parse_selection_rules(raw["selection_rules"])

        return config

    def _parse_track_config(self, data: Dict[str, Any]) -> TrackConfig:
        """Parse a track configuration."""
        return TrackConfig(
            enabled=data.get("enabled", True),
            keys_preferred=data.get("keys_preferred", []),
            fallbacks=data.get("fallbacks", []),
            metrics_preferred=data.get("metrics_preferred", []),
            subtype_metric_map=data.get("subtype_metric_map", {}),
            complaint_metric_map=data.get("complaint_metric_map", {}),
            reliability_min_history_days=data.get("reliability_min_history_days", 28),
        )

    def _parse_signal_type_config(self, data: Dict[str, Any]) -> SignalTypeConfig:
        """Parse signal type configuration."""
        tracks_data = data.get("tracks", {})
        return SignalTypeConfig(
            track_a=self._parse_track_config(tracks_data.get("A_detection_rule", {})),
            track_b=self._parse_track_config(
                tracks_data.get("B_indicator_artifact", {})
            ),
            track_c=self._parse_track_config(tracks_data.get("C_entity_behavior", {})),
        )

    def _parse_selection_rules(self, data: Dict[str, Any]) -> SelectionRules:
        """Parse selection rules."""
        quality_gates = {}
        if "quality_gates" in data:
            for level, gate_data in data["quality_gates"].items():
                quality_gates[level] = QualityGate(
                    description=gate_data.get("description", ""),
                    mase_h6_max=gate_data.get("mase_h6_max"),
                    mase_h24_max=gate_data.get("mase_h24_max"),
                    coverage95_min=gate_data.get("coverage95_min"),
                    coverage95_max=gate_data.get("coverage95_max"),
                    missing_pct_max=gate_data.get("missing_pct_max"),
                )

        reliability_gate = data.get("reliability_gate", {})
        return SelectionRules(
            primary_entity_priority=data.get("primary_entity_priority", []),
            indicator_value_format=data.get(
                "indicator_value_format", "<indicator_type>=<indicator_value>"
            ),
            min_history_days_default=reliability_gate.get(
                "min_history_days_default", 28
            ),
            require_backtest=reliability_gate.get("require_backtest", True),
            allow_influence_actions_if_reliability_at_least=reliability_gate.get(
                "allow_influence_actions_if_reliability_at_least", "MEDIUM"
            ),
            quality_gates=quality_gates,
        )

    @property
    def config(self) -> ForecastConfig:
        """Get the loaded configuration."""
        if self._config is None:
            self._load_config()
        assert self._config is not None, "Config should be loaded after _load_config()"
        return self._config

    def get_signal_type_config(self, signal_type: str) -> SignalTypeConfig:
        """Get track configuration for a signal type.

        Args:
            signal_type: Signal type (e.g., 'SIEM_ALERT', 'IOC')

        Returns:
            SignalTypeConfig for the signal type, or default SIEM_ALERT config.
        """
        normalized = signal_type.upper()
        if normalized in self.config.signal_types:
            return self.config.signal_types[normalized]
        # Fallback to SIEM_ALERT or empty config
        return self.config.signal_types.get("SIEM_ALERT", SignalTypeConfig())

    def get_default_track(self, track_key: str) -> TrackConfig:
        """Get default track configuration.

        Args:
            track_key: Track key (e.g., 'A_detection_rule')

        Returns:
            Default TrackConfig for the track.
        """
        return self.config.tracks.get(track_key, TrackConfig())

    def get_quality_gate(self, level: str) -> Optional[QualityGate]:
        """Get quality gate for a reliability level.

        Args:
            level: Reliability level ('LOW', 'MEDIUM', 'HIGH')

        Returns:
            QualityGate thresholds or None.
        """
        return self.config.selection_rules.quality_gates.get(level.upper())


# Module-level convenience functions
_loader: Optional[ForecastConfigLoader] = None


def get_forecast_config() -> ForecastConfig:
    """Get the forecast configuration (singleton)."""
    global _loader
    if _loader is None:
        _loader = ForecastConfigLoader()
    return _loader.config


def get_signal_type_config(signal_type: str) -> SignalTypeConfig:
    """Get track configuration for a signal type.

    Args:
        signal_type: Signal type (e.g., 'SIEM_ALERT', 'IOC')

    Returns:
        SignalTypeConfig for the signal type.
    """
    global _loader
    if _loader is None:
        _loader = ForecastConfigLoader()
    return _loader.get_signal_type_config(signal_type)


def get_quality_gate(level: str) -> Optional[QualityGate]:
    """Get quality gate for a reliability level."""
    global _loader
    if _loader is None:
        _loader = ForecastConfigLoader()
    return _loader.get_quality_gate(level)
