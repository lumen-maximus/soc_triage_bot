"""Adapter framework for enrichments."""

from .ai_provider import (
    AIProviderConfig,
    AIResponse,
    AnthropicProvider,
    BaseAIProvider,
    MockProvider,
    OllamaProvider,
    OpenAIProvider,
    get_provider,
)
from .base import BaseAdapter
from .base_historical import HistoricalQueryCapable, TimeSeriesPoint, TimeSeriesResult
from .cmdb import CMDBAdapter
from .edr import EDRAdapter
from .mock_historical import MockHistoricalAdapter
from .siem import SIEMAdapter
from .soar import SOARAdapter
from .threat_intel import ThreatIntelAdapter
from .vulnerability import VulnerabilityAdapter

__all__ = [
    "BaseAdapter",
    "SIEMAdapter",
    "SOARAdapter",
    "EDRAdapter",
    "ThreatIntelAdapter",
    "VulnerabilityAdapter",
    "CMDBAdapter",
    # AI Providers
    "AIProviderConfig",
    "AIResponse",
    "BaseAIProvider",
    "MockProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "get_provider",
    # Historical query support
    "HistoricalQueryCapable",
    "TimeSeriesPoint",
    "TimeSeriesResult",
    "MockHistoricalAdapter",
]
