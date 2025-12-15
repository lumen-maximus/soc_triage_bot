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
from .cmdb import CMDBAdapter
from .edr import EDRAdapter
from .siem import SIEMAdapter
from .threat_intel import ThreatIntelAdapter
from .vulnerability import VulnerabilityAdapter

__all__ = [
    "BaseAdapter",
    "SIEMAdapter",
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
]
