"""Base adapter interface."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from ..models import EnrichmentResult, Signal


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

    async def health_check(self) -> bool:
        """Check if the adapter is healthy and can be used.

        Returns:
            True if adapter is healthy, False otherwise
        """
        return True
