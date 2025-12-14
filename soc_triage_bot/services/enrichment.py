"""Enrichment orchestration service."""

import asyncio
from typing import List, Dict, Any
from ..models import Signal, EnrichmentResult
from ..adapters import BaseAdapter


class EnrichmentService:
    """Service for orchestrating concurrent enrichments."""
    
    def __init__(self, adapters: List[BaseAdapter]):
        """Initialize with list of adapters.
        
        Args:
            adapters: List of enrichment adapters to use
        """
        self.adapters = adapters
    
    async def enrich_signal(self, signal: Signal) -> Dict[str, EnrichmentResult]:
        """Enrich a signal using all adapters concurrently.
        
        Args:
            signal: The signal to enrich
            
        Returns:
            Dictionary mapping adapter name to enrichment result
        """
        # Run all enrichments concurrently
        tasks = [adapter.enrich(signal) for adapter in self.adapters]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Map results to adapter names
        enrichments = {}
        for adapter, result in zip(self.adapters, results):
            if isinstance(result, Exception):
                # Handle adapter failures gracefully
                from ..models.enrichment import EnrichmentStatus
                from datetime import datetime
                enrichments[adapter.name] = EnrichmentResult(
                    adapter=adapter.name,
                    status=EnrichmentStatus.FAILED,
                    error=str(result),
                    timestamp=datetime.utcnow()
                )
            else:
                enrichments[adapter.name] = result
        
        return enrichments
    
    async def health_check(self) -> Dict[str, bool]:
        """Check health of all adapters.
        
        Returns:
            Dictionary mapping adapter name to health status
        """
        tasks = [adapter.health_check() for adapter in self.adapters]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        health_status = {}
        for adapter, result in zip(self.adapters, results):
            if isinstance(result, Exception):
                health_status[adapter.name] = False
            else:
                health_status[adapter.name] = result
        
        return health_status
