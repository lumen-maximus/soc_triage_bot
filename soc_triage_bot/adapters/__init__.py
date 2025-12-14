"""Adapter framework for enrichments."""

from .base import BaseAdapter
from .siem import SIEMAdapter
from .edr import EDRAdapter
from .threat_intel import ThreatIntelAdapter
from .vulnerability import VulnerabilityAdapter
from .cmdb import CMDBAdapter

__all__ = [
    "BaseAdapter",
    "SIEMAdapter",
    "EDRAdapter",
    "ThreatIntelAdapter",
    "VulnerabilityAdapter",
    "CMDBAdapter",
]
