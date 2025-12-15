"""Signal data models for normalized security events."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SignalType(str, Enum):
    """Types of security signals."""

    SIEM_ALERT = "siem_alert"
    IOC = "ioc"
    CVE = "cve"
    HUNT = "hunt"
    USER_REPORT = "user_report"


class SignalSource(BaseModel):
    """Source information for a signal."""

    system: str
    instance: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None


class Signal(BaseModel):
    """Normalized security signal schema."""

    signal_id: str = Field(..., description="Unique identifier for the signal")
    signal_type: SignalType
    timestamp: datetime
    source: SignalSource

    # Core fields
    title: str
    description: str
    severity: str  # low, medium, high, critical

    # Entity information
    entities: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Entities involved (ip, hostname, user, process, file, etc.)",
    )

    # Indicators (IOCs) - for IOC-led signals
    indicators: Dict[str, str] = Field(
        default_factory=dict,
        description="Indicators/IOCs (ip, domain, hash, url, email, etc.)",
    )

    # Signal-specific data
    raw_data: Dict[str, Any] = Field(
        default_factory=dict, description="Original signal data"
    )

    # Metadata
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        json_schema_extra = {
            "example": {
                "signal_id": "sig-12345",
                "signal_type": "siem_alert",
                "timestamp": "2025-12-14T19:00:00Z",
                "source": {
                    "system": "splunk",
                    "rule_id": "rule-001",
                    "rule_name": "Suspicious PowerShell",
                },
                "title": "Suspicious PowerShell Execution",
                "description": "PowerShell with encoded command detected",
                "severity": "high",
                "entities": {
                    "hostname": ["workstation-01"],
                    "user": ["admin"],
                    "process": ["powershell.exe"],
                },
                "indicators": {
                    "ip": "192.168.1.100",
                    "domain": "malicious.example.com",
                    "hash": "abc123def456...",
                },
                "tags": ["malware", "powershell"],
            }
        }
