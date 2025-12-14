#!/usr/bin/env python3
"""
Demonstration script for SOC Triage Bot.

This script demonstrates the key features of the SOC triage system:
1. Signal ingestion and normalization
2. Concurrent enrichments
3. ETS forecasting
4. Similar case retrieval
5. TP/FP classification
6. Action proposal generation
7. Report rendering
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path

from soc_triage_bot.models import Signal, SignalType, SignalSource
from soc_triage_bot.services import TriageService, EnrichmentService
from soc_triage_bot.adapters import (
    SIEMAdapter, EDRAdapter, ThreatIntelAdapter, 
    VulnerabilityAdapter, CMDBAdapter
)


async def main():
    print("=" * 80)
    print("SOC Triage Bot Demonstration")
    print("=" * 80)
    
    # Initialize the triage service
    print("\n1. Initializing triage service with all adapters...")
    adapters = [
        SIEMAdapter(),
        EDRAdapter(),
        ThreatIntelAdapter(),
        VulnerabilityAdapter(),
        CMDBAdapter()
    ]
    enrichment_service = EnrichmentService(adapters)
    triage_service = TriageService(enrichment_service=enrichment_service)
    print(f"   ✓ Initialized {len(adapters)} adapters")
    
    # Create a sample signal
    print("\n2. Creating sample security signal...")
    signal = Signal(
        signal_id="demo-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(
            system="demo_siem",
            rule_id="rule-suspicious-powershell",
            rule_name="Suspicious PowerShell Activity"
        ),
        title="Encoded PowerShell Command Execution",
        description="Detected PowerShell with base64 encoded command",
        severity="high",
        entities={
            "hostname": ["workstation-42"],
            "user": ["admin"],
            "process": ["powershell.exe"],
            "ip": ["192.0.2.50"]
        },
        tags=["malware", "powershell", "suspicious"],
        raw_data={"command_line": "powershell.exe -enc ..."}
    )
    print(f"   ✓ Signal ID: {signal.signal_id}")
    print(f"   ✓ Type: {signal.signal_type.value}")
    print(f"   ✓ Severity: {signal.severity}")
    
    # Prepare historical data for forecasting
    print("\n3. Preparing historical data for ETS forecasting...")
    historical_data = [
        {"timestamp": "2025-11-14", "count": 3},
        {"timestamp": "2025-11-21", "count": 2},
        {"timestamp": "2025-11-28", "count": 4},
        {"timestamp": "2025-12-05", "count": 3},
        {"timestamp": "2025-12-12", "count": 5},
        {"timestamp": "2025-12-14", "count": 15}  # Anomaly
    ]
    print(f"   ✓ Loaded {len(historical_data)} data points")
    
    # Execute triage
    print("\n4. Executing triage workflow...")
    print("   → Running concurrent enrichments...")
    result = await triage_service.triage(signal, historical_data)
    print(f"   ✓ Triage completed in {result.duration_ms:.2f}ms")
    
    # Show enrichment results
    print("\n5. Enrichment Results:")
    for adapter_name, enrichment in result.enrichments.items():
        status_icon = "✓" if enrichment.status.value == "success" else "✗"
        print(f"   {status_icon} {adapter_name.upper()}: {enrichment.status.value} ({enrichment.duration_ms:.2f}ms)")
    
    # Show forecast results
    print("\n6. ETS Forecasting Results:")
    if result.forecast_data and result.forecast_data.get("forecast_available"):
        fd = result.forecast_data
        print(f"   Current value: {fd['current_value']}")
        print(f"   Forecast: {fd['forecast']:.2f}")
        print(f"   Anomaly score: {fd['anomaly_score']:.2f}")
        print(f"   Exceeds threshold: {'YES' if fd['exceeds_threshold'] else 'NO'}")
        print(f"   Backtest MAPE: {fd['backtest_mape']:.2f}%")
        print(f"   Confidence: {fd['confidence']:.2f}")
    
    # Show classification
    print("\n7. Classification:")
    print(f"   Label: {result.classification.label.value.upper()}")
    print(f"   Confidence: {result.classification.confidence:.2%}")
    print(f"   Reasoning:")
    for reason in result.classification.reasoning:
        print(f"     • {reason}")
    
    # Show similar cases
    print("\n8. Similar Cases:")
    if result.similar_cases:
        for case_id, similarity in result.similar_cases:
            print(f"   • {case_id} (similarity: {similarity:.2f})")
    else:
        print("   No similar cases found")
    
    # Show action proposals
    print("\n9. Proposed Actions:")
    for i, action in enumerate(result.actions[:3], 1):  # Show top 3
        print(f"\n   Action {i}: {action.title}")
        print(f"   Type: {action.action_type.value}")
        print(f"   Priority: {action.priority}")
        print(f"   Confidence: {action.confidence:.2%}")
        print(f"   Source: {action.source}")
        print(f"   Steps:")
        for step in action.steps[:2]:  # Show first 2 steps
            print(f"     • {step}")
    
    # Show report excerpt
    print("\n10. Generated Report (excerpt):")
    report_lines = result.report.split('\n')
    for line in report_lines[:20]:
        print(f"   {line}")
    print("   ... (truncated)")
    
    print("\n" + "=" * 80)
    print("Demonstration Complete!")
    print("=" * 80)
    print(f"\nFull report contains {len(report_lines)} lines")
    print(f"Total processing time: {result.duration_ms:.2f}ms")
    print("\nFor more information, see: README.md")


if __name__ == "__main__":
    asyncio.run(main())
