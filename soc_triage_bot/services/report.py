"""Report generation service using Jinja templates."""

from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, Template

from ..models import Action, Classification, EnrichmentResult, Signal


class ReportService:
    """Service for rendering triage reports."""

    def __init__(self, template_dir: Optional[str] = None):
        """Initialize report service.

        Args:
            template_dir: Directory containing Jinja templates
        """
        if template_dir:
            self.env = Environment(loader=FileSystemLoader(template_dir))
        else:
            # Use inline template if no template directory provided
            self.env = None

    def generate_report(
        self,
        signal: Signal,
        enrichments: Dict[str, EnrichmentResult],
        classification: Classification,
        actions: List[Action],
        forecast_data: Optional[Dict[str, Any]] = None,
        similar_cases: Optional[List[tuple]] = None,
    ) -> str:
        """Generate Markdown triage report.

        Args:
            signal: The signal
            enrichments: Enrichment results
            classification: Classification result
            actions: Proposed actions
            forecast_data: Optional forecast data
            similar_cases: Optional similar cases

        Returns:
            Markdown report string
        """
        # Prepare data for template
        context = {
            "signal": signal,
            "enrichments": enrichments,
            "classification": classification,
            "actions": actions,
            "forecast_data": forecast_data or {},
            "similar_cases": similar_cases or [],
        }

        template = self._get_template()
        return template.render(**context)

    def _get_template(self) -> Template:
        """Get the report template."""
        if self.env:
            try:
                return self.env.get_template("triage_report.md.j2")
            except Exception:
                pass

        # Default inline template
        return Template("""# Security Signal Triage Report

## Signal Information

- **Signal ID**: {{ signal.signal_id }}
- **Type**: {{ signal.signal_type.value }}
- **Timestamp**: {{ signal.timestamp.isoformat() }}
- **Severity**: {{ signal.severity }}

### Title
{{ signal.title }}

### Description
{{ signal.description }}

### Source
- **System**: {{ signal.source.system }}
{% if signal.source.rule_id -%}
- **Rule ID**: {{ signal.source.rule_id }}
{% endif -%}
{% if signal.source.rule_name -%}
- **Rule Name**: {{ signal.source.rule_name }}
{% endif %}

### Entities
{% for entity_type, entity_values in signal.entities.items() %}
- **{{ entity_type }}**: {{ entity_values|join(', ') }}
{% endfor %}

{% if signal.tags -%}
### Tags
{{ signal.tags|join(', ') }}
{% endif %}

---

## Enrichment Results

{% for adapter_name, enrichment in enrichments.items() %}
### {{ adapter_name.upper() }} ({{ enrichment.status.value }})
{% if enrichment.status.value == "success" -%}
{% if enrichment.duration_ms -%}
*Duration: {{ "%.2f"|format(enrichment.duration_ms) }}ms*

{% endif -%}
```json
{{ enrichment.data|tojson(indent=2) }}
```
{% else -%}
**Error**: {{ enrichment.error }}
{% endif %}

{% endfor %}

---

## Classification

- **Label**: {{ classification.label.value.upper() }}
- **Confidence**: {{ "%.2f"|format(classification.confidence * 100) }}%

### Reasoning
{% for reason in classification.reasoning %}
- {{ reason }}
{% endfor %}

### Contributing Factors
{% for factor, score in classification.factors.items() %}
- **{{ factor }}**: {{ "%.2f"|format(score) }}
{% endfor %}

{% if classification.similar_cases -%}
### Similar Cases
{% for case_id in classification.similar_cases %}
- {{ case_id }}
{% endfor %}
{% endif %}

{% if forecast_data and forecast_data.forecast_available -%}
### Forecast Analysis
- **Current Value**: {{ forecast_data.current_value }}
- **Forecast**: {{ "%.2f"|format(forecast_data.forecast) }}
- **Anomaly Score**: {{ "%.2f"|format(forecast_data.anomaly_score) }}
- **Exceeds Threshold**: {{ "Yes" if forecast_data.exceeds_threshold else "No" }}
- **Backtest MAPE**: {{ "%.2f"|format(forecast_data.backtest_mape) }}%
- **Confidence**: {{ "%.2f"|format(forecast_data.confidence * 100) }}%
{% endif %}

---

## Recommended Actions

{% for action in actions %}
### {{ loop.index }}. {{ action.title }} (Priority {{ action.priority }})

**Type**: {{ action.action_type.value }}
**Confidence**: {{ "%.2f"|format(action.confidence * 100) }}%
**Source**: {{ action.source }}
{% if action.estimated_effort -%}
**Estimated Effort**: {{ action.estimated_effort }}
{% endif -%}
**Automation Available**: {{ "Yes" if action.automation_available else "No" }}

{{ action.description }}

**Reasoning**: {{ action.reasoning }}

**Steps**:
{% for step in action.steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

---

{% endfor %}

## Summary

This triage report was automatically generated for signal {{ signal.signal_id }}.

- **Classification**: {{ classification.label.value.upper() }}
- **Confidence**: {{ "%.2f"|format(classification.confidence * 100) }}%
- **Recommended Actions**: {{ actions|length }}

*Generated by SOC Triage Bot*
""")
