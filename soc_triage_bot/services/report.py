"""Report generation service using Jinja templates.

This service renders the 13-section triage report from a TriageReport model.
It uses the enterprise template: triage_report.md.j2

FORWARD ONLY: This service requires the new TriageReport model structure.
No legacy fallbacks or backward compatibility with old Signal/Classification models.
"""

from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

from ..models import AIOverlay
from ..models.triage_report import TriageReport

# Default template directory (relative to this file)
DEFAULT_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
TEMPLATE_NAME = "triage_report.md.j2"


class ReportService:
    """Service for rendering triage reports.

    Requires:
        - TriageReport model with all sections populated
        - Optional AIOverlay for LLM-generated insights

    Usage:
        service = ReportService()
        report_md = service.generate_report(triage_report, ai_overlay=ai_overlay)
    """

    def __init__(self, template_dir: Optional[str] = None):
        """Initialize report service.

        Args:
            template_dir: Directory containing Jinja templates.
                         If not provided, uses the default templates directory.

        Raises:
            FileNotFoundError: If template directory or template file doesn't exist.
        """
        self.template_path = (
            Path(template_dir) if template_dir else DEFAULT_TEMPLATE_DIR
        )

        if not self.template_path.exists():
            raise FileNotFoundError(
                f"Template directory not found: {self.template_path}"
            )

        template_file = self.template_path / TEMPLATE_NAME
        if not template_file.exists():
            raise FileNotFoundError(f"Template file not found: {template_file}")

        self.env = Environment(loader=FileSystemLoader(str(self.template_path)))

    def generate_report(
        self,
        r: TriageReport,
        ai_overlay: Optional[AIOverlay] = None,
    ) -> str:
        """Generate Markdown triage report from TriageReport model.

        Args:
            r: The complete TriageReport model containing all 13 sections.
            ai_overlay: Optional AI overlay with LLM-generated summaries/explanations.

        Returns:
            Rendered Markdown report string.

        Template Variables:
            - r: TriageReport (top-level container)
            - r.signal: NormalizedSignal
            - r.meta: ReportMeta
            - r.ctx: SignalContext (entity focus)
            - r.classification: ClassificationResult
            - r.forecast: ForecastData (with tracks)
            - r.enrich: EnrichmentBundle
            - r.similar_cases: List[SimilarCase]
            - r.recommendations: List[Recommendation]
            - r.exec: ExecutiveSummary
            - ai_overlay: AIOverlay (optional, LLM insights)
        """
        template = self.env.get_template(TEMPLATE_NAME)
        return template.render(r=r, ai_overlay=ai_overlay)
