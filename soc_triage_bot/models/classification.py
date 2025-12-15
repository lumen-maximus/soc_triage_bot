"""Classification label enum.

The main classification model is ClassificationResult in triage_report.py.
This module only exports the ClassificationLabel enum for disposition mapping.
"""

from enum import Enum


class ClassificationLabel(str, Enum):
    """Classification labels for signal disposition."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_POSITIVE = "benign_positive"
    UNKNOWN = "unknown"
