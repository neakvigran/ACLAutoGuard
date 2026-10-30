"""Export local assessment evidence without implying live validation."""

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path

from aclautoguard.application import StaticAssessment


class ReportError(ValueError):
    """An assessment report could not be written."""


def write_static_report(assessment: StaticAssessment, path: str | Path) -> None:
    """Create a JSON report exclusively; refuse to replace existing files."""
    document = {
        "schema_version": 1,
        "report_type": "static_assessment",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "blocked": assessment.blocked,
        "shadow_findings": [asdict(finding) for finding in assessment.shadow_findings],
        "requirement_results": [
            {**asdict(result), "satisfied": result.satisfied}
            for result in assessment.requirement_results
        ],
        "traffic_sent": False,
        "limitations": [
            "Single-earlier-rule shadows only; joint coverage is not checked.",
            "Only explicitly selected host requirements were evaluated.",
            "ACL applicability and network paths are not verified.",
            "Baseline health and recovery readiness are not verified.",
            "This report is not deployment authorization or live traffic evidence.",
        ],
    }
    try:
        with Path(path).open("x", encoding="utf-8") as output:
            json.dump(document, output, indent=2)
            output.write("\n")
    except (OSError, UnicodeError) as exc:
        raise ReportError(f"Cannot write static report: {exc}") from exc
