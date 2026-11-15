"""Multi-format DFIR forensic report builder (JSON, Markdown, and standalone HTML).

Uses Jinja2 templates for structured Markdown and self-contained dark-mode HTML
investigation reports with automatic HTML escaping to protect analysts against
stored XSS payloads embedded inside malicious packet captures.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.models import (
    ForensicReportData,
    format_bytes,
    format_duration,
    format_utc_timestamp,
)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _md_escape(value: Any) -> str:
    """Escape pipe characters and newlines so Markdown tables stay well-formed."""
    text = str(value if value is not None else "")
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


class ReportBuilder:
    """Generates JSON, Markdown, and standalone dark-mode HTML forensic reports."""

    def __init__(self, templates_dir: Path | None = None) -> None:
        tpl_dir = templates_dir or TEMPLATES_DIR
        self._html_env = Environment(
            loader=FileSystemLoader(str(tpl_dir)),
            autoescape=select_autoescape(enabled_extensions=("html", "j2", "xml"), default_for_string=True),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._md_env = Environment(
            loader=FileSystemLoader(str(tpl_dir)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        for env in (self._html_env, self._md_env):
            env.filters["fmt_utc"] = format_utc_timestamp
            env.filters["fmt_bytes"] = format_bytes
            env.filters["fmt_duration"] = format_duration
            env.filters["md_escape"] = _md_escape

    def build_json_string(self, report: ForensicReportData) -> str:
        """Serialize the full forensic dataset into pretty-printed JSON."""
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)

    def write_json(self, report: ForensicReportData, output_path: str | Path) -> Path:
        """Write the JSON forensic report to disk."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.build_json_string(report), encoding="utf-8")
        return out

    def build_markdown_string(self, report: ForensicReportData) -> str:
        """Render the structured Markdown investigation report via Jinja2."""
        template = self._md_env.get_template("report.md.j2")
        return template.render(report=report, data=report.to_dict())

    def write_markdown(self, report: ForensicReportData, output_path: str | Path) -> Path:
        """Write the Markdown forensic report to disk."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.build_markdown_string(report), encoding="utf-8")
        return out

    def build_html_string(self, report: ForensicReportData) -> str:
        """Render the self-contained dark-mode HTML dashboard report via Jinja2."""
        template = self._html_env.get_template("report.html.j2")
        return template.render(report=report, data=report.to_dict())

    def write_html(self, report: ForensicReportData, output_path: str | Path) -> Path:
        """Write the standalone HTML forensic report to disk."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.build_html_string(report), encoding="utf-8")
        return out
