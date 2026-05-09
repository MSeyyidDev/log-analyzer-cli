"""Report orchestration: run multiple analyzers and emit a combined view.

Three output formats are supported:

* ``rich`` — pretty terminal output (default)
* ``markdown`` — GitHub-flavored Markdown
* ``json`` — machine-readable JSON, one entry per analyzer
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

from log_analyzer.analyzers import (
    AnalysisResult,
    BaseAnalyzer,
    NotFoundAnalyzer,
    ServerErrorAnalyzer,
    StatusCodeAnalyzer,
    SuspiciousPatternAnalyzer,
    TopIPAnalyzer,
    TrafficByHourAnalyzer,
    UserAgentAnalyzer,
)
from log_analyzer.parser import LogEntry


def default_analyzers() -> list[BaseAnalyzer]:
    """Return the canonical set of analyzers used by ``report``."""
    return [
        TopIPAnalyzer(limit=10),
        StatusCodeAnalyzer(),
        NotFoundAnalyzer(limit=10),
        ServerErrorAnalyzer(limit=10),
        SuspiciousPatternAnalyzer(),
        UserAgentAnalyzer(limit=10),
        TrafficByHourAnalyzer(),
    ]


@dataclass
class Report:
    """A bundle of analyzer results plus run metadata."""

    source: str
    generated_at: datetime
    total_entries: int
    malformed: int
    results: list[AnalysisResult]

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "generated_at": self.generated_at.isoformat(),
            "total_entries": self.total_entries,
            "malformed": self.malformed,
            "analyzers": [
                {
                    "name": r.name,
                    "title": r.title,
                    "summary": r.summary,
                    "data": r.data,
                }
                for r in self.results
            ],
        }


class ReportBuilder:
    """Run a sequence of analyzers against a list of entries.

    The builder materializes the entries once and feeds the same list
    into each analyzer; analyzers should treat input as read-only.
    """

    def __init__(self, analyzers: Sequence[BaseAnalyzer] | None = None) -> None:
        self.analyzers: list[BaseAnalyzer] = list(analyzers or default_analyzers())

    def build(
        self,
        entries: Iterable[LogEntry],
        source: str,
        malformed: int = 0,
    ) -> Report:
        """Run all analyzers and assemble a :class:`Report`."""
        materialized = list(entries)
        results = [analyzer.analyze(materialized) for analyzer in self.analyzers]
        return Report(
            source=source,
            generated_at=datetime.now(timezone.utc),
            total_entries=len(materialized),
            malformed=malformed,
            results=results,
        )

    # ----- rendering -------------------------------------------------------

    def render_rich(self, report: Report, console: Console) -> None:
        """Render a Report to a Rich console."""
        header = Panel.fit(
            (
                f"[bold]Source:[/bold] {report.source}\n"
                f"[bold]Generated at:[/bold] {report.generated_at.isoformat()}\n"
                f"[bold]Total entries:[/bold] {report.total_entries:,}"
                + (
                    f"\n[bold]Malformed lines:[/bold] {report.malformed:,}"
                    if report.malformed
                    else ""
                )
            ),
            title="[bold cyan]log-analyzer report[/bold cyan]",
            border_style="cyan",
        )
        console.print(header)

        for analyzer, result in zip(self.analyzers, report.results):
            console.print(Rule(style="dim"))
            analyzer.render(result, console)

    def render_markdown(self, report: Report) -> str:
        """Render a Report as Markdown text."""
        lines: list[str] = []
        lines.append("# log-analyzer report\n")
        lines.append(f"- **Source:** `{report.source}`")
        lines.append(f"- **Generated at:** {report.generated_at.isoformat()}")
        lines.append(f"- **Total entries:** {report.total_entries:,}")
        if report.malformed:
            lines.append(f"- **Malformed lines:** {report.malformed:,}")
        lines.append("")

        for result in report.results:
            lines.append(f"## {result.title}\n")
            lines.append(f"_{result.summary}_\n")
            lines.extend(self._markdown_section(result))
            lines.append("")
        return "\n".join(lines)

    def render_json(self, report: Report) -> str:
        return json.dumps(report.to_dict(), indent=2, default=str)

    # ----- helpers ---------------------------------------------------------

    def _markdown_section(self, result: AnalysisResult) -> list[str]:
        data = result.data
        lines: list[str] = []
        if result.name == "topip" and data.get("top"):
            lines.append("| # | IP | Requests |")
            lines.append("| -:| -- | -------:|")
            for idx, item in enumerate(data["top"], 1):
                lines.append(f"| {idx} | `{item['ip']}` | {item['count']:,} |")
        elif result.name == "statuscode":
            lines.append("| Code | Count |")
            lines.append("| ---: | ----: |")
            for item in data.get("codes", []):
                lines.append(f"| {item['code']} | {item['count']:,} |")
        elif result.name == "notfound" and data.get("top"):
            lines.append("| # | Path | Hits |")
            lines.append("| -:| ---- | ---:|")
            for idx, item in enumerate(data["top"], 1):
                lines.append(f"| {idx} | `{item['path']}` | {item['count']:,} |")
        elif result.name == "servererror" and data.get("top"):
            lines.append("| # | Path | Code | Hits |")
            lines.append("| -:| ---- | ---:| ---:|")
            for idx, item in enumerate(data["top"], 1):
                lines.append(
                    f"| {idx} | `{item['path']}` | {item['code']} | {item['count']:,} |"
                )
        elif result.name == "suspiciouspattern":
            lines.append("| Severity | Category | Hits | Example |")
            lines.append("| -------- | -------- | ---: | ------- |")
            for cat in data.get("categories", []):
                example = cat["examples"][0] if cat["examples"] else "-"
                lines.append(
                    f"| **{cat['severity'].upper()}** | {cat['category']} | "
                    f"{cat['count']:,} | `{example}` |"
                )
        elif result.name == "useragent":
            lines.append("| Browser family | Requests |")
            lines.append("| -------------- | -------: |")
            for item in data.get("families", []):
                lines.append(f"| {item['family']} | {item['count']:,} |")
        elif result.name == "trafficbyhour":
            lines.append("| Hour (UTC) | Requests |")
            lines.append("| ---------: | -------: |")
            for item in data.get("hours", []):
                lines.append(f"| {item['hour']:02d}:00 | {item['count']:,} |")
        return lines


def write_report(
    report: Report,
    builder: ReportBuilder,
    fmt: str,
    out: Path | None,
    console: Console,
) -> None:
    """Render a :class:`Report` and write or print it according to ``fmt``."""
    fmt = fmt.lower()
    if fmt == "rich":
        if out is not None:
            file_console = Console(file=out.open("w", encoding="utf-8"), record=False)
            builder.render_rich(report, file_console)
        else:
            builder.render_rich(report, console)
    elif fmt == "markdown":
        text = builder.render_markdown(report)
        if out is not None:
            out.write_text(text, encoding="utf-8")
            console.print(f"[green]Markdown report written to[/green] {out}")
        else:
            console.print(text)
    elif fmt == "json":
        text = builder.render_json(report)
        if out is not None:
            out.write_text(text, encoding="utf-8")
            console.print(f"[green]JSON report written to[/green] {out}")
        else:
            console.print(text)
    else:
        raise ValueError(f"Unknown report format: {fmt!r}")
