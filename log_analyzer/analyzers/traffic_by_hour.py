"""Traffic-by-hour analyzer with an inline ASCII bar chart."""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from rich.console import Console
from rich.table import Table

from log_analyzer.analyzers.base import AnalysisResult, BaseAnalyzer
from log_analyzer.parser import LogEntry


_BAR_WIDTH = 40


class TrafficByHourAnalyzer(BaseAnalyzer):
    """Count requests bucketed by UTC hour-of-day."""

    title = "Traffic by hour (UTC)"

    def analyze(self, entries: Iterable[LogEntry]) -> AnalysisResult:
        per_hour: Counter[int] = Counter()
        total = 0
        for entry in entries:
            per_hour[entry.timestamp.hour] += 1
            total += 1

        hours = [{"hour": h, "count": per_hour.get(h, 0)} for h in range(24)]
        peak = max(hours, key=lambda h: h["count"]) if total else {"hour": 0, "count": 0}

        return AnalysisResult(
            name=self.name,
            title=self.title,
            summary=(
                f"{total:,} requests; peak hour {peak['hour']:02d}:00 UTC "
                f"with {peak['count']:,} hits"
            ),
            data={"total": total, "hours": hours, "peak": peak},
        )

    def render(self, result: AnalysisResult, console: Console) -> None:
        max_count = max((h["count"] for h in result.data["hours"]), default=1) or 1

        table = Table(
            title=result.title,
            title_style="bold cyan",
            header_style="bold magenta",
        )
        table.add_column("Hour", justify="right", style="bold")
        table.add_column("Requests", justify="right", style="green")
        table.add_column("Distribution", style="cyan")

        for item in result.data["hours"]:
            bar_len = int(round(_BAR_WIDTH * item["count"] / max_count))
            bar = "#" * bar_len
            table.add_row(
                f"{item['hour']:02d}:00",
                f"{item['count']:,}",
                bar,
            )

        console.print(table)
        console.print(f"[dim]{result.summary}[/dim]")
