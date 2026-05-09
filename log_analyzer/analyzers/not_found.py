"""Most-requested URLs that produced a 404 response."""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from rich.console import Console
from rich.table import Table

from log_analyzer.analyzers.base import AnalysisResult, BaseAnalyzer
from log_analyzer.parser import LogEntry


class NotFoundAnalyzer(BaseAnalyzer):
    """Surface frequently-requested missing paths."""

    title = "Top 404 / Not Found paths"

    def __init__(self, limit: int = 15) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self.limit = limit

    def analyze(self, entries: Iterable[LogEntry]) -> AnalysisResult:
        counter: Counter[str] = Counter()
        total_404 = 0
        for entry in entries:
            if entry.status == 404:
                counter[entry.path_only] += 1
                total_404 += 1

        top = counter.most_common(self.limit)
        return AnalysisResult(
            name=self.name,
            title=self.title,
            summary=f"{total_404:,} responses with status 404 across {len(counter)} unique paths",
            data={
                "total_404": total_404,
                "unique_paths": len(counter),
                "top": [{"path": path, "count": count} for path, count in top],
            },
        )

    def render(self, result: AnalysisResult, console: Console) -> None:
        table = Table(
            title=result.title,
            title_style="bold cyan",
            header_style="bold magenta",
        )
        table.add_column("#", justify="right", style="dim")
        table.add_column("Path", style="yellow")
        table.add_column("Hits", justify="right", style="red")
        for idx, item in enumerate(result.data["top"], start=1):
            table.add_row(str(idx), item["path"], f"{item['count']:,}")
        console.print(table)
        console.print(f"[dim]{result.summary}[/dim]")
