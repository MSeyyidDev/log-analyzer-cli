"""Server-error analyzer (5xx responses)."""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from rich.console import Console
from rich.table import Table

from log_analyzer.analyzers.base import AnalysisResult, BaseAnalyzer
from log_analyzer.parser import LogEntry


class ServerErrorAnalyzer(BaseAnalyzer):
    """Group 5xx responses by path and status code."""

    title = "Server errors (5xx)"

    def __init__(self, limit: int = 15) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self.limit = limit

    def analyze(self, entries: Iterable[LogEntry]) -> AnalysisResult:
        by_path: Counter[tuple[str, int]] = Counter()
        codes: Counter[int] = Counter()
        total = 0
        for entry in entries:
            if entry.is_server_error:
                by_path[(entry.path_only, entry.status)] += 1
                codes[entry.status] += 1
                total += 1
        top = by_path.most_common(self.limit)

        return AnalysisResult(
            name=self.name,
            title=self.title,
            summary=f"{total:,} 5xx responses across {len(by_path)} (path, code) pairs",
            data={
                "total": total,
                "codes": [{"code": c, "count": n} for c, n in sorted(codes.items())],
                "top": [
                    {"path": path, "code": code, "count": count}
                    for (path, code), count in top
                ],
            },
        )

    def render(self, result: AnalysisResult, console: Console) -> None:
        if result.data["total"] == 0:
            console.print("[green]No 5xx server errors detected.[/green]")
            return

        table = Table(
            title=result.title,
            title_style="bold red",
            header_style="bold magenta",
        )
        table.add_column("#", justify="right", style="dim")
        table.add_column("Path", style="yellow")
        table.add_column("Code", justify="right", style="red")
        table.add_column("Hits", justify="right", style="bold")
        for idx, item in enumerate(result.data["top"], start=1):
            table.add_row(
                str(idx),
                item["path"],
                str(item["code"]),
                f"{item['count']:,}",
            )
        console.print(table)
        console.print(f"[dim]{result.summary}[/dim]")
