"""Top-IP analyzer: who hits the server hardest?"""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from rich.console import Console
from rich.table import Table

from log_analyzer.analyzers.base import AnalysisResult, BaseAnalyzer
from log_analyzer.parser import LogEntry


class TopIPAnalyzer(BaseAnalyzer):
    """Aggregate request counts per source IP."""

    title = "Top IP addresses"

    def __init__(self, limit: int = 15) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self.limit = limit

    def analyze(self, entries: Iterable[LogEntry]) -> AnalysisResult:
        counter: Counter[str] = Counter()
        total = 0
        for entry in entries:
            counter[entry.ip] += 1
            total += 1

        top = counter.most_common(self.limit)
        unique_ips = len(counter)

        return AnalysisResult(
            name=self.name,
            title=self.title,
            summary=(
                f"{unique_ips:,} unique IPs across {total:,} requests; "
                f"top {len(top)} shown"
            ),
            data={
                "total_requests": total,
                "unique_ips": unique_ips,
                "top": [{"ip": ip, "count": count} for ip, count in top],
            },
        )

    def render(self, result: AnalysisResult, console: Console) -> None:
        table = Table(
            title=result.title,
            title_style="bold cyan",
            header_style="bold magenta",
            show_lines=False,
        )
        table.add_column("#", justify="right", style="dim")
        table.add_column("IP", style="cyan")
        table.add_column("Requests", justify="right", style="green")
        table.add_column("Share", justify="right", style="yellow")

        total = max(1, result.data.get("total_requests", 0))
        for idx, item in enumerate(result.data["top"], start=1):
            share = 100.0 * item["count"] / total
            table.add_row(
                str(idx),
                item["ip"],
                f"{item['count']:,}",
                f"{share:5.2f}%",
            )

        console.print(table)
        console.print(f"[dim]{result.summary}[/dim]")
