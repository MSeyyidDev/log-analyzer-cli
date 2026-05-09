"""Status-code distribution analyzer."""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from rich.console import Console
from rich.table import Table

from log_analyzer.analyzers.base import AnalysisResult, BaseAnalyzer
from log_analyzer.parser import LogEntry


_CLASS_LABELS = {
    1: ("1xx informational", "blue"),
    2: ("2xx success", "green"),
    3: ("3xx redirection", "cyan"),
    4: ("4xx client error", "yellow"),
    5: ("5xx server error", "red"),
}


class StatusCodeAnalyzer(BaseAnalyzer):
    """Count HTTP status codes and roll them up into class buckets."""

    title = "HTTP status codes"

    def analyze(self, entries: Iterable[LogEntry]) -> AnalysisResult:
        codes: Counter[int] = Counter()
        classes: Counter[int] = Counter()
        total = 0
        for entry in entries:
            codes[entry.status] += 1
            classes[entry.status // 100] += 1
            total += 1

        return AnalysisResult(
            name=self.name,
            title=self.title,
            summary=f"{total:,} requests across {len(codes)} distinct status codes",
            data={
                "total": total,
                "codes": [
                    {"code": code, "count": count}
                    for code, count in sorted(codes.items())
                ],
                "classes": [
                    {"class": klass, "count": count}
                    for klass, count in sorted(classes.items())
                ],
            },
        )

    def render(self, result: AnalysisResult, console: Console) -> None:
        total = max(1, result.data["total"])

        class_table = Table(
            title=f"{result.title} - by class",
            title_style="bold cyan",
            header_style="bold magenta",
        )
        class_table.add_column("Class", style="bold")
        class_table.add_column("Count", justify="right")
        class_table.add_column("Share", justify="right")
        for item in result.data["classes"]:
            label, style = _CLASS_LABELS.get(item["class"], (f"{item['class']}xx", "white"))
            share = 100.0 * item["count"] / total
            class_table.add_row(
                f"[{style}]{label}[/{style}]",
                f"{item['count']:,}",
                f"{share:5.2f}%",
            )

        code_table = Table(
            title=f"{result.title} - detail",
            title_style="bold cyan",
            header_style="bold magenta",
        )
        code_table.add_column("Code", justify="right", style="bold")
        code_table.add_column("Count", justify="right")
        code_table.add_column("Share", justify="right")
        for item in result.data["codes"]:
            share = 100.0 * item["count"] / total
            style = _CLASS_LABELS.get(item["code"] // 100, ("", "white"))[1]
            code_table.add_row(
                f"[{style}]{item['code']}[/{style}]",
                f"{item['count']:,}",
                f"{share:5.2f}%",
            )

        console.print(class_table)
        console.print(code_table)
        console.print(f"[dim]{result.summary}[/dim]")
