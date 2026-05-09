"""User-Agent analyzer.

Buckets requests by browser family / device type using the optional
``user-agents`` library when available, falling back to regex heuristics
otherwise.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from rich.console import Console
from rich.table import Table

from log_analyzer.analyzers.base import AnalysisResult, BaseAnalyzer
from log_analyzer.parser import LogEntry

try:  # pragma: no cover - import-time dependency check
    from user_agents import parse as _ua_parse

    _HAVE_UA = True
except Exception:  # pragma: no cover
    _HAVE_UA = False


def _classify(ua_string: str) -> tuple[str, str]:
    """Return ``(family, device_type)`` for a UA string."""
    if _HAVE_UA:
        ua = _ua_parse(ua_string)
        if ua.is_bot:
            family = ua.browser.family or "Bot"
            return family, "bot"
        family = ua.browser.family or "Other"
        if ua.is_mobile:
            return family, "mobile"
        if ua.is_tablet:
            return family, "tablet"
        return family, "desktop"

    lower = ua_string.lower()
    if any(b in lower for b in ("bot", "crawler", "spider", "curl", "wget", "python-")):
        return "Bot", "bot"
    if "edg/" in lower:
        return "Edge", "desktop"
    if "chrome" in lower:
        return "Chrome", "mobile" if "mobile" in lower else "desktop"
    if "firefox" in lower:
        return "Firefox", "desktop"
    if "safari" in lower:
        return "Safari", "mobile" if "mobile" in lower else "desktop"
    return "Other", "desktop"


class UserAgentAnalyzer(BaseAnalyzer):
    """Aggregate requests by browser family and device type."""

    title = "User agents"

    def __init__(self, limit: int = 15) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self.limit = limit

    def analyze(self, entries: Iterable[LogEntry]) -> AnalysisResult:
        families: Counter[str] = Counter()
        devices: Counter[str] = Counter()
        raw: Counter[str] = Counter()
        total = 0
        for entry in entries:
            family, device = _classify(entry.user_agent)
            families[family] += 1
            devices[device] += 1
            raw[entry.user_agent] += 1
            total += 1

        return AnalysisResult(
            name=self.name,
            title=self.title,
            summary=(
                f"{total:,} requests across {len(families)} browser families "
                f"({len(raw)} distinct UA strings)"
            ),
            data={
                "total": total,
                "families": [
                    {"family": f, "count": c} for f, c in families.most_common(self.limit)
                ],
                "devices": [
                    {"device": d, "count": c} for d, c in devices.most_common()
                ],
                "top_strings": [
                    {"ua": ua, "count": c} for ua, c in raw.most_common(self.limit)
                ],
            },
        )

    def render(self, result: AnalysisResult, console: Console) -> None:
        total = max(1, result.data["total"])

        family_table = Table(
            title=f"{result.title} - browser families",
            title_style="bold cyan",
            header_style="bold magenta",
        )
        family_table.add_column("Family", style="cyan")
        family_table.add_column("Requests", justify="right", style="green")
        family_table.add_column("Share", justify="right", style="yellow")
        for item in result.data["families"]:
            share = 100.0 * item["count"] / total
            family_table.add_row(item["family"], f"{item['count']:,}", f"{share:5.2f}%")

        device_table = Table(
            title="Device classes",
            title_style="bold cyan",
            header_style="bold magenta",
        )
        device_table.add_column("Device", style="cyan")
        device_table.add_column("Requests", justify="right", style="green")
        device_table.add_column("Share", justify="right", style="yellow")
        for item in result.data["devices"]:
            share = 100.0 * item["count"] / total
            device_table.add_row(item["device"], f"{item['count']:,}", f"{share:5.2f}%")

        console.print(family_table)
        console.print(device_table)
        console.print(f"[dim]{result.summary}[/dim]")
