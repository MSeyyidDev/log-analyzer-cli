"""Suspicious-pattern analyzer.

Detects requests that look like reconnaissance, exploitation attempts
or brute-force activity. Each detection is tagged with a category and a
severity (``low`` / ``medium`` / ``high`` / ``critical``).
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from log_analyzer.analyzers.base import AnalysisResult, BaseAnalyzer
from log_analyzer.parser import LogEntry


@dataclass(frozen=True)
class Rule:
    """A single suspicious-pattern detection rule."""

    category: str
    severity: str
    pattern: re.Pattern[str]
    target: str  # "path" or "ua"
    description: str


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


_RULES: tuple[Rule, ...] = (
    Rule(
        category="admin-probe",
        severity="high",
        pattern=re.compile(
            r"/(?:admin(?:\.php)?|wp-login\.php|wp-admin/setup-config\.php|"
            r"phpmyadmin|administrator|cpanel)(?:/|$|\?)",
            re.IGNORECASE,
        ),
        target="path",
        description="Probe of well-known admin / CMS endpoints",
    ),
    Rule(
        category="config-leak",
        severity="critical",
        pattern=re.compile(
            r"/(?:\.env(?:\.\w+)?|\.git/(?:config|HEAD)|\.aws/credentials|"
            r"\.ssh/(?:id_rsa|authorized_keys)|config\.php\.bak|backup\.zip|db\.sql)"
            r"(?:$|\?)",
            re.IGNORECASE,
        ),
        target="path",
        description="Attempted access to leaked secrets / config files",
    ),
    Rule(
        category="sql-injection",
        severity="critical",
        pattern=re.compile(
            r"(?:%27|')(?:\s|%20)*(?:or|union|select|drop|--|#)|"
            r"\bunion\s+select\b|\bdrop\s+table\b|\bor\s+1=1\b",
            re.IGNORECASE,
        ),
        target="path",
        description="SQL-injection payload in URL or query string",
    ),
    Rule(
        category="xss",
        severity="high",
        pattern=re.compile(
            r"<script\b|onerror\s*=|onload\s*=|javascript:|<svg\b[^>]*onload",
            re.IGNORECASE,
        ),
        target="path",
        description="Cross-site-scripting payload in URL or query string",
    ),
    Rule(
        category="path-traversal",
        severity="high",
        pattern=re.compile(r"(?:\.\./){2,}|%2e%2e%2f|%2e%2e/", re.IGNORECASE),
        target="path",
        description="Path-traversal attempt (../ sequences)",
    ),
    Rule(
        category="rce-probe",
        severity="critical",
        pattern=re.compile(
            r"/(?:_ignition/execute-solution|actuator/env|"
            r"vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php|"
            r"cgi-bin/[^?]+\.cgi)(?:$|\?)",
            re.IGNORECASE,
        ),
        target="path",
        description="Probe of known RCE / framework debug endpoints",
    ),
    Rule(
        category="dirbuster",
        severity="medium",
        pattern=re.compile(
            r"/(?:backup|old|test|tmp|uploads|dev|staging|private|hidden|"
            r"console|swagger|api-docs|server-status)(?:$|/|\?)",
            re.IGNORECASE,
        ),
        target="path",
        description="Directory-busting / hidden-resource enumeration",
    ),
    Rule(
        category="bad-user-agent",
        severity="medium",
        pattern=re.compile(
            r"sqlmap|nikto|nmap|masscan|zgrab|zmeu|acunetix|wpscan",
            re.IGNORECASE,
        ),
        target="ua",
        description="Known offensive-tool User-Agent string",
    ),
    Rule(
        category="shellshock",
        severity="critical",
        pattern=re.compile(r"\(\)\s*\{\s*:;\s*\};", re.IGNORECASE),
        target="ua",
        description="Shellshock probe in User-Agent header",
    ),
)


class SuspiciousPatternAnalyzer(BaseAnalyzer):
    """Identify and group requests that look offensive."""

    title = "Suspicious requests"

    def __init__(self, brute_force_threshold: int = 10) -> None:
        if brute_force_threshold < 2:
            raise ValueError("brute_force_threshold must be >= 2")
        self.brute_force_threshold = brute_force_threshold

    def analyze(self, entries: Iterable[LogEntry]) -> AnalysisResult:
        category_counts: Counter[str] = Counter()
        category_severity: dict[str, str] = {}
        category_examples: dict[str, list[str]] = defaultdict(list)
        per_ip_categories: dict[str, set[str]] = defaultdict(set)
        login_attempts: Counter[str] = Counter()
        flagged_total = 0

        for entry in entries:
            matched = False
            for rule in _RULES:
                target = entry.path if rule.target == "path" else entry.user_agent
                if rule.pattern.search(target):
                    matched = True
                    category_counts[rule.category] += 1
                    category_severity[rule.category] = rule.severity
                    if len(category_examples[rule.category]) < 5:
                        category_examples[rule.category].append(
                            f"{entry.ip} {entry.method} {entry.path_only or entry.path}"
                        )
                    per_ip_categories[entry.ip].add(rule.category)
            if (
                entry.method == "POST"
                and entry.path_only.rstrip("/") in ("/login", "/wp-login.php", "/admin/login")
            ):
                login_attempts[entry.ip] += 1
            if matched:
                flagged_total += 1

        # Brute-force detection layered on top of raw rule matches.
        brute_force_ips = [
            {"ip": ip, "attempts": count}
            for ip, count in login_attempts.most_common()
            if count >= self.brute_force_threshold
        ]
        if brute_force_ips:
            category_counts["brute-force"] += sum(
                item["attempts"] for item in brute_force_ips
            )
            category_severity["brute-force"] = "high"
            category_examples["brute-force"] = [
                f"{item['ip']} -> {item['attempts']} POST /login attempts"
                for item in brute_force_ips[:5]
            ]

        categories = []
        for cat, count in category_counts.most_common():
            categories.append(
                {
                    "category": cat,
                    "count": count,
                    "severity": category_severity.get(cat, "low"),
                    "examples": category_examples.get(cat, []),
                }
            )
        categories.sort(
            key=lambda item: (
                _SEVERITY_ORDER.get(item["severity"], 99),
                -item["count"],
            )
        )

        top_offenders = sorted(
            (
                {"ip": ip, "categories": sorted(cats), "category_count": len(cats)}
                for ip, cats in per_ip_categories.items()
            ),
            key=lambda item: item["category_count"],
            reverse=True,
        )[:10]

        return AnalysisResult(
            name=self.name,
            title=self.title,
            summary=(
                f"{flagged_total:,} suspicious requests across "
                f"{len(category_counts)} categories"
            ),
            data={
                "flagged_total": flagged_total,
                "categories": categories,
                "top_offenders": top_offenders,
                "brute_force_ips": brute_force_ips,
            },
        )

    def render(self, result: AnalysisResult, console: Console) -> None:
        if not result.data["categories"]:
            console.print(
                Panel.fit(
                    "[green]No suspicious patterns detected.[/green]",
                    title="Suspicious requests",
                    border_style="green",
                )
            )
            return

        table = Table(
            title=result.title,
            title_style="bold red",
            header_style="bold magenta",
        )
        table.add_column("Severity", style="bold")
        table.add_column("Category", style="cyan")
        table.add_column("Hits", justify="right", style="red")
        table.add_column("Example", style="dim")
        for cat in result.data["categories"]:
            sev = cat["severity"]
            color = {
                "critical": "bright_red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
            }.get(sev, "white")
            example = cat["examples"][0] if cat["examples"] else "-"
            table.add_row(
                f"[{color}]{sev.upper()}[/{color}]",
                cat["category"],
                f"{cat['count']:,}",
                example,
            )
        console.print(table)

        if result.data["top_offenders"]:
            offenders = Table(
                title="Top offending IPs",
                title_style="bold yellow",
                header_style="bold magenta",
            )
            offenders.add_column("IP", style="cyan")
            offenders.add_column("Distinct categories", justify="right")
            offenders.add_column("Categories", style="dim")
            for off in result.data["top_offenders"]:
                offenders.add_row(
                    off["ip"],
                    str(off["category_count"]),
                    ", ".join(off["categories"]),
                )
            console.print(offenders)

        console.print(f"[dim]{result.summary}[/dim]")
