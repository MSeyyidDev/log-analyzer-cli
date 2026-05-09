"""Tests for the analyzer suite."""

from __future__ import annotations

from typing import Iterable

import pytest
from rich.console import Console

from log_analyzer.analyzers import (
    NotFoundAnalyzer,
    ServerErrorAnalyzer,
    StatusCodeAnalyzer,
    SuspiciousPatternAnalyzer,
    TopIPAnalyzer,
    TrafficByHourAnalyzer,
    UserAgentAnalyzer,
)
from log_analyzer.parser import LogEntry


def _render(analyzer, entries: Iterable[LogEntry]) -> str:
    console = Console(record=True, width=120)
    result = analyzer.analyze(list(entries))
    analyzer.render(result, console)
    return console.export_text()


def test_top_ips_counts_and_orders(sample_entries: list[LogEntry]) -> None:
    analyzer = TopIPAnalyzer(limit=3)
    result = analyzer.analyze(sample_entries)
    top = result.data["top"]
    counts = {row["ip"]: row["count"] for row in top}
    # 192.0.2.99 brute-forced 12 times in the fixture.
    assert counts.get("192.0.2.99") == 12
    assert top[0]["count"] >= top[-1]["count"]
    assert result.data["unique_ips"] >= 4


def test_top_ips_render_includes_summary(sample_entries: list[LogEntry]) -> None:
    text = _render(TopIPAnalyzer(limit=5), sample_entries)
    assert "unique IPs" in text
    assert "192.0.2.99" in text


def test_top_ips_invalid_limit() -> None:
    with pytest.raises(ValueError):
        TopIPAnalyzer(limit=0)


def test_status_code_distribution(sample_entries: list[LogEntry]) -> None:
    analyzer = StatusCodeAnalyzer()
    result = analyzer.analyze(sample_entries)
    codes = {row["code"]: row["count"] for row in result.data["codes"]}
    assert codes.get(200, 0) >= 2
    assert codes.get(404, 0) >= 2
    assert codes.get(500, 0) == 1
    assert codes.get(401, 0) >= 1


def test_status_code_render(sample_entries: list[LogEntry]) -> None:
    text = _render(StatusCodeAnalyzer(), sample_entries)
    assert "status codes" in text.lower()


def test_not_found_analyzer(sample_entries: list[LogEntry]) -> None:
    analyzer = NotFoundAnalyzer(limit=10)
    result = analyzer.analyze(sample_entries)
    paths = {row["path"]: row["count"] for row in result.data["top"]}
    assert "/missing-page" in paths
    assert "/wp-login.php" in paths
    assert "/.env" in paths
    assert result.data["total_404"] >= 3


def test_not_found_render(sample_entries: list[LogEntry]) -> None:
    text = _render(NotFoundAnalyzer(), sample_entries)
    assert "/missing-page" in text


def test_server_errors(sample_entries: list[LogEntry]) -> None:
    analyzer = ServerErrorAnalyzer()
    result = analyzer.analyze(sample_entries)
    assert result.data["total"] == 1
    assert result.data["top"][0]["path"] == "/api/v1/orders"
    assert result.data["top"][0]["code"] == 500


def test_server_errors_empty_render() -> None:
    text = _render(ServerErrorAnalyzer(), [])
    assert "No 5xx" in text


def test_suspicious_detects_admin_probe(sample_entries: list[LogEntry]) -> None:
    result = SuspiciousPatternAnalyzer(brute_force_threshold=10).analyze(sample_entries)
    cats = {row["category"] for row in result.data["categories"]}
    assert "admin-probe" in cats
    assert "config-leak" in cats
    assert "sql-injection" in cats
    assert "bad-user-agent" in cats
    assert "brute-force" in cats


def test_suspicious_severity_assignment(sample_entries: list[LogEntry]) -> None:
    result = SuspiciousPatternAnalyzer().analyze(sample_entries)
    by_cat = {row["category"]: row["severity"] for row in result.data["categories"]}
    assert by_cat["config-leak"] == "critical"
    assert by_cat["sql-injection"] == "critical"
    assert by_cat["admin-probe"] == "high"


def test_suspicious_brute_force_threshold(sample_entries: list[LogEntry]) -> None:
    # threshold 100 → no brute-force flag
    result = SuspiciousPatternAnalyzer(brute_force_threshold=100).analyze(sample_entries)
    cats = {row["category"] for row in result.data["categories"]}
    assert "brute-force" not in cats


def test_suspicious_empty_render() -> None:
    text = _render(SuspiciousPatternAnalyzer(), [])
    assert "No suspicious patterns" in text


def test_suspicious_render_table(sample_entries: list[LogEntry]) -> None:
    text = _render(SuspiciousPatternAnalyzer(), sample_entries)
    assert "Suspicious requests" in text
    assert "admin-probe" in text


def test_user_agent_analyzer(sample_entries: list[LogEntry]) -> None:
    result = UserAgentAnalyzer().analyze(sample_entries)
    families = [row["family"] for row in result.data["families"]]
    assert any("Chrome" in f or "Safari" in f for f in families)
    assert result.data["total"] == len(sample_entries)


def test_user_agent_render(sample_entries: list[LogEntry]) -> None:
    text = _render(UserAgentAnalyzer(), sample_entries)
    assert "browser families" in text


def test_traffic_by_hour_buckets_correctly(sample_entries: list[LogEntry]) -> None:
    result = TrafficByHourAnalyzer().analyze(sample_entries)
    assert len(result.data["hours"]) == 24
    # All sample entries happen during UTC hour 13 or 14.
    interesting_hours = {h["hour"]: h["count"] for h in result.data["hours"] if h["count"]}
    assert set(interesting_hours).issubset({13, 14})
    assert sum(interesting_hours.values()) == len(sample_entries)


def test_traffic_by_hour_render(sample_entries: list[LogEntry]) -> None:
    text = _render(TrafficByHourAnalyzer(), sample_entries)
    assert "Traffic by hour" in text
