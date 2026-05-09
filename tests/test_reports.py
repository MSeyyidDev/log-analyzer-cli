"""Tests for log_analyzer.reports."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from log_analyzer.parser import LogEntry
from log_analyzer.reports import ReportBuilder, write_report


def test_report_builder_runs_all_default_analyzers(sample_entries: list[LogEntry]) -> None:
    builder = ReportBuilder()
    report = builder.build(sample_entries, source="sample.log")
    names = {r.name for r in report.results}
    expected = {
        "topip",
        "statuscode",
        "notfound",
        "servererror",
        "suspiciouspattern",
        "useragent",
        "trafficbyhour",
    }
    assert expected.issubset(names)
    assert report.total_entries == len(sample_entries)


def test_render_markdown_contains_sections(sample_entries: list[LogEntry]) -> None:
    builder = ReportBuilder()
    report = builder.build(sample_entries, source="sample.log")
    md = builder.render_markdown(report)
    assert "# log-analyzer report" in md
    assert "## Top IP addresses" in md
    assert "## Suspicious requests" in md
    assert "| Severity | Category |" in md


def test_render_json_is_valid(sample_entries: list[LogEntry]) -> None:
    builder = ReportBuilder()
    report = builder.build(sample_entries, source="sample.log")
    payload = json.loads(builder.render_json(report))
    assert payload["total_entries"] == len(sample_entries)
    analyzer_names = {a["name"] for a in payload["analyzers"]}
    assert "suspiciouspattern" in analyzer_names


def test_write_report_markdown_file(
    tmp_path: Path, sample_entries: list[LogEntry]
) -> None:
    builder = ReportBuilder()
    report = builder.build(sample_entries, source="sample.log")
    out = tmp_path / "report.md"
    console = Console(record=True, width=120)
    write_report(report, builder, "markdown", out, console)
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "log-analyzer report" in text


def test_write_report_json_file(tmp_path: Path, sample_entries: list[LogEntry]) -> None:
    builder = ReportBuilder()
    report = builder.build(sample_entries, source="sample.log")
    out = tmp_path / "report.json"
    console = Console(record=True, width=120)
    write_report(report, builder, "json", out, console)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["total_entries"] == len(sample_entries)


def test_write_report_rich_to_stdout(sample_entries: list[LogEntry]) -> None:
    builder = ReportBuilder()
    report = builder.build(sample_entries, source="sample.log")
    console = Console(record=True, width=140)
    write_report(report, builder, "rich", None, console)
    text = console.export_text()
    assert "log-analyzer report" in text
    assert "Suspicious requests" in text


def test_write_report_unknown_format_raises(sample_entries: list[LogEntry]) -> None:
    builder = ReportBuilder()
    report = builder.build(sample_entries, source="sample.log")
    console = Console(record=True)
    try:
        write_report(report, builder, "yaml", None, console)
    except ValueError as exc:
        assert "Unknown" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError")
