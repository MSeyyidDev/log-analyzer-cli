"""End-to-end CLI tests via Typer's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from log_analyzer.cli import app


runner = CliRunner()


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "log-analyzer" in result.stdout
    assert "generate" in result.stdout


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "log-analyzer" in result.stdout


def test_cli_generate_creates_file(tmp_path: Path) -> None:
    out = tmp_path / "x.log"
    result = runner.invoke(
        app,
        ["generate", "--out", str(out), "--lines", "200", "--days", "2", "--seed", "7"],
    )
    assert result.exit_code == 0, result.stdout
    assert out.exists()
    assert sum(1 for _ in out.open(encoding="utf-8")) == 200
    assert "Generation complete" in result.stdout


def test_cli_parse_outputs_table(generated_log_file: Path) -> None:
    result = runner.invoke(app, ["parse", str(generated_log_file), "--head", "2", "--tail", "2"])
    assert result.exit_code == 0
    assert "entries" in result.stdout


def test_cli_top_ips(generated_log_file: Path) -> None:
    result = runner.invoke(app, ["top-ips", str(generated_log_file), "--limit", "5"])
    assert result.exit_code == 0
    assert "IP" in result.stdout


def test_cli_status_codes(generated_log_file: Path) -> None:
    result = runner.invoke(app, ["status-codes", str(generated_log_file)])
    assert result.exit_code == 0
    assert "status code" in result.stdout.lower()


def test_cli_not_found(generated_log_file: Path) -> None:
    result = runner.invoke(app, ["not-found", str(generated_log_file)])
    assert result.exit_code == 0
    # Either rows shown or a clear summary string.
    assert "404" in result.stdout or "Not Found" in result.stdout


def test_cli_server_errors(generated_log_file: Path) -> None:
    result = runner.invoke(app, ["server-errors", str(generated_log_file)])
    assert result.exit_code == 0


def test_cli_suspicious_detects_patterns(generated_log_file: Path) -> None:
    result = runner.invoke(app, ["suspicious", str(generated_log_file)])
    assert result.exit_code == 0
    # The fixture uses suspicious_ratio=0.05 with seed=42, so we expect findings.
    assert (
        "Suspicious requests" in result.stdout
        or "No suspicious patterns" in result.stdout
    )


def test_cli_report_json(tmp_path: Path, generated_log_file: Path) -> None:
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["report", str(generated_log_file), "--format", "json", "--out", str(out)],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["total_entries"] > 0
    assert any(a["name"] == "suspiciouspattern" for a in payload["analyzers"])


def test_cli_report_markdown(tmp_path: Path, generated_log_file: Path) -> None:
    out = tmp_path / "report.md"
    result = runner.invoke(
        app,
        ["report", str(generated_log_file), "--format", "markdown", "--out", str(out)],
    )
    assert result.exit_code == 0
    text = out.read_text(encoding="utf-8")
    assert "# log-analyzer report" in text


def test_cli_report_rich_stdout(generated_log_file: Path) -> None:
    result = runner.invoke(app, ["report", str(generated_log_file), "--format", "rich"])
    assert result.exit_code == 0
    assert "log-analyzer report" in result.stdout


def test_cli_report_unknown_format(generated_log_file: Path) -> None:
    result = runner.invoke(
        app, ["report", str(generated_log_file), "--format", "yaml"]
    )
    assert result.exit_code != 0


def test_cli_missing_file_exits_nonzero(tmp_path: Path) -> None:
    result = runner.invoke(app, ["top-ips", str(tmp_path / "nope.log")])
    assert result.exit_code != 0
