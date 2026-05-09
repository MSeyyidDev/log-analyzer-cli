"""Tests for log_analyzer.generator."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from log_analyzer.generator import LogGenerator
from log_analyzer.parser import LogParser


def test_generator_produces_requested_line_count(tmp_path: Path) -> None:
    out = tmp_path / "x.log"
    stats = LogGenerator(seed=1).generate(out, lines=200, days=2)
    assert stats.total_lines == 200
    assert stats.output_path == out
    assert out.exists()
    assert sum(1 for _ in out.open(encoding="utf-8")) == 200


def test_generator_output_parses_cleanly(tmp_path: Path) -> None:
    out = tmp_path / "x.log"
    LogGenerator(seed=2).generate(out, lines=300, days=1)
    parser = LogParser()
    entries = list(parser.parse_file(out))
    assert len(entries) == 300
    assert parser.malformed_count == 0


def test_generator_deterministic_with_seed(tmp_path: Path) -> None:
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    end = datetime(2026, 5, 1, tzinfo=timezone.utc)
    LogGenerator(seed=99).generate(a, lines=100, days=2, end=end)
    LogGenerator(seed=99).generate(b, lines=100, days=2, end=end)
    assert a.read_text(encoding="utf-8") == b.read_text(encoding="utf-8")


def test_generator_embeds_suspicious_patterns(tmp_path: Path) -> None:
    out = tmp_path / "x.log"
    stats = LogGenerator(seed=3, suspicious_ratio=0.2).generate(
        out, lines=1000, days=2
    )
    assert stats.suspicious_lines > 50  # ~200 expected at 20%
    text = out.read_text(encoding="utf-8")
    # At least one of the suspicious markers should show up.
    suspicious_markers = ("/wp-login.php", "/.env", "sqlmap", "/admin", "/.git/config")
    assert any(marker in text for marker in suspicious_markers)


def test_generator_timestamps_within_window(tmp_path: Path) -> None:
    out = tmp_path / "x.log"
    end = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    LogGenerator(seed=4).generate(out, lines=200, days=3, end=end)
    parser = LogParser()
    entries = list(parser.parse_file(out))
    start = end - timedelta(days=3)
    assert entries
    for entry in entries:
        assert start - timedelta(seconds=1) <= entry.timestamp <= end + timedelta(seconds=1)


def test_generator_unique_ips_reasonable(tmp_path: Path) -> None:
    out = tmp_path / "x.log"
    stats = LogGenerator(seed=5).generate(out, lines=2000, days=1)
    # We expect a long-tail distribution: many requests, far fewer IPs.
    assert stats.unique_ips < stats.total_lines
    assert stats.unique_ips >= 20


def test_generator_rejects_zero_lines(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        LogGenerator().generate(tmp_path / "x.log", lines=0)


def test_generator_rejects_invalid_ratio() -> None:
    with pytest.raises(ValueError):
        LogGenerator(suspicious_ratio=1.5)


def test_generator_rejects_invalid_days(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        LogGenerator().generate(tmp_path / "x.log", lines=10, days=0)
