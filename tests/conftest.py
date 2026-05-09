"""Shared pytest fixtures for log-analyzer tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from log_analyzer.generator import LogGenerator
from log_analyzer.parser import LogEntry, LogParser


SAMPLE_LINES: list[str] = [
    # 2 requests from one chatty IP
    '203.0.113.10 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"',
    '203.0.113.10 - - [10/Oct/2026:13:56:01 +0000] "GET /static/css/main.css HTTP/1.1" 200 14023 "-" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"',
    # Different IP, 404 path
    '198.51.100.42 - - [10/Oct/2026:14:00:11 +0000] "GET /missing-page HTTP/1.1" 404 312 "-" '
    '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"',
    # 5xx server error
    '198.51.100.42 - - [10/Oct/2026:14:00:30 +0000] "POST /api/v1/orders HTTP/1.1" 500 410 "-" '
    '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"',
    # Suspicious: admin probe
    '192.0.2.7 - - [10/Oct/2026:14:01:00 +0000] "GET /wp-login.php HTTP/1.1" 404 200 "-" '
    '"Mozilla/5.0 zgrab/0.x"',
    # Suspicious: .env config leak
    '192.0.2.7 - - [10/Oct/2026:14:01:30 +0000] "GET /.env HTTP/1.1" 404 198 "-" '
    '"sqlmap/1.7.11"',
    # Suspicious: SQL injection payload
    '192.0.2.7 - - [10/Oct/2026:14:02:00 +0000] "GET /api/v1/products?id=1\' OR \'1\'=\'1 HTTP/1.1" 400 240 "-" '
    '"sqlmap/1.7.11"',
    # Bot
    '66.249.66.1 - - [10/Oct/2026:14:03:00 +0000] "GET /robots.txt HTTP/1.1" 200 200 "-" '
    '"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"',
    # Brute force POST attempts
    *[
        f'192.0.2.99 - - [10/Oct/2026:14:0{i // 6}:{(i % 6) * 10:02d} +0000] '
        '"POST /login HTTP/1.1" 401 180 "-" "curl/8.5.0"'
        for i in range(12)
    ],
]


@pytest.fixture
def sample_lines() -> list[str]:
    """Return a small, hand-crafted list of NCSA Combined log lines."""
    return list(SAMPLE_LINES)


@pytest.fixture
def sample_entries(sample_lines: list[str]) -> list[LogEntry]:
    """Return :class:`LogEntry` objects for ``SAMPLE_LINES``."""
    parser = LogParser()
    return list(parser.parse_lines(sample_lines))


@pytest.fixture
def sample_log_file(tmp_path: Path, sample_lines: list[str]) -> Path:
    """Write ``SAMPLE_LINES`` to a temp file and return its path."""
    p = tmp_path / "sample.log"
    p.write_text("\n".join(sample_lines) + "\n", encoding="utf-8")
    return p


@pytest.fixture
def generated_log_file(tmp_path: Path) -> Path:
    """Generate a small deterministic synthetic log."""
    out = tmp_path / "generated.log"
    gen = LogGenerator(seed=42, suspicious_ratio=0.05)
    gen.generate(
        out,
        lines=500,
        days=2,
        end=datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc),
    )
    return out
