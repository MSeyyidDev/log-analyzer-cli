"""Tests for log_analyzer.parser."""

from __future__ import annotations

from datetime import timezone
from pathlib import Path

import pytest

from log_analyzer.parser import LogEntry, LogParser


def test_parse_valid_line() -> None:
    line = (
        '127.0.0.1 - alice [10/Oct/2026:13:55:36 +0000] '
        '"GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
    )
    parser = LogParser()
    entry = parser.parse_line(line)

    assert isinstance(entry, LogEntry)
    assert entry.ip == "127.0.0.1"
    assert entry.user == "alice"
    assert entry.method == "GET"
    assert entry.path == "/index.html"
    assert entry.protocol == "HTTP/1.1"
    assert entry.status == 200
    assert entry.size == 2326
    assert entry.user_agent == "Mozilla/5.0"
    assert entry.timestamp.tzinfo is timezone.utc
    assert parser.parsed_count == 1
    assert parser.malformed_count == 0


def test_parse_dash_size_treated_as_zero() -> None:
    line = (
        '10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] '
        '"HEAD / HTTP/1.1" 304 - "-" "curl/8.5.0"'
    )
    entry = LogParser().parse_line(line)
    assert entry is not None
    assert entry.size == 0
    assert entry.status == 304


def test_parse_empty_line_returns_none() -> None:
    parser = LogParser()
    assert parser.parse_line("") is None
    assert parser.parse_line("\n") is None
    assert parser.malformed_count == 0  # empty lines are not counted as malformed


def test_parse_malformed_lines_counted() -> None:
    parser = LogParser()
    assert parser.parse_line("definitely not a log line") is None
    assert parser.parse_line('1.2.3.4 - - [bad-date] "GET / HTTP/1.1" 200 0 "-" "-"') is None
    assert parser.malformed_count == 2


def test_parse_request_with_query_string_exposes_helpers() -> None:
    line = (
        '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] '
        '"GET /search?q=hello&page=2 HTTP/1.1" 200 100 "-" "-"'
    )
    entry = LogParser().parse_line(line)
    assert entry is not None
    assert entry.path_only == "/search"
    assert entry.query_string == "q=hello&page=2"


def test_log_entry_classification_helpers() -> None:
    line = (
        '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] '
        '"GET / HTTP/1.1" 503 100 "-" "-"'
    )
    entry = LogParser().parse_line(line)
    assert entry is not None
    assert entry.is_error is True
    assert entry.is_server_error is True
    assert entry.is_client_error is False


def test_parse_file_skips_blank_and_malformed(tmp_path: Path) -> None:
    p = tmp_path / "x.log"
    p.write_text(
        "\n".join(
            [
                '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 0 "-" "-"',
                "",
                "garbage line",
                '1.2.3.4 - - [10/Oct/2026:13:55:37 +0000] "GET /a HTTP/1.1" 200 0 "-" "-"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    parser = LogParser()
    entries = list(parser.parse_file(p))
    assert len(entries) == 2
    assert parser.malformed_count == 1


def test_parser_reset() -> None:
    parser = LogParser()
    parser.parse_line("garbage")
    parser.parse_line(
        '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'
    )
    assert parser.parsed_count == 1
    assert parser.malformed_count == 1
    parser.reset()
    assert parser.parsed_count == 0
    assert parser.malformed_count == 0


@pytest.mark.parametrize(
    "status,client,server",
    [(200, False, False), (404, True, False), (500, False, True), (502, False, True)],
)
def test_status_buckets(status: int, client: bool, server: bool) -> None:
    line = (
        f'1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] '
        f'"GET / HTTP/1.1" {status} 0 "-" "-"'
    )
    entry = LogParser().parse_line(line)
    assert entry is not None
    assert entry.is_client_error is client
    assert entry.is_server_error is server
