"""NCSA Combined Log Format parser.

This module exposes :class:`LogEntry`, a typed dataclass representing one
access-log line, and :class:`LogParser`, a streaming parser that turns
raw lines into :class:`LogEntry` objects while quietly skipping
malformed input.

NCSA Combined format::

    %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"

Example::

    127.0.0.1 - alice [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LogEntry:
    """A single parsed NCSA Combined access-log entry."""

    ip: str
    identity: str
    user: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referer: str
    user_agent: str
    raw: str = field(default="", repr=False, compare=False)

    @property
    def is_error(self) -> bool:
        """True for 4xx and 5xx responses."""
        return self.status >= 400

    @property
    def is_server_error(self) -> bool:
        """True for 5xx responses."""
        return 500 <= self.status < 600

    @property
    def is_client_error(self) -> bool:
        """True for 4xx responses."""
        return 400 <= self.status < 500

    @property
    def query_string(self) -> str:
        """Return the query-string portion of the request path, if any."""
        return self.path.split("?", 1)[1] if "?" in self.path else ""

    @property
    def path_only(self) -> str:
        """Return the path portion of the request without the query string."""
        return self.path.split("?", 1)[0]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class LogParser:
    """Streaming parser for NCSA Combined Log Format.

    The parser is intentionally permissive: malformed lines are skipped
    and counted in :attr:`malformed_count` rather than raising.
    """

    # %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
    _LINE_RE = re.compile(
        r'^(?P<ip>\S+)\s+'
        r'(?P<identity>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<request>[^"]*)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<size>\S+)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"\s*$'
    )

    _REQUEST_RE = re.compile(r"^(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)$")

    _TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

    def __init__(self) -> None:
        self.parsed_count: int = 0
        self.malformed_count: int = 0

    # ----- public API ------------------------------------------------------

    def parse_line(self, line: str) -> LogEntry | None:
        """Parse a single log line; return ``None`` for malformed input."""
        line = line.rstrip("\r\n")
        if not line:
            return None

        match = self._LINE_RE.match(line)
        if match is None:
            self.malformed_count += 1
            return None

        request = match.group("request")
        req_match = self._REQUEST_RE.match(request)
        if req_match is None:
            method, path, protocol = "-", request or "-", "-"
        else:
            method = req_match.group("method")
            path = req_match.group("path")
            protocol = req_match.group("protocol")

        try:
            ts = datetime.strptime(match.group("time"), self._TIME_FORMAT)
        except ValueError:
            self.malformed_count += 1
            return None

        size_raw = match.group("size")
        size = 0 if size_raw == "-" else int(size_raw) if size_raw.isdigit() else 0

        try:
            status = int(match.group("status"))
        except ValueError:
            self.malformed_count += 1
            return None

        entry = LogEntry(
            ip=match.group("ip"),
            identity=match.group("identity"),
            user=match.group("user"),
            timestamp=ts.astimezone(timezone.utc),
            method=method,
            path=path,
            protocol=protocol,
            status=status,
            size=size,
            referer=match.group("referer"),
            user_agent=match.group("user_agent"),
            raw=line,
        )
        self.parsed_count += 1
        return entry

    def parse_lines(self, lines: Iterable[str]) -> Iterator[LogEntry]:
        """Yield :class:`LogEntry` objects from an iterable of raw lines."""
        for line in lines:
            entry = self.parse_line(line)
            if entry is not None:
                yield entry

    def parse_file(self, path: str | Path, encoding: str = "utf-8") -> Iterator[LogEntry]:
        """Yield :class:`LogEntry` objects from a log file."""
        p = Path(path)
        with p.open("r", encoding=encoding, errors="replace") as fh:
            yield from self.parse_lines(fh)

    def reset(self) -> None:
        """Reset internal counters."""
        self.parsed_count = 0
        self.malformed_count = 0
