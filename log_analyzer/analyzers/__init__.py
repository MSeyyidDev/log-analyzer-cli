"""Analyzer suite for parsed access-log entries.

Each analyzer is a small object with two methods:

* ``analyze(entries) -> AnalysisResult`` — pure computation
* ``render(result, console) -> None`` — pretty Rich output

This separation lets reports collect raw results before deciding on a
presentation format (Rich, Markdown, JSON).
"""

from __future__ import annotations

from log_analyzer.analyzers.base import AnalysisResult, BaseAnalyzer
from log_analyzer.analyzers.top_ips import TopIPAnalyzer
from log_analyzer.analyzers.status_codes import StatusCodeAnalyzer
from log_analyzer.analyzers.not_found import NotFoundAnalyzer
from log_analyzer.analyzers.server_errors import ServerErrorAnalyzer
from log_analyzer.analyzers.suspicious import SuspiciousPatternAnalyzer
from log_analyzer.analyzers.user_agents import UserAgentAnalyzer
from log_analyzer.analyzers.traffic_by_hour import TrafficByHourAnalyzer

__all__ = [
    "AnalysisResult",
    "BaseAnalyzer",
    "TopIPAnalyzer",
    "StatusCodeAnalyzer",
    "NotFoundAnalyzer",
    "ServerErrorAnalyzer",
    "SuspiciousPatternAnalyzer",
    "UserAgentAnalyzer",
    "TrafficByHourAnalyzer",
]
