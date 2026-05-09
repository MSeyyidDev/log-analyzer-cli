"""log-analyzer-cli: generate and analyze NCSA Combined access logs.

A polished, object-oriented Python toolkit that produces realistic
synthetic web-server access logs and surfaces actionable security
signals from them through a Rich-powered command-line interface.
"""

from __future__ import annotations

from log_analyzer.parser import LogEntry, LogParser
from log_analyzer.generator import LogGenerator

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "LogEntry",
    "LogParser",
    "LogGenerator",
]
