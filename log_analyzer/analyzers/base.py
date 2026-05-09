"""Base classes for analyzers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from rich.console import Console

from log_analyzer.parser import LogEntry


@dataclass
class AnalysisResult:
    """A small, JSON-serializable result of an analyzer run."""

    name: str
    title: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)


class BaseAnalyzer:
    """Abstract base class for analyzers.

    Concrete analyzers override :meth:`analyze` and :meth:`render`.
    The default :attr:`name` is the lowercased class name without the
    trailing ``Analyzer`` suffix.
    """

    title: str = "Analysis"

    @property
    def name(self) -> str:
        cls = type(self).__name__
        if cls.endswith("Analyzer"):
            cls = cls[: -len("Analyzer")]
        return cls.lower()

    def analyze(self, entries: Iterable[LogEntry]) -> AnalysisResult:  # pragma: no cover
        raise NotImplementedError

    def render(self, result: AnalysisResult, console: Console) -> None:  # pragma: no cover
        raise NotImplementedError
