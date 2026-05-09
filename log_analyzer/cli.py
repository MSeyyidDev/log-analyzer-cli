"""Typer-based command-line interface for log-analyzer.

Run ``log-analyzer --help`` to see all commands.

Examples
--------
::

    log-analyzer generate --out access.log --lines 100000 --days 7
    log-analyzer top-ips access.log --limit 20
    log-analyzer suspicious access.log
    log-analyzer report access.log --format markdown --out report.md
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from log_analyzer import __version__
from log_analyzer.analyzers import (
    NotFoundAnalyzer,
    ServerErrorAnalyzer,
    StatusCodeAnalyzer,
    SuspiciousPatternAnalyzer,
    TopIPAnalyzer,
)
from log_analyzer.generator import LogGenerator
from log_analyzer.parser import LogParser
from log_analyzer.reports import ReportBuilder, write_report


app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help=(
        "[bold cyan]log-analyzer[/bold cyan] — generate and analyze NCSA "
        "Combined access logs.\n\nGenerate realistic synthetic traffic, then "
        "explore it through focused subcommands or a full report."
    ),
)

console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"log-analyzer {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the installed version and exit.",
    ),
) -> None:
    """log-analyzer top-level entry point."""
    # The callback exists so ``--version`` works as a global flag.
    return None


def _load_entries(log_file: Path) -> tuple[list, int]:
    """Parse ``log_file`` with progress feedback. Returns ``(entries, malformed)``."""
    if not log_file.exists():
        console.print(f"[red]Log file not found:[/red] {log_file}")
        raise typer.Exit(code=2)

    parser = LogParser()
    entries: list = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task(f"Parsing {log_file.name}", total=None)
        for entry in parser.parse_file(log_file):
            entries.append(entry)
            if len(entries) % 5000 == 0:
                progress.update(task, description=f"Parsed {len(entries):,} entries")
    return entries, parser.malformed_count


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command("generate", help="Generate a synthetic NCSA Combined access-log file.")
def generate_cmd(
    out: Path = typer.Option(
        Path("access.log"),
        "--out",
        "-o",
        help="Destination log file (will be overwritten).",
    ),
    lines: int = typer.Option(
        10_000, "--lines", "-n", min=1, help="Number of lines to generate."
    ),
    days: int = typer.Option(
        7, "--days", "-d", min=1, help="Time window the entries are spread over."
    ),
    suspicious_ratio: float = typer.Option(
        0.005,
        "--suspicious-ratio",
        min=0.0,
        max=1.0,
        help="Approximate fraction of lines that contain suspicious patterns.",
    ),
    seed: Optional[int] = typer.Option(
        None, "--seed", help="Seed for fully deterministic output."
    ),
) -> None:
    """Generate ``--lines`` realistic NCSA Combined log entries.

    Example:

        log-analyzer generate --out access.log --lines 100000 --days 7
    """
    generator = LogGenerator(seed=seed, suspicious_ratio=suspicious_ratio)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task(f"Generating {lines:,} lines into {out}", total=None)
        stats = generator.generate(out, lines=lines, days=days)

    panel = Panel.fit(
        (
            f"[bold]File:[/bold] {stats.output_path}\n"
            f"[bold]Lines:[/bold] {stats.total_lines:,}\n"
            f"[bold]Suspicious:[/bold] {stats.suspicious_lines:,} "
            f"({100.0 * stats.suspicious_lines / max(1, stats.total_lines):.2f}%)\n"
            f"[bold]Unique IPs:[/bold] {stats.unique_ips:,}\n"
            f"[bold]Window:[/bold] {days} day(s)"
        ),
        title="[bold green]Generation complete[/bold green]",
        border_style="green",
    )
    console.print(panel)


@app.command("parse", help="Show the first/last N parsed entries as a table.")
def parse_cmd(
    log_file: Path = typer.Argument(..., help="Path to the access.log file."),
    head: int = typer.Option(5, "--head", min=0, help="Show this many leading entries."),
    tail: int = typer.Option(5, "--tail", min=0, help="Show this many trailing entries."),
) -> None:
    """Parse ``log_file`` and print a peek of the entries.

    Example:

        log-analyzer parse access.log --head 3 --tail 3
    """
    entries, malformed = _load_entries(log_file)
    if not entries:
        console.print("[yellow]No entries parsed.[/yellow]")
        return

    table = Table(
        title=f"{log_file.name} - {len(entries):,} entries (malformed: {malformed:,})",
        title_style="bold cyan",
        header_style="bold magenta",
        show_lines=False,
    )
    table.add_column("Time", style="cyan", no_wrap=True)
    table.add_column("IP", style="green")
    table.add_column("Method", style="bold")
    table.add_column("Path", style="yellow", overflow="fold")
    table.add_column("Status", justify="right")
    table.add_column("Size", justify="right", style="dim")

    selected: list = []
    if head:
        selected.extend(entries[:head])
    if tail and len(entries) > head:
        selected.extend(entries[-tail:])

    for entry in selected:
        status_style = (
            "red" if entry.is_server_error else "yellow" if entry.is_client_error else "green"
        )
        table.add_row(
            entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            entry.ip,
            entry.method,
            entry.path,
            f"[{status_style}]{entry.status}[/{status_style}]",
            f"{entry.size:,}",
        )
    console.print(table)


@app.command("top-ips", help="Show the IP addresses with the most requests.")
def top_ips_cmd(
    log_file: Path = typer.Argument(..., help="Path to the access.log file."),
    limit: int = typer.Option(15, "--limit", "-n", min=1, help="Number of rows."),
) -> None:
    """Show the loudest source IPs.

    Example:

        log-analyzer top-ips access.log --limit 20
    """
    entries, _ = _load_entries(log_file)
    analyzer = TopIPAnalyzer(limit=limit)
    analyzer.render(analyzer.analyze(entries), console)


@app.command("status-codes", help="Show the HTTP status-code distribution.")
def status_codes_cmd(
    log_file: Path = typer.Argument(..., help="Path to the access.log file."),
) -> None:
    """Aggregate HTTP status codes and class buckets."""
    entries, _ = _load_entries(log_file)
    analyzer = StatusCodeAnalyzer()
    analyzer.render(analyzer.analyze(entries), console)


@app.command("not-found", help="Show the most-requested 404 paths.")
def not_found_cmd(
    log_file: Path = typer.Argument(..., help="Path to the access.log file."),
    limit: int = typer.Option(15, "--limit", "-n", min=1, help="Number of rows."),
) -> None:
    """Surface frequently-requested missing paths."""
    entries, _ = _load_entries(log_file)
    analyzer = NotFoundAnalyzer(limit=limit)
    analyzer.render(analyzer.analyze(entries), console)


@app.command("server-errors", help="Show server-error (5xx) hot spots.")
def server_errors_cmd(
    log_file: Path = typer.Argument(..., help="Path to the access.log file."),
    limit: int = typer.Option(15, "--limit", "-n", min=1, help="Number of rows."),
) -> None:
    """Group 5xx responses by path and status code."""
    entries, _ = _load_entries(log_file)
    analyzer = ServerErrorAnalyzer(limit=limit)
    analyzer.render(analyzer.analyze(entries), console)


@app.command("suspicious", help="Detect suspicious requests grouped by category.")
def suspicious_cmd(
    log_file: Path = typer.Argument(..., help="Path to the access.log file."),
    brute_force_threshold: int = typer.Option(
        10,
        "--brute-force-threshold",
        min=2,
        help="Minimum POST /login attempts per IP to flag brute-force.",
    ),
) -> None:
    """Detect admin probing, SQLi/XSS payloads, dirbusting, brute force, etc.

    Example:

        log-analyzer suspicious access.log --brute-force-threshold 5
    """
    entries, _ = _load_entries(log_file)
    analyzer = SuspiciousPatternAnalyzer(brute_force_threshold=brute_force_threshold)
    analyzer.render(analyzer.analyze(entries), console)


@app.command("report", help="Run all analyzers and emit a combined report.")
def report_cmd(
    log_file: Path = typer.Argument(..., help="Path to the access.log file."),
    format: str = typer.Option(
        "rich",
        "--format",
        "-f",
        case_sensitive=False,
        help="Output format: rich, markdown, or json.",
    ),
    out: Optional[Path] = typer.Option(
        None, "--out", "-o", help="Optional output file (otherwise printed to stdout)."
    ),
) -> None:
    """Run the full analyzer suite.

    Example:

        log-analyzer report access.log --format markdown --out report.md
    """
    fmt = format.lower()
    if fmt not in ("rich", "markdown", "json"):
        console.print(f"[red]Unknown format:[/red] {format}")
        raise typer.Exit(code=2)

    entries, malformed = _load_entries(log_file)
    builder = ReportBuilder()
    report = builder.build(entries, source=str(log_file), malformed=malformed)
    write_report(report, builder, fmt, out, console)


if __name__ == "__main__":  # pragma: no cover
    app()
