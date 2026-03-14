"""Command-line interface for Dev Trust Scanner."""

import logging
from pathlib import Path

import click

from .core.models import ScanResult
from .core.orchestrator import Orchestrator
from .core.reporting import JsonReporter, SarifReporter, TextReporter
from .core.webhook import post_sarif

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _filter_by_severity(result: ScanResult, min_severity: str) -> ScanResult:
    """Return a new ScanResult with findings filtered to min_severity and above."""
    threshold = _SEVERITY_RANK[min_severity.lower()]
    filtered = [
        f for f in result.findings
        if _SEVERITY_RANK[f.severity.value] >= threshold
    ]
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(filtered)}
    for f in filtered:
        summary[f.severity.value] += 1
    return ScanResult(
        target_path=result.target_path,
        findings=filtered,
        plugins_run=result.plugins_run,
        scan_duration_seconds=result.scan_duration_seconds,
        summary=summary,
    )


@click.command()
@click.argument(
    "target",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=".",
)
@click.option(
    "--plugin",
    "-p",
    multiple=True,
    help="Run specific plugin(s). Can be specified multiple times.",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "--webhook-url",
    default=None,
    help="POST SARIF results to this URL after scanning.",
)
@click.option(
    "--tenant-id",
    default=None,
    help="Tenant identifier injected into SARIF properties and webhook headers.",
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
    default="low",
    help="Minimum severity to report (default: low = report all findings)",
)
@click.option(
    "--verbose", "-v", count=True, help="Increase verbosity (-v for INFO, -vv for DEBUG)"
)
@click.option(
    "--list-plugins", is_flag=True, help="List available plugins and exit"
)
def main(target, plugin, format, output, webhook_url, tenant_id, severity, verbose, list_plugins):
    """
    Dev Trust Scanner - Detect malicious patterns in developer tooling.

    Scans TARGET directory for suspicious patterns in npm scripts,
    VS Code tasks, and other developer configurations.
    """
    # Setup logging
    if verbose == 1:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    elif verbose >= 2:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    orchestrator = Orchestrator()

    # List plugins and exit
    if list_plugins:
        click.echo("Available plugins:")
        for plugin_meta in orchestrator.list_plugins():
            click.echo(f"  - {plugin_meta['name']}: {plugin_meta['description']}")
        return

    # Run scan
    plugin_filter = list(plugin) if plugin else None
    result = orchestrator.scan(target, plugin_filter=plugin_filter)

    # Apply severity filter
    if severity.lower() != "low":
        result = _filter_by_severity(result, severity)

    # Generate report
    if format == "text":
        reporter = TextReporter()
        if output:
            from rich.console import Console
            file_console = Console(file=output.open("w"), highlight=False)
            reporter = TextReporter(console=file_console)
            reporter.report(result)
        else:
            reporter.report(result)

    elif format == "json":
        reporter = JsonReporter()
        report_output = reporter.report(result)
        if output:
            output.write_text(report_output, encoding="utf-8")
        else:
            click.echo(report_output)

    elif format == "sarif":
        reporter = SarifReporter()
        report_output = reporter.report(result, tenant_id=tenant_id)
        if output:
            output.write_text(report_output, encoding="utf-8")
        else:
            click.echo(report_output)

        # Webhook delivery (fire-and-forget, after normal output)
        if webhook_url:
            import json as _json
            post_sarif(
                url=webhook_url,
                sarif_data=_json.loads(report_output),
                tenant_id=tenant_id,
            )

    # Exit code based on findings
    if result.summary["critical"] > 0 or result.summary["high"] > 0:
        raise SystemExit(1)
    elif result.summary["medium"] > 0 or result.summary["low"] > 0:
        raise SystemExit(1)
    else:
        raise SystemExit(0)


if __name__ == "__main__":
    main()
