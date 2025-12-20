"""CLI for the AI-Enhanced SIEM."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ai_siem.models import SIEMConfig, create_config
from ai_siem.pipeline import SIEMPipeline, create_pipeline

app = typer.Typer(
    name="ai-siem",
    help="AI-Enhanced SIEM with Wazuh, msgspec, Redis, and Gemini AI",
    add_completion=False,
)
console = Console()


def get_config(api_key: str | None = None, mock: bool = False) -> SIEMConfig:
    """Get configuration with optional overrides."""
    kwargs = {"enable_mock_mode": mock}
    if api_key:
        kwargs["gemini_api_key"] = api_key
    return create_config(**kwargs)


@app.command()
def process(
    file_path: str = typer.Argument(None, help="Path to Wazuh alerts file"),
    limit: int = typer.Option(100, "--limit", "-l", help="Maximum alerts to process"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="GEMINI_API_KEY"),
    mock: bool = typer.Option(False, "--mock", help="Use mock mode"),
) -> None:
    """Process a Wazuh alerts file."""
    config = get_config(api_key, mock)
    if limit:
        config.batch_size = limit

    pipeline = create_pipeline(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Processing alerts...", total=None)

        try:
            batch = pipeline.process_file(file_path)

            console.print()
            console.print(Panel(f"[green]Processed {batch.total_count} alerts[/green]"))

            # Show summary table
            table = Table(title="Processing Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Total Alerts", str(batch.total_count))
            table.add_row("Enriched", str(batch.enriched_count))
            table.add_row("Errors", str(batch.error_count))
            table.add_row("Deduplicated", str(batch.total_count - len(batch.alerts)))

            console.print(table)

            # Show sample alerts
            if batch.alerts:
                console.print("\n[cyan]Recent Enriched Alerts:[/cyan]")
                for alert in batch.alerts[:5]:
                    severity_color = {
                        "critical": "red",
                        "high": "yellow",
                        "medium": "orange3",
                        "low": "green",
                    }.get(alert.severity.value, "white")

                    console.print(
                        f"  [{severity_color}]{alert.severity.value.upper()}[/{severity_color}] "
                        f"{alert.original_description[:60]}..."
                    )
                    if alert.mitre_mappings:
                        techniques = ", ".join(m.technique_id for m in alert.mitre_mappings)
                        console.print(f"    MITRE: {techniques}")

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
        finally:
            pipeline.cleanup()


@app.command()
def recent(
    limit: int = typer.Option(20, "--limit", "-l", help="Number of alerts"),
    severity: str = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    mock: bool = typer.Option(False, "--mock", help="Use mock mode"),
) -> None:
    """Show recent enriched alerts."""
    config = get_config(mock=mock)
    pipeline = create_pipeline(config)

    try:
        alerts = pipeline.get_recent_alerts(limit, severity)

        if not alerts:
            console.print("[yellow]No alerts found[/yellow]")
            return

        table = Table(title=f"Recent Alerts ({len(alerts)})")
        table.add_column("ID", style="dim", width=20)
        table.add_column("Severity", width=10)
        table.add_column("Description", width=40)
        table.add_column("Risk", width=6)
        table.add_column("MITRE", width=15)

        for alert in alerts:
            severity_color = {
                "critical": "red",
                "high": "yellow",
                "medium": "orange3",
                "low": "green",
            }.get(alert.severity.value, "white")

            techniques = ", ".join(m.technique_id for m in alert.mitre_mappings[:2])

            table.add_row(
                alert.alert_id[:20],
                f"[{severity_color}]{alert.severity.value}[/{severity_color}]",
                alert.original_description[:40] + "...",
                f"{alert.risk_score:.0f}",
                techniques or "-",
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    finally:
        pipeline.cleanup()


@app.command()
def analyze(
    alert_id: str = typer.Argument(..., help="Alert ID to analyze"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="GEMINI_API_KEY"),
    mock: bool = typer.Option(False, "--mock", help="Use mock mode"),
) -> None:
    """Perform deep analysis on an alert."""
    config = get_config(api_key, mock)
    pipeline = create_pipeline(config)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Analyzing threat...", total=None)
            analysis = pipeline.analyze_alert(alert_id)

        if "error" in analysis:
            console.print(f"[red]Error: {analysis['error']}[/red]")
            raise typer.Exit(1)

        console.print()
        console.print(Panel("[cyan]Threat Analysis[/cyan]"))

        table = Table()
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        for key, value in analysis.items():
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            table.add_row(key.replace("_", " ").title(), str(value))

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    finally:
        pipeline.cleanup()


@app.command()
def stats(
    mock: bool = typer.Option(False, "--mock", help="Use mock mode"),
) -> None:
    """Show SIEM statistics."""
    config = get_config(mock=mock)
    pipeline = create_pipeline(config)

    try:
        stats = pipeline.get_stats()
        cache_stats = pipeline.cache.get_stats()

        console.print(Panel("[cyan]SIEM Statistics[/cyan]"))

        # Processing stats
        table = Table(title="Processing Stats")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Total Alerts", str(stats.total_alerts))
        table.add_row("Avg Risk Score", f"{stats.avg_risk_score:.1f}")
        table.add_row("Processing Time", f"{stats.processing_time_ms:.1f}ms")

        console.print(table)

        # Severity breakdown
        if stats.alerts_by_severity:
            sev_table = Table(title="Alerts by Severity")
            sev_table.add_column("Severity", style="cyan")
            sev_table.add_column("Count", style="green")

            for sev, count in stats.alerts_by_severity.items():
                sev_table.add_row(sev, str(count))

            console.print(sev_table)

        # Cache stats
        cache_table = Table(title="Cache Stats")
        cache_table.add_column("Metric", style="cyan")
        cache_table.add_column("Value", style="green")

        for key, value in cache_stats.items():
            cache_table.add_row(key.replace("_", " ").title(), str(value))

        console.print(cache_table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    finally:
        pipeline.cleanup()


@app.command()
def demo() -> None:
    """Run a demo in mock mode."""
    console.print(Panel("[cyan]Running demo in mock mode...[/cyan]"))

    config = get_config(mock=True)
    pipeline = create_pipeline(config)

    try:
        batch = pipeline.process_file()

        console.print(f"\n[green]Processed {batch.total_count} mock alerts[/green]")

        for alert in batch.alerts:
            console.print(f"\n[cyan]Alert: {alert.alert_id}[/cyan]")
            console.print(f"  Description: {alert.original_description}")
            console.print(f"  Severity: {alert.severity.value}")
            console.print(f"  Risk Score: {alert.risk_score}")
            console.print(f"  AI Summary: {alert.ai_summary}")

            if alert.mitre_mappings:
                console.print("  MITRE Mappings:")
                for m in alert.mitre_mappings:
                    console.print(f"    - {m.tactic} ({m.tactic_id}): {m.technique}")

            if alert.suggested_rules:
                console.print("  Suggested Rules:")
                for r in alert.suggested_rules:
                    console.print(f"    - {r.action} {r.protocol} port {r.port}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    finally:
        pipeline.cleanup()


@app.command()
def clear() -> None:
    """Clear the alert cache."""
    config = get_config(mock=True)
    pipeline = create_pipeline(config)

    try:
        if pipeline.clear_cache():
            console.print("[green]Cache cleared successfully[/green]")
        else:
            console.print("[red]Failed to clear cache[/red]")
    finally:
        pipeline.cleanup()


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
