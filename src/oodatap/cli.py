"""Typer + Rich command-line interface for OodaTap."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from oodatap import __version__
from oodatap.benchmark.evaluate import run_benchmark
from oodatap.benchmark.generator import generate_corpus
from oodatap.detectors.engine import OodaTapEngine
from oodatap.ingest.base import load_events
from oodatap.ingest.jsonl import write_jsonl
from oodatap.policy import load_policy
from oodatap.report.ecs import write_ecs_jsonl
from oodatap.report.html import write_html_report
from oodatap.schemas import VerdictLevel

app = typer.Typer(
    name="oodatap",
    help="Passive network detection for autonomous and hybrid human+agentic OODA loops.",
    no_args_is_help=True,
)
console = Console()

_VERDICT_STYLE: dict[VerdictLevel, str] = {
    VerdictLevel.HYBRID_HUMAN_AGENT_INTRUSION: "bold red",
    VerdictLevel.AGENTIC_OODA_INTRUSION: "bold bright_red",
    VerdictLevel.SUSPICIOUS_LOOP: "bold yellow",
    VerdictLevel.BENIGN_DEV_AGENT: "cyan",
    VerdictLevel.SCRIPTED_AUTOMATION: "magenta",
    VerdictLevel.BENIGN: "green",
}


@app.command()
def analyze(
    source: Path = typer.Argument(
        ..., exists=True, help="Input .pcap/.pcapng, Zeek log, Suricata EVE, or JSONL."
    ),
    fmt: str = typer.Option(
        "auto", "--format", "-f", help="Adapter: auto|pcap|pcapng|zeek|suricata|jsonl."
    ),
    policy: Path | None = typer.Option(None, "--policy", "-p", help="Custom YAML policy path."),
    ssl_log: Path | None = typer.Option(None, "--ssl-log", help="Optional Zeek ssl.log path."),
    html_out: Path | None = typer.Option(
        None, "--html", help="Write interactive HTML timeline report."
    ),
    ecs_out: Path | None = typer.Option(
        None, "--ecs-out", help="Write Elastic Common Schema JSONL alerts."
    ),
    include_benign_ecs: bool = typer.Option(
        False, "--include-benign-ecs", help="Include benign hosts in ECS output."
    ),
    fail_on_alert: bool = typer.Option(
        False, "--fail-on-alert", help="Exit with code 2 if any host triggers an intrusion alert."
    ),
) -> None:
    """Analyze network telemetry for encrypted agentic OODA loops and human<->agent handoffs."""
    cfg = load_policy(policy)
    adapter, events = load_events(source, fmt=fmt, policy=cfg, ssl_log=ssl_log)
    engine = OodaTapEngine(policy=cfg)
    report = engine.analyze_events(events, source_path=str(source), adapter=adapter)

    table = Table(title=f"OodaTap Analysis — {source.name} ({adapter}, {len(events)} events)")
    table.add_column("Host IP", style="bold")
    table.add_column("Verdict")
    table.add_column("Composite", justify="right")
    table.add_column("Sawtooth", justify="right")
    table.add_column("Coupler", justify="right")
    table.add_column("Kinematics", justify="right")
    table.add_column("Cycles", justify="right")
    table.add_column("Handoffs", justify="right")
    table.add_column("Lateral", justify="right")

    for hv in report.host_verdicts:
        style = _VERDICT_STYLE.get(hv.verdict, "white")
        table.add_row(
            hv.host_ip,
            f"[{style}]{hv.verdict.value}[/{style}]",
            f"{hv.scores.composite:.2f}",
            f"{hv.scores.sawtooth.score:.2f}",
            f"{hv.scores.coupler.score:.2f}",
            f"{hv.scores.kinematics.score:.2f}",
            str(hv.scores.coupler.coupled_cycle_count),
            str(len(hv.scores.kinematics.handoffs)),
            str(hv.sensitive_lateral_actions),
        )

    console.print(table)
    for hv in report.host_verdicts:
        console.print(f"  [dim]•[/dim] {hv.summary}")

    if html_out is not None:
        written_html = write_html_report(report, html_out)
        console.print(f"[green]Wrote HTML timeline report:[/green] {written_html}")

    if ecs_out is not None:
        written_ecs = write_ecs_jsonl(report, ecs_out, include_benign=include_benign_ecs)
        console.print(f"[green]Wrote ECS JSONL alerts:[/green] {written_ecs}")

    if fail_on_alert and report.alerting_hosts:
        raise typer.Exit(code=2)


@app.command()
def ingest(
    source: Path = typer.Argument(
        ..., exists=True, help="Raw .pcap/.pcapng, Zeek log, or Suricata EVE file."
    ),
    output: Path = typer.Option(..., "--out", "-o", help="Output normalized OodaTap JSONL path."),
    fmt: str = typer.Option(
        "auto", "--format", "-f", help="Adapter: auto|pcap|pcapng|zeek|suricata|jsonl."
    ),
    policy: Path | None = typer.Option(None, "--policy", "-p", help="Custom YAML policy path."),
    ssl_log: Path | None = typer.Option(None, "--ssl-log", help="Optional Zeek ssl.log path."),
) -> None:
    """Normalize raw network telemetry into OodaTap's canonical burst/action JSONL schema."""
    cfg = load_policy(policy)
    adapter, events = load_events(source, fmt=fmt, policy=cfg, ssl_log=ssl_log)
    out = write_jsonl(events, output)
    console.print(f"[green]Normalized {len(events)} events ({adapter}) -> {out}[/green]")


@app.command()
def benchmark(
    seeds_per_class: int = typer.Option(
        5, "--seeds", "-n", min=1, max=50, help="Traces per class."
    ),
    base_seed: int = typer.Option(100, "--base-seed", help="Base PRNG seed for reproducibility."),
    policy: Path | None = typer.Option(None, "--policy", "-p", help="Custom YAML policy path."),
) -> None:
    """Run the reproducible 5-class OodaTap detection benchmark."""
    cfg = load_policy(policy)
    res = run_benchmark(seeds_per_class=seeds_per_class, base_seed=base_seed, policy=cfg)

    summary = (
        f"Traces: [bold]{res.total_traces}[/bold]  |  "
        f"Precision: [bold green]{res.precision:.1%}[/bold green]  |  "
        f"Recall: [bold green]{res.recall:.1%}[/bold green]  |  "
        f"F1: [bold cyan]{res.f1_score:.1%}[/bold cyan]\n"
        f"Exact 5-Class Accuracy: [bold]{res.exact_verdict_accuracy:.1%}[/bold]  |  "
        f"Benign Dev-Agent FPR: [bold]{res.benign_dev_agent_fpr:.1%}[/bold]  |  "
        f"Handoff Recall: [bold]{res.handoff_recall:.1%}[/bold]"
    )
    console.print(Panel(summary, title="OodaTap Benchmark Summary", border_style="cyan"))

    table = Table(title="Per-Class Breakdown")
    table.add_column("Scenario Class", style="bold")
    table.add_column("Traces", justify="right")
    table.add_column("Alerts", justify="right")
    table.add_column("Exact Match", justify="right")
    table.add_column("Composite", justify="right")
    table.add_column("Sawtooth", justify="right")
    table.add_column("Coupler", justify="right")
    table.add_column("Kinematics", justify="right")

    for cls_name, stats in res.per_class_summary.items():
        table.add_row(
            cls_name,
            str(stats["count"]),
            str(stats["alerts"]),
            f"{stats['exact_matches']}/{stats['count']}",
            f"{stats['mean_composite']:.2f}",
            f"{stats['mean_sawtooth']:.2f}",
            f"{stats['mean_coupler']:.2f}",
            f"{stats['mean_kinematics']:.2f}",
        )
    console.print(table)


@app.command("generate-corpus")
def generate_corpus_cmd(
    output_dir: Path = typer.Option(Path("corpus"), "--out", "-o", help="Target directory."),
    seeds_per_class: int = typer.Option(2, "--seeds", "-n", min=1, max=25),
    no_pcap: bool = typer.Option(False, "--no-pcap", help="Skip writing binary .pcap files."),
) -> None:
    """Generate a labeled synthetic JSONL + binary .pcap corpus on disk."""
    scenarios = generate_corpus(
        output_dir=output_dir,
        seeds_per_class=seeds_per_class,
        write_pcaps=not no_pcap,
    )
    console.print(f"[green]Generated {len(scenarios)} labeled traces in {output_dir}[/green]")


@app.command()
def version() -> None:
    """Print the OodaTap version."""
    console.print(f"oodatap {__version__}")


if __name__ == "__main__":
    app()
