"""CLI smoke and exit-code tests via Typer CliRunner."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from oodatap.benchmark.generator import generate_scenario
from oodatap.cli import app
from oodatap.ingest.pcap import write_pcap_from_events

runner = CliRunner()


def test_cli_version() -> None:
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "oodatap" in res.stdout


def test_cli_analyze_and_ingest_on_pcap(tmp_path: Path) -> None:
    sc = generate_scenario("hybrid_human_agent_intrusion", seed=303)
    pcap = write_pcap_from_events(sc.events, tmp_path / "case.pcap")
    html_out = tmp_path / "report.html"
    ecs_out = tmp_path / "alerts.jsonl"
    norm_out = tmp_path / "norm.jsonl"

    res_ingest = runner.invoke(app, ["ingest", str(pcap), "--out", str(norm_out)])
    assert res_ingest.exit_code == 0
    assert norm_out.exists()

    res_analyze = runner.invoke(
        app,
        [
            "analyze",
            str(pcap),
            "--html",
            str(html_out),
            "--ecs-out",
            str(ecs_out),
            "--fail-on-alert",
        ],
    )
    assert res_analyze.exit_code == 2
    assert html_out.exists()
    assert ecs_out.exists()


def test_cli_benchmark() -> None:
    res = runner.invoke(app, ["benchmark", "--seeds", "2"])
    assert res.exit_code == 0
    assert "OodaTap Benchmark Summary" in res.stdout
