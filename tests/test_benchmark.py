"""Tests for the reproducible 5-class benchmark harness and corpus generator."""

from __future__ import annotations

import json
from pathlib import Path

from oodatap.benchmark.evaluate import run_benchmark
from oodatap.benchmark.generator import generate_corpus


def test_five_class_benchmark_achieves_strong_separation() -> None:
    result = run_benchmark(seeds_per_class=4, base_seed=200)

    assert result.total_traces == 20
    assert result.precision >= 0.90
    assert result.recall >= 0.90
    assert result.f1_score >= 0.90
    assert result.benign_dev_agent_fpr == 0.0
    assert result.handoff_recall >= 0.75


def test_generate_corpus_writes_manifest_jsonl_and_pcaps(tmp_path: Path) -> None:
    scenarios = generate_corpus(tmp_path / "corpus", seeds_per_class=1, write_pcaps=True)
    assert len(scenarios) == 5
    manifest = json.loads((tmp_path / "corpus" / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest) == 5
    for entry in manifest:
        assert (tmp_path / "corpus" / entry["jsonl"]).exists()
        assert (tmp_path / "corpus" / entry["pcap"]).exists()
