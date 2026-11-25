"""Synthetic trace corpus generator and reproducible benchmark evaluator."""

from oodatap.benchmark.evaluate import BenchmarkResult, ScenarioEvaluation, run_benchmark
from oodatap.benchmark.generator import (
    SCENARIO_CLASSES,
    GeneratedScenario,
    generate_corpus,
    generate_mixed_enterprise_events,
    generate_scenario,
)

__all__ = [
    "BenchmarkResult",
    "GeneratedScenario",
    "SCENARIO_CLASSES",
    "ScenarioEvaluation",
    "generate_corpus",
    "generate_mixed_enterprise_events",
    "generate_scenario",
    "run_benchmark",
]
