"""Reproducible benchmark harness: precision, recall, F1, dev-FPR, and handoff accuracy."""

from __future__ import annotations

from pydantic import BaseModel, Field

from oodatap.benchmark.generator import SCENARIO_CLASSES, ScenarioClass, generate_scenario
from oodatap.detectors.engine import OodaTapEngine
from oodatap.policy import PolicyConfig
from oodatap.schemas import VerdictLevel


class ScenarioEvaluation(BaseModel):
    """Result of running OodaTap on a single labeled benchmark scenario."""

    name: str
    scenario_class: str
    expected_alert: bool
    predicted_alert: bool
    expected_verdict: VerdictLevel
    predicted_verdict: VerdictLevel
    expected_handoff: bool
    detected_handoffs: int
    composite_score: float
    sawtooth_score: float
    coupler_score: float
    kinematics_score: float


class BenchmarkResult(BaseModel):
    """Aggregate benchmark metrics across all evaluated traces."""

    total_traces: int
    seeds_per_class: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    exact_verdict_accuracy: float
    benign_dev_agent_fpr: float
    handoff_recall: float
    per_class_summary: dict[str, dict[str, float | int]] = Field(default_factory=dict)
    evaluations: list[ScenarioEvaluation] = Field(default_factory=list)


def run_benchmark(
    seeds_per_class: int = 5,
    base_seed: int = 100,
    policy: PolicyConfig | None = None,
) -> BenchmarkResult:
    """Run OodaTap across all 5 scenario classes and return quantitative metrics."""
    engine = OodaTapEngine(policy=policy)
    alert_verdicts = {
        VerdictLevel.AGENTIC_OODA_INTRUSION,
        VerdictLevel.HYBRID_HUMAN_AGENT_INTRUSION,
    }

    evaluations: list[ScenarioEvaluation] = []
    tp = fp = tn = fn = 0
    exact_matches = 0

    for cls_idx, scenario_class in enumerate(SCENARIO_CLASSES):
        for offset in range(seeds_per_class):
            seed = base_seed + cls_idx * 100 + offset
            sc = generate_scenario(scenario_class, seed=seed, policy=engine.policy)
            report = engine.analyze_events(sc.events, source_path=sc.name, adapter="synthetic")
            hv = next(
                (v for v in report.host_verdicts if v.host_ip == sc.primary_host),
                report.host_verdicts[0],
            )
            predicted_alert = hv.verdict in alert_verdicts
            if sc.expected_alert and predicted_alert:
                tp += 1
            elif not sc.expected_alert and predicted_alert:
                fp += 1
            elif not sc.expected_alert and not predicted_alert:
                tn += 1
            else:
                fn += 1

            if hv.verdict == sc.expected_verdict:
                exact_matches += 1

            evaluations.append(
                ScenarioEvaluation(
                    name=sc.name,
                    scenario_class=sc.scenario_class,
                    expected_alert=sc.expected_alert,
                    predicted_alert=predicted_alert,
                    expected_verdict=sc.expected_verdict,
                    predicted_verdict=hv.verdict,
                    expected_handoff=sc.expected_handoff,
                    detected_handoffs=len(hv.scores.kinematics.handoffs),
                    composite_score=hv.scores.composite,
                    sawtooth_score=hv.scores.sawtooth.score,
                    coupler_score=hv.scores.coupler.score,
                    kinematics_score=hv.scores.kinematics.score,
                )
            )

    total = len(evaluations)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    exact_acc = exact_matches / total if total > 0 else 0.0

    dev_evals = [e for e in evaluations if e.scenario_class == "benign_dev_agent"]
    dev_fpr = sum(1 for e in dev_evals if e.predicted_alert) / len(dev_evals) if dev_evals else 0.0

    handoff_evals = [e for e in evaluations if e.expected_handoff]
    handoff_recall = (
        sum(1 for e in handoff_evals if e.detected_handoffs > 0) / len(handoff_evals)
        if handoff_evals
        else 1.0
    )

    per_class: dict[str, dict[str, float | int]] = {}
    for cls in SCENARIO_CLASSES:
        cls_name: ScenarioClass = cls
        subset = [e for e in evaluations if e.scenario_class == cls_name]
        if not subset:
            continue
        per_class[cls_name] = {
            "count": len(subset),
            "alerts": sum(1 for e in subset if e.predicted_alert),
            "exact_matches": sum(1 for e in subset if e.predicted_verdict == e.expected_verdict),
            "mean_composite": round(sum(e.composite_score for e in subset) / len(subset), 3),
            "mean_sawtooth": round(sum(e.sawtooth_score for e in subset) / len(subset), 3),
            "mean_coupler": round(sum(e.coupler_score for e in subset) / len(subset), 3),
            "mean_kinematics": round(sum(e.kinematics_score for e in subset) / len(subset), 3),
        }

    return BenchmarkResult(
        total_traces=total,
        seeds_per_class=seeds_per_class,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        exact_verdict_accuracy=round(exact_acc, 4),
        benign_dev_agent_fpr=round(dev_fpr, 4),
        handoff_recall=round(handoff_recall, 4),
        per_class_summary=per_class,
        evaluations=evaluations,
    )
