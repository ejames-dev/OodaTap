"""Main OodaTap host-level orchestration and verdict engine."""

from __future__ import annotations

import time
from collections import defaultdict

from oodatap.detectors.coupler import analyze_coupling
from oodatap.detectors.kinematics import analyze_kinematics
from oodatap.detectors.sawtooth import analyze_sawtooth
from oodatap.policy import PolicyConfig, load_policy
from oodatap.schemas import (
    ActionEvent,
    AnalysisReport,
    DetectorScores,
    DirectionClass,
    HostVerdict,
    TelemetryEvent,
    TlsBurstEvent,
    VerdictLevel,
)


class OodaTapEngine:
    """Runs the 3-signal OodaTap detection pipeline across normalized telemetry."""

    def __init__(self, policy: PolicyConfig | None = None) -> None:
        self.policy = policy or load_policy()

    def _summarize_hosts(
        self,
        events: list[TelemetryEvent],
    ) -> dict[str, dict[str, int]]:
        """Aggregate per-host telemetry counts in a single linear pass."""
        summary: dict[str, dict[str, int]] = {}
        for ev in events:
            bucket = summary.setdefault(
                ev.src_ip,
                {"tls_count": 0, "action_count": 0, "sensitive_count": 0, "dev_count": 0},
            )
            if isinstance(ev, TlsBurstEvent):
                bucket["tls_count"] += 1
            elif isinstance(ev, ActionEvent):
                bucket["action_count"] += 1
                if ev.is_sensitive_lateral:
                    bucket["sensitive_count"] += 1
                if ev.direction_class == DirectionClass.DEV_LOCAL:
                    bucket["dev_count"] += 1
        return summary

    def analyze_host(
        self,
        host_ip: str,
        tls_bursts: list[TlsBurstEvent],
        actions: list[ActionEvent],
    ) -> HostVerdict:
        """Evaluate a single source host across Sawtooth, Coupler, and Kinematics detectors."""
        classified_tls = [self.policy.classify_tls_burst(b) for b in tls_bursts]
        classified_actions = [self.policy.classify_action(a) for a in actions]

        sawtooth = analyze_sawtooth(classified_tls, policy=self.policy)
        coupler = analyze_coupling(classified_tls, classified_actions, policy=self.policy)
        kinematics = analyze_kinematics(classified_actions, policy=self.policy)

        weights = self.policy.scoring.weights
        composite = (
            weights.sawtooth * sawtooth.score
            + weights.coupler * coupler.score
            + weights.kinematics * kinematics.score
        )

        # Off-box LLM agent fallback: if no local TLS LLM stream exists, allow strong
        # kinematic + parallel fan-out + handoff evidence to elevate the host to suspicious/alert.
        if sawtooth.turn_count < self.policy.scoring.min_turns_for_sawtooth and (
            kinematics.score >= 0.70 and kinematics.scanner_regularity_score < 0.45
        ):
            composite = max(composite, 0.72 * kinematics.score)

        composite = round(min(1.0, max(0.0, composite)), 4)

        internal_actions = [
            a for a in classified_actions if a.direction_class == DirectionClass.EAST_WEST_INTERNAL
        ]
        dev_actions = [
            a for a in classified_actions if a.direction_class == DirectionClass.DEV_LOCAL
        ]
        sensitive_count = sum(1 for a in internal_actions if a.is_sensitive_lateral)
        unique_internal_targets = len({a.dst_ip for a in internal_actions})

        scores = DetectorScores(
            composite=composite,
            sawtooth=sawtooth,
            coupler=coupler,
            kinematics=kinematics,
        )

        # False-positive suppression for benign developer coding agents (Cursor, Claude Code, etc.).
        is_dev_only_loop = (
            sensitive_count == 0
            and len(internal_actions) == 0
            and len(dev_actions) >= 2
            and (sawtooth.score >= 0.40 or coupler.score >= 0.35)
        )
        is_approved_dev_host = (
            host_ip in self.policy.dev_allowlist.approved_dev_hosts and sensitive_count == 0
        )

        suppressed_dev = False
        if is_dev_only_loop or (
            is_approved_dev_host and composite >= self.policy.scoring.suspicious_threshold
        ):
            verdict = VerdictLevel.BENIGN_DEV_AGENT
            suppressed_dev = True
            confidence = round(max(sawtooth.score, coupler.score), 3)
            summary = (
                f"Detected agentic OODA loop on {host_ip} ({coupler.coupled_cycle_count} coupled "
                f"cycles), suppressed as benign dev agent (0 sensitive lateral actions; "
                f"{len(dev_actions)} allowlisted dev-local actions)."
            )
        elif (
            kinematics.scanner_regularity_score >= 0.65
            and sawtooth.score < 0.35
            and coupler.score < 0.25
        ):
            verdict = VerdictLevel.SCRIPTED_AUTOMATION
            confidence = round(kinematics.scanner_regularity_score, 3)
            summary = (
                f"High-frequency uniform probing on {host_ip} without LLM sawtooth or causal "
                f"coupling (scanner regularity={kinematics.scanner_regularity_score:.2f}); "
                "classified as classic scripted automation."
            )
        elif composite >= self.policy.scoring.alert_threshold and (
            sensitive_count > 0 or unique_internal_targets >= 2 or coupler.score >= 0.55
        ):
            if kinematics.handoffs:
                verdict = VerdictLevel.HYBRID_HUMAN_AGENT_INTRUSION
                summary = (
                    f"Hybrid human+agentic intrusion detected on {host_ip} "
                    f"(composite={composite:.2f}, {coupler.coupled_cycle_count} coupled OODA "
                    f"cycles, {len(kinematics.handoffs)} agent<->human handoff(s), "
                    f"{sensitive_count} sensitive lateral actions across "
                    f"{unique_internal_targets} internal host(s))."
                )
            else:
                verdict = VerdictLevel.AGENTIC_OODA_INTRUSION
                summary = (
                    f"Autonomous agentic OODA intrusion detected on {host_ip} "
                    f"(composite={composite:.2f}, sawtooth={sawtooth.score:.2f}, "
                    f"coupler={coupler.score:.2f}, {sensitive_count} sensitive lateral actions "
                    f"across {unique_internal_targets} internal host(s))."
                )
            confidence = round(min(0.99, 0.55 + 0.45 * composite), 3)
        elif composite >= self.policy.scoring.suspicious_threshold:
            verdict = VerdictLevel.SUSPICIOUS_LOOP
            confidence = round(composite, 3)
            summary = (
                f"Suspicious reasoning-loop signature on {host_ip} (composite={composite:.2f}, "
                f"sawtooth={sawtooth.score:.2f}, coupler={coupler.score:.2f}, "
                f"kinematics={kinematics.score:.2f})."
            )
        else:
            verdict = VerdictLevel.BENIGN
            confidence = round(1.0 - composite, 3)
            summary = (
                f"No malicious agentic OODA coupling detected on {host_ip} "
                f"(composite={composite:.2f})."
            )

        return HostVerdict(
            host_ip=host_ip,
            verdict=verdict,
            confidence=confidence,
            scores=scores,
            suppressed_as_dev_agent=suppressed_dev,
            sensitive_lateral_actions=sensitive_count,
            dev_allowlisted_actions=len(dev_actions),
            unique_internal_targets=unique_internal_targets,
            summary=summary,
            tls_bursts=sorted(classified_tls, key=lambda b: b.timestamp),
            actions=sorted(classified_actions, key=lambda a: a.timestamp),
        )

    def analyze_events(
        self,
        events: list[TelemetryEvent],
        source_path: str = "<memory>",
        adapter: str = "jsonl",
    ) -> AnalysisReport:
        """Analyze a list of normalized events across all observed source hosts."""
        host_stats = self._summarize_hosts(events)
        tls_by_host: dict[str, list[TlsBurstEvent]] = defaultdict(list)
        actions_by_host: dict[str, list[ActionEvent]] = defaultdict(list)

        for ev in events:
            if isinstance(ev, TlsBurstEvent):
                tls_by_host[ev.src_ip].append(ev)
            elif isinstance(ev, ActionEvent):
                actions_by_host[ev.src_ip].append(ev)

        all_hosts = sorted(set(tls_by_host) | set(actions_by_host))
        verdicts = [
            self.analyze_host(host, tls_by_host[host], actions_by_host[host]) for host in all_hosts
        ]
        verdicts.sort(key=lambda v: v.scores.composite, reverse=True)

        return AnalysisReport(
            source_path=source_path,
            adapter=adapter,
            analyzed_at_epoch=round(time.time(), 3),
            total_events=len(events),
            host_verdicts=verdicts,
            metadata={"host_event_counts": host_stats},
        )
