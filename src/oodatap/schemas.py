"""Strict Pydantic v2 schemas for normalized OodaTap telemetry, detections, and alerts."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class DirectionClass(StrEnum):
    """Semantic network classification assigned by policy."""

    EAST_WEST_INTERNAL = "east_west_internal"
    DEV_LOCAL = "dev_local"
    EXTERNAL_BENIGN = "external_benign"
    REMOTE_INBOUND = "remote_inbound"


class RegimeType(StrEnum):
    """Kinematic session regime inferred from timing and fan-out signatures."""

    AUTONOMOUS_AGENT = "autonomous_agent"
    HUMAN_OPERATOR = "human_operator"
    SCRIPTED_SCANNER = "scripted_scanner"
    IDLE_OR_MIXED = "idle_or_mixed"


class VerdictLevel(StrEnum):
    """Final per-host triage verdict."""

    AGENTIC_OODA_INTRUSION = "agentic_ooda_intrusion"
    HYBRID_HUMAN_AGENT_INTRUSION = "hybrid_human_agent_intrusion"
    SUSPICIOUS_LOOP = "suspicious_loop"
    BENIGN_DEV_AGENT = "benign_dev_agent"
    SCRIPTED_AUTOMATION = "scripted_automation"
    BENIGN = "benign"


class TlsBurstEvent(BaseModel):
    """A single encrypted North-South request/response turn (e.g. HTTPS/TLS LLM API turn)."""

    kind: Literal["tls_burst"] = "tls_burst"
    timestamp: float = Field(description="Epoch seconds when client uplink burst begins.")
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 443
    sni: str | None = Field(default=None, description="TLS ClientHello SNI if observed.")
    flow_id: str = Field(default="", description="Stable flow identifier.")
    uplink_bytes: int = Field(ge=0, description="Total client->server TLS AppData bytes.")
    downlink_bytes: int = Field(ge=0, description="Total server->client TLS AppData bytes.")
    uplink_end_ts: float = Field(description="Epoch seconds when client uplink burst finishes.")
    downlink_start_ts: float = Field(description="Epoch seconds when first server reply arrives.")
    downlink_end_ts: float = Field(description="Epoch seconds when server downlink burst ends.")
    downlink_record_count: int = Field(
        default=1,
        ge=1,
        description="Number of TLS Application Data records received during downlink.",
    )
    is_llm_endpoint: bool = Field(
        default=False,
        description="Whether policy matched this destination as a known LLM endpoint.",
    )

    @property
    def ttft_seconds(self) -> float:
        """Estimated time-to-first-token (server think gap before first downlink record)."""
        return max(0.0, self.downlink_start_ts - self.uplink_end_ts)

    @property
    def decode_duration_seconds(self) -> float:
        """Duration of server downlink streaming/response."""
        return max(0.0, self.downlink_end_ts - self.downlink_start_ts)


class ActionEvent(BaseModel):
    """An East-West internal network action, lateral probe, or remote session command."""

    kind: Literal["action"] = "action"
    timestamp: float = Field(description="Epoch seconds when action/request begins.")
    end_ts: float = Field(description="Epoch seconds when response completes.")
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = Field(default="tcp", description="Application or transport label.")
    bytes_out: int = Field(default=0, ge=0, description="Bytes sent by the actor host.")
    bytes_in: int = Field(default=0, ge=0, description="Bytes returned by target host.")
    direction_class: DirectionClass = DirectionClass.EAST_WEST_INTERNAL
    is_sensitive_lateral: bool = False


TelemetryEvent = TlsBurstEvent | ActionEvent


class SawtoothEvidence(BaseModel):
    """Explainable metrics produced by the Context-Growth Sawtooth detector."""

    score: float = Field(ge=0.0, le=1.0)
    turn_count: int = 0
    kendall_tau: float = 0.0
    monotonic_step_ratio: float = 0.0
    max_growth_ratio: float = 1.0
    compaction_cliffs: list[float] = Field(default_factory=list)
    sse_stream_ratio: float = 0.0
    matched_endpoints: list[str] = Field(default_factory=list)


class CouplerEvidence(BaseModel):
    """Explainable metrics produced by the Cross-Flow Causal Coupler."""

    score: float = Field(ge=0.0, le=1.0)
    coupled_cycle_count: int = 0
    total_llm_turns: int = 0
    obs_lag_match_ratio: float = 0.0
    dispatch_lag_match_ratio: float = 0.0
    median_obs_lag_s: float | None = None
    median_dispatch_lag_s: float | None = None
    byte_delta_correlation: float = 0.0
    granger_f_stat: float = 0.0
    coupled_target_hosts: list[str] = Field(default_factory=list)
    coupled_protocols: list[str] = Field(default_factory=list)
    coupled_links: list[dict[str, float | str | int]] = Field(default_factory=list)


class RegimeSegment(BaseModel):
    """A contiguous session interval with an inferred kinematic regime."""

    start_ts: float
    end_ts: float
    action_count: int
    regime: RegimeType
    median_inter_action_s: float
    inter_action_cv: float
    fanout_burst_ratio: float


class HandoffEvent(BaseModel):
    """Detected regime transition (e.g., autonomous agent handing off to human operator)."""

    timestamp: float
    from_regime: RegimeType
    to_regime: RegimeType
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str


class KinematicsEvidence(BaseModel):
    """Explainable metrics produced by the Session Kinematics & Handoff detector."""

    score: float = Field(ge=0.0, le=1.0)
    action_count: int = 0
    parallel_fanout_bursts: int = 0
    max_fanout_width: int = 1
    size_to_pause_correlation: float = 0.0
    scanner_regularity_score: float = 0.0
    segments: list[RegimeSegment] = Field(default_factory=list)
    handoffs: list[HandoffEvent] = Field(default_factory=list)


class DetectorScores(BaseModel):
    """Composite and per-detector breakdown."""

    composite: float = Field(ge=0.0, le=1.0)
    sawtooth: SawtoothEvidence
    coupler: CouplerEvidence
    kinematics: KinematicsEvidence


class HostVerdict(BaseModel):
    """Final analysis result for a single source host."""

    host_ip: str
    verdict: VerdictLevel
    confidence: float = Field(ge=0.0, le=1.0)
    scores: DetectorScores
    suppressed_as_dev_agent: bool = False
    sensitive_lateral_actions: int = 0
    dev_allowlisted_actions: int = 0
    unique_internal_targets: int = 0
    summary: str
    tls_bursts: list[TlsBurstEvent] = Field(default_factory=list)
    actions: list[ActionEvent] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    """Top-level report emitted by an OodaTap analysis run."""

    source_path: str
    adapter: str
    analyzed_at_epoch: float
    total_events: int
    host_verdicts: list[HostVerdict] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def alerting_hosts(self) -> list[HostVerdict]:
        """Hosts whose verdict requires analyst attention."""
        alert_levels = {
            VerdictLevel.AGENTIC_OODA_INTRUSION,
            VerdictLevel.HYBRID_HUMAN_AGENT_INTRUSION,
            VerdictLevel.SUSPICIOUS_LOOP,
        }
        return [hv for hv in self.host_verdicts if hv.verdict in alert_levels]
