"""Normalized OodaTap JSONL telemetry reader and writer."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from oodatap.policy import PolicyConfig
from oodatap.schemas import ActionEvent, TelemetryEvent, TlsBurstEvent


def read_jsonl(
    path: Path | str,
    policy: PolicyConfig | None = None,
) -> list[TelemetryEvent]:
    """Read normalized OodaTap TelemetryEvent records from a JSONL file."""
    events: list[TelemetryEvent] = []
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            payload = json.loads(stripped)
            kind = payload.get("kind")
            if kind == "tls_burst":
                event: TelemetryEvent = TlsBurstEvent.model_validate(payload)
                if policy is not None:
                    event = policy.classify_tls_burst(event)
            elif kind == "action":
                event = ActionEvent.model_validate(payload)
                if policy is not None:
                    event = policy.classify_action(event)
            else:
                raise ValueError(
                    f"Unsupported OodaTap JSONL event kind {kind!r} at {file_path}:{line_no}"
                )
            events.append(event)
    events.sort(key=lambda ev: ev.timestamp)
    return events


def write_jsonl(events: Iterable[TelemetryEvent], path: Path | str) -> Path:
    """Write normalized TelemetryEvent records to a JSONL file."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(events, key=lambda ev: ev.timestamp)
    with out_path.open("w", encoding="utf-8") as fh:
        for event in ordered:
            fh.write(event.model_dump_json() + "\n")
    return out_path
