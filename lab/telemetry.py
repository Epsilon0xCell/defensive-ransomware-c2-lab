"""Typed telemetry schema and JSONL logging for the lab.

Every simulator action emits one structured event. Detection rules and
the metrics engine consume ONLY these events, so a detection can be
tested against fixtures the same way a SIEM rule is tested against
seeded log data. Field names are kept close to Sysmon/OCSF concepts
(process, file, network) so the mapping to real telemetry is explicit.
"""
from __future__ import annotations

import json
import math
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Event:
    event_type: str            # e.g. process_create, file_encrypt, beacon
    actor: str                 # agent id, simulator, probe name, operator
    ts: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TelemetryLog:
    """Append-only JSONL ground-truth log plus an in-memory copy."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.events: list[Event] = []
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event_type: str, actor: str, **details: Any) -> Event:
        ev = Event(event_type=event_type, actor=actor, details=details)
        self.events.append(ev)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev.to_dict()) + "\n")
        return ev


def read_events(path: Path) -> list[Event]:
    out: list[Event] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            d = json.loads(line)
            out.append(Event(event_type=d["event_type"], actor=d["actor"],
                             ts=d["ts"], details=d.get("details", {})))
    return out


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, 0.0 (constant) to 8.0 (random)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)
