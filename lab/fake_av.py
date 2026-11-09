"""A FAKE antivirus scanner, built to be tested against.

This module is the defender in the AV-bypass test bench: a small,
honest model of how real scanners layer checks, so the bench can
measure which layer catches what. It scans only lab artifacts.

Tiers, weakest to strongest:
- naive:       file extension or file magic only. This is the tier
               that simple renaming defeats, and the bench proves it
               at check level.
- standard:    naive, plus the dummy-marker signature and a
               high-entropy check. Encoding a lab file into a text
               container defeats this tier's content checks, and the
               bench proves that too.
- behavioural: standard, plus host telemetry. The transform actions
               that produced a file (encrypt, rename, encode, split)
               are themselves observable events, so an EDR-style
               tier catches cases whose file content looks clean.
               This is the actual lesson of the bench: content
               scanning alone loses, behaviour wins.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .crypto_lab import MAGIC
from .safety import LAB_MARKER
from .telemetry import Event, shannon_entropy

ENTROPY_FLAG = 7.2
ACTION_EVENTS = ("file_encrypt", "file_create_variant", "file_encode_sim",
                 "file_split_sim", "file_rename_sim")


@dataclass
class ScanResult:
    file: str
    checks: dict[str, bool] = field(default_factory=dict)
    tiers: dict[str, bool] = field(default_factory=dict)
    entropy: float = 0.0


def scan_bytes(name: str, blob: bytes) -> dict[str, bool]:
    return {
        "extension": name.endswith(".FAKECRYPT"),
        "magic": blob[: len(MAGIC)] == MAGIC,
        "marker": LAB_MARKER in blob,
        "entropy": shannon_entropy(blob) > ENTROPY_FLAG,
    }


def scan_file(path: Path, events: list[Event] | None = None) -> ScanResult:
    blob = path.read_bytes()
    checks = scan_bytes(path.name, blob)
    naive = checks["extension"] or checks["magic"]
    standard = naive or checks["marker"] or checks["entropy"]
    behavioural = standard
    if events:
        for ev in events:
            if ev.event_type in ACTION_EVENTS and \
                    ev.details.get("case_file") == path.name:
                behavioural = True
    return ScanResult(file=path.name, checks=checks, entropy=shannon_entropy(blob),
                      tiers={"naive": naive, "standard": standard,
                             "behavioural": behavioural})
