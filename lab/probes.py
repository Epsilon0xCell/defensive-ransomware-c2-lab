"""Evasion-behaviour detection probes: safe, logged, reversible.

Each probe performs the OBSERVABLE a defender would see (a check, a
sleep, a variant file) and writes it to telemetry, then CONTINUES.
Nothing here hides from the log, impairs a defence, deletes a backup,
or touches anything outside the sandbox. Two fixtures are synthetic
telemetry only, clearly labelled synthetic and never executed:
recovery-inhibition command lines, because the real commands are on
the research report's never-replicate list.
"""
from __future__ import annotations

import os
import platform
import time
from pathlib import Path

from . import crypto_lab
from .simulator import run_simulation
from .telemetry import TelemetryLog


def probe_env_check(log: TelemetryLog) -> dict:
    """T1497.001 style environment checks that log and continue anyway."""
    checks = {
        "cpu_count": os.cpu_count() or 0,
        "platform": platform.system(),
        "python_version": platform.python_version(),
        "sandbox_marker_present": True,
    }
    result = {"checks": checks, "decision": "continue_anyway_lab"}
    log.emit("anti_analysis_check", "probe_env", **result)
    return result


def probe_timing_sleep(log: TelemetryLog, seconds: float = 2.0) -> dict:
    """T1497.003 style long sleep, bracketed by log lines."""
    log.emit("sleep_start", "probe_timing", requested_seconds=seconds)
    time.sleep(seconds)
    result = {"slept_seconds": seconds}
    log.emit("sleep_end", "probe_timing", **result)
    return result


def probe_extension_variants(sandbox: Path, master_key: bytes,
                             log: TelemetryLog) -> list[dict]:
    """T1486/T1036 observable: encrypted copies under variant extensions."""
    run_simulation(sandbox, master_key, mode="full", log=None)
    src = sandbox / "encrypted" / "notes.txt.FAKECRYPT"
    blob = src.read_bytes()
    variants_dir = sandbox / "variants"
    variants_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for label, fname in (("none", "notes_copy"),
                         ("double", "notes_copy.txt.FAKECRYPT"),
                         ("dat", "notes_copy.dat")):
        p = variants_dir / fname
        p.write_bytes(blob)
        entry = {"file": fname, "extension_label": label}
        out.append(entry)
        log.emit("file_create_variant", "probe_variants", **entry)
    return out


def probe_masquerade(log: TelemetryLog) -> dict:
    """T1036: a telemetry fixture for a system-named process outside its
    real path. Fixture only, no renamed binary is created or run."""
    entry = {"presented_image": "svchost_notes.exe",
             "presented_path": "lab://sandbox/variants",
             "true_type": "synthetic_fixture_no_binary",
             "synthetic": True}
    log.emit("process_create", "probe_masquerade",
             command_line="svchost_notes.exe (SYNTHETIC FIXTURE)", **entry)
    return entry


def probe_recovery_inhibition_fixtures(log: TelemetryLog) -> list[dict]:
    """T1490 fixtures, synthetic telemetry only, never executed.

    Positive: a shadow-deletion command line (what Sigma must catch).
    Negative: the read-only list variant (what Sigma must NOT catch).
    """
    pos = {"command_line": "vssadmin.exe Delete Shadows /all /quiet",
           "synthetic": True, "executed": False}
    neg = {"command_line": "vssadmin.exe List Shadows",
           "synthetic": True, "executed": False}
    log.emit("process_create", "probe_recovery_positive", **pos)
    log.emit("process_create", "probe_recovery_negative", **neg)
    return [pos, neg]
