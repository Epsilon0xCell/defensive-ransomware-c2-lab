"""AV bypass TEST BENCH, against this repo's fake AV only.

Each case takes a lab encrypted copy (an inert dummy artifact from
sandbox/encrypted, produced by the simulator) and applies one
textbook transform inside sandbox/av_cases: rename, extension
change, text encoding, splitting, partial encryption. The bench
then runs the fake AV's three tiers over every case file and
publishes a scorecard of what each tier caught and missed, with the
defensive fix for each miss.

Scope, in code: the only accepted input is a FAKECRYPT lab file
from this lab's sandbox. Nothing here targets, tests against, or
evades any real antivirus or EDR product, and the transforms are
applied only to dummy lab artifacts so the fake AV's detection
layers can be measured and improved.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from . import fake_av
from .safety import ensure_dummy_file
from .simulator import run_simulation
from .telemetry import TelemetryLog

CASES_DOC = {
    "control_fakecrypt": "Unmodified lab artifact. Every tier must catch this.",
    "no_extension": "Extension removed. Extension-only checking misses it; magic catches it.",
    "renamed_dat": "Renamed to a data-file name. Same lesson as no_extension.",
    "encoded_container": "Lab artifact base64-encoded into a text file. Content checks miss it; behaviour catches the encode action.",
    "partial_encryption": "Partial mode artifact. Entropy-only checking misses it; magic catches it.",
    "split_chunk_b": "Second half of a split artifact. No magic, no marker; entropy and the split action are the only signals.",
}


def build_cases(sandbox: Path, master_key: bytes,
                log: TelemetryLog) -> Path:
    run_simulation(sandbox, master_key, mode="full", log=None)
    run_simulation(sandbox, master_key, mode="partial", log=None)
    # rebuild the full-mode notes artifact last so cases use full mode
    run_simulation(sandbox, master_key, mode="full", log=None)
    src = sandbox / "encrypted" / "notes.txt.FAKECRYPT"
    if not src.is_file():
        raise FileNotFoundError(src)
    blob = src.read_bytes()
    cases = sandbox / "av_cases"
    cases.mkdir(parents=True, exist_ok=True)
    for old in cases.iterdir():
        old.unlink()

    def put(name: str, data: bytes, action: str, technique: str) -> None:
        (cases / name).write_bytes(data)
        log.emit(action, "av_bypass_bench", case_file=name, technique=technique)

    put("control_fakecrypt.FAKECRYPT", blob, "file_encrypt", "control")
    put("no_extension", blob, "file_rename_sim", "extension_removal")
    put("renamed_dat.dat", blob, "file_rename_sim", "rename")
    put("encoded_container.txt", base64.b64encode(blob),
        "file_encode_sim", "text_encoding_container")
    # partial artifact: regenerate and read before full mode overwrite order
    run_simulation(sandbox, master_key, mode="partial", log=None)
    partial_blob = src.read_bytes()
    put("partial_encryption.FAKECRYPT", partial_blob, "file_encrypt",
        "partial_encryption")
    run_simulation(sandbox, master_key, mode="full", log=None)
    half = len(blob) // 2
    put("split_chunk_a", blob[:half], "file_split_sim", "split")
    put("split_chunk_b", blob[half:], "file_split_sim", "split")
    return cases


def run_bench(sandbox: Path, master_key: bytes, log: TelemetryLog) -> dict:
    cases = build_cases(sandbox, master_key, log)
    results = []
    for p in sorted(cases.iterdir()):
        r = fake_av.scan_file(p, events=log.events)
        case = p.name.split(".")[0] if p.name != "control_fakecrypt.FAKECRYPT" else "control_fakecrypt"
        doc_key = ("control_fakecrypt" if p.name.startswith("control")
                   else "no_extension" if p.name == "no_extension"
                   else "renamed_dat" if p.name.startswith("renamed")
                   else "encoded_container" if p.name.startswith("encoded")
                   else "partial_encryption" if p.name.startswith("partial")
                   else "split_chunk_b")
        results.append({"file": p.name, "checks": r.checks, "tiers": r.tiers,
                        "entropy": r.entropy, "lesson": CASES_DOC[doc_key]})
    tiers = ("naive", "standard", "behavioural")
    summary = {t: sum(1 for r in results if r["tiers"][t]) for t in tiers}
    return {"cases": len(results), "caught_by_tier": summary,
            "total_files": len(results), "results": results,
            "reading": "A miss at a tier is a finding about that tier, "
                       "not a capability of the case file: every case is "
                       "an inert dummy artifact inside the sandbox."}


def write_scorecard(bench: dict, out: Path) -> Path:
    lines = ["# Fake AV bypass test bench scorecard (auto-generated)", "",
             f"Cases: {bench['cases']} lab artifacts. Caught by tier: "
             f"naive {bench['caught_by_tier']['naive']}, standard "
             f"{bench['caught_by_tier']['standard']}, behavioural "
             f"{bench['caught_by_tier']['behavioural']}.", "",
             "| File | Extension | Magic | Marker | Entropy check | Naive | Standard | Behavioural |",
             "|---|---|---|---|---|---|---|---|"]
    for r in bench["results"]:
        c, t = r["checks"], r["tiers"]
        lines.append(f"| {r['file']} | {c['extension']} | {c['magic']} | "
                     f"{c['marker']} | {c['entropy']} | {t['naive']} | "
                     f"{t['standard']} | {t['behavioural']} |")
    lines += ["", bench["reading"], "", "Per-case lessons:"]
    for r in bench["results"]:
        lines.append(f"- {r['file']}: {r['lesson']}")
    out.write_text("\n".join(lines) + "\n")
    return out
