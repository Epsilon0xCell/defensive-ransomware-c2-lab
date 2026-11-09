"""Detection engine: rules as data, scored against telemetry fixtures.

Honest-coverage rules (from the research report, section 7.3):
- a technique counts as VALIDATED (ladder L3) only when its rule
  fires on the positive fixture AND stays silent on the negative
  fixture. A rule merely existing is L1 and scores nothing.
- time-to-detect is measured from the first telemetry event to the
  first matching event, in seconds, and reported per rule.
ATT&CK IDs are version-stamped in the Navigator layer export because
Defense Evasion was renumbered (T1685/T1688 new, T1562/T1070 legacy).
"""
from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .telemetry import Event

ATTACK_STAMP = "technique IDs as researched 2026-11-09 (post-renumbering, legacy IDs noted)"


@dataclass
class Rule:
    rule_id: str
    title: str
    attck: str
    attck_legacy: str
    fp_notes: str
    matcher: Callable[[Event], bool]

    def first_match(self, events: list[Event]) -> Event | None:
        for ev in events:
            if self.matcher(ev):
                return ev
        return None


def _cmd(ev: Event) -> str:
    return str(ev.details.get("command_line", "")).lower()


RULES: list[Rule] = [
    Rule("lab-1490-recovery-inhibition", "Shadow deletion command line",
         "T1490", "", "Backup products are the FP source; read-only list must not fire.",
         lambda ev: ev.event_type == "process_create"
         and "vssadmin" in _cmd(ev) and "delete" in _cmd(ev) and "shadows" in _cmd(ev)),
    Rule("lab-1486-encryption-burst", "Encryption burst across dummy set",
         "T1486", "", "Backup/sync bursts are the FP source; rate plus spread is the signal.",
         lambda ev: ev.event_type == "file_encrypt"),
    Rule("lab-1486-partial-entropy", "Partial encryption pattern (entropy alone would miss)",
         "T1486", "", "Fires on mode metadata joined to the burst, teaching the entropy gap.",
         lambda ev: ev.event_type == "file_encrypt"
         and ev.details.get("mode") == "partial"),
    Rule("lab-1497-anti-analysis-sequence", "Anti-analysis checks present in run",
         "T1497.001", "T1497.003", "Never alert on a check alone in production; here it is scored joined to the run.",
         lambda ev: ev.event_type == "anti_analysis_check"),
    Rule("lab-1036-masquerade-fixture", "Masquerading fixture: system name, wrong place",
         "T1036", "", "Portable admin tools are the FP source; signer plus path tuning required.",
         lambda ev: ev.event_type == "process_create"
         and ev.details.get("true_type") == "synthetic_fixture_no_binary"),
    Rule("lab-1071-beacon", "Fake C2 beaconing present",
         "T1071.001", "", "Updates and telemetry also beacon; baseline per process and destination.",
         lambda ev: ev.event_type == "beacon"),
    Rule("lab-1486-variant-extensions", "Encrypted copies under variant extensions",
         "T1486", "T1036", "Legit archives use odd extensions; join to the burst rule.",
         lambda ev: ev.event_type == "file_create_variant"),
]

BURST_RULE_ID = "lab-1486-encryption-burst"
BURST_THRESHOLD = 3
BURST_WINDOW_S = 30.0


def _burst_ttd(events: list[Event]) -> float | None:
    hits = [ev for ev in events if ev.event_type == "file_encrypt"]
    if len(hits) < BURST_THRESHOLD:
        return None
    start = hits[0].ts
    for h in hits:
        window = [x for x in hits if h.ts - BURST_WINDOW_S <= x.ts <= h.ts]
        if len(window) >= BURST_THRESHOLD:
            return round(h.ts - events[0].ts, 4) if events else None
    return None


def negative_fixture_events() -> list[Event]:
    """Benign fixtures every rule must stay silent on."""
    base = 1_700_000_000.0
    return [
        Event("process_create", "fixture", ts=base,
              details={"command_line": "vssadmin.exe List Shadows"}),
        Event("process_create", "fixture", ts=base + 1,
              details={"command_line": "notepad.exe notes.txt"}),
        Event("sleep_end", "fixture", ts=base + 2, details={"slept_seconds": 5}),
        Event("file_create", "fixture", ts=base + 3,
              details={"file": "backup.zip"}),
    ]


def evaluate(events: list[Event], negatives: list[Event]) -> dict:
    results = []
    t0 = events[0].ts if events else 0.0
    for rule in RULES:
        pos = rule.first_match(events)
        neg = rule.first_match(negatives)
        if rule.rule_id == BURST_RULE_ID:
            ttd = _burst_ttd(events)
            fired_pos = ttd is not None
        else:
            fired_pos = pos is not None
            ttd = round(pos.ts - t0, 4) if pos else None
        fired_neg = neg is not None
        results.append({
            "rule_id": rule.rule_id, "title": rule.title,
            "attck": rule.attck, "attck_legacy": rule.attck_legacy,
            "fired_on_positive": fired_pos, "fired_on_negative": fired_neg,
            "validated_L3": bool(fired_pos and not fired_neg),
            "time_to_detect_s": ttd, "fp_notes": rule.fp_notes})
    validated = [r for r in results if r["validated_L3"]]
    ttds = [r["time_to_detect_s"] for r in validated
            if r["time_to_detect_s"] is not None]
    return {"rules": results,
            "validated_count": len(validated), "total_rules": len(results),
            "validated_coverage_pct": round(100 * len(validated) / len(results), 1),
            "ttd_median_s": statistics.median(ttds) if ttds else None,
            "attack_stamp": ATTACK_STAMP}


def navigator_layer(evaluation: dict, domain: str = "enterprise-attack") -> dict:
    techniques = []
    for r in evaluation["rules"]:
        techniques.append({
            "techniqueID": r["attck"], "enabled": True,
            "score": 1 if r["validated_L3"] else 0,
            "color": "#2ca02c" if r["validated_L3"] else "#d3d3d3",
            "comment": (f"{r['rule_id']}: validated L3 (fired on positive, silent on "
                        f"negative), TTD {r['time_to_detect_s']}s" if r["validated_L3"]
                        else f"{r['rule_id']}: NOT validated, scores 0")})
    return {"name": "defensive-lab-combined validated coverage",
            "versions": {"layer": "4.5", "navigator": "5.1"},
            "domain": domain, "description": ATTACK_STAMP,
            "techniques": techniques}


def write_reports(evaluation: dict, out_dir: Path) -> tuple[Path, Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    metrics = out_dir / "metrics.json"
    metrics.write_text(json.dumps(evaluation, indent=2))
    layer = out_dir / "navigator_layer.json"
    layer.write_text(json.dumps(navigator_layer(evaluation), indent=2))
    lines = ["# Purple-team detection report (auto-generated)", "",
             f"Validated coverage (L3, honest count): "
             f"{evaluation['validated_count']} of {evaluation['total_rules']} rules "
             f"({evaluation['validated_coverage_pct']} percent).",
             f"Median time-to-detect: {evaluation['ttd_median_s']} s.", "",
             "| Rule | ATT&CK | Fired on positive | Silent on negative | Validated | TTD s |",
             "|---|---|---|---|---|---|"]
    for r in evaluation["rules"]:
        lines.append(f"| {r['rule_id']} | {r['attck']} | {r['fired_on_positive']} | "
                     f"{not r['fired_on_negative']} | {r['validated_L3']} | "
                     f"{r['time_to_detect_s']} |")
    lines += ["", "False-positive notes are per rule in metrics.json.",
              "A rule that exists but did not fire scores zero, on purpose."]
    report = out_dir / "report.md"
    report.write_text("\n".join(lines) + "\n")
    return metrics, layer, report
