"""One-command reproducible lab run.

Starts the fake C2 on localhost, queues the full task set, runs the
agent (ransomware simulation, partial mode, evasion probes, restore),
then scores every detection rule against the collected telemetry and
the negative fixtures, and writes reports/metrics.json,
reports/navigator_layer.json and reports/report.md.

Usage: python -m lab.run_lab
"""
from __future__ import annotations

import json
import threading
import urllib.request
from pathlib import Path

from . import bypass_tests, c2, detections
from .crypto_lab import new_key
from .simulator import make_dummies
from .telemetry import TelemetryLog

ROOT = Path(__file__).resolve().parent.parent
SANDBOX = ROOT / "sandbox"
PORT = 8787


def _queue(base: str, token: str, task: str) -> None:
    req = urllib.request.Request(
        base + "/operator/queue", data=json.dumps({"task": task}).encode(),
        headers={"Authorization": f"Bearer {token}",
                 c2.MARKER_HEADER: c2.MARKER_VALUE,
                 "User-Agent": "FakeC2Lab-Operator/2.0",
                 "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def main() -> int:
    log_path = ROOT / "evidence" / "sample_run_log.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path.exists():
        log_path.unlink()
    log = TelemetryLog(log_path)
    make_dummies(SANDBOX)
    # The master key exists only in memory for this run. It is never
    # written to disk and never sent to the server, by design.
    master_key = new_key()
    token = c2.new_token()
    server = c2.make_server("127.0.0.1", PORT, token, log)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{PORT}"
    try:
        for task in ("run_ransomware_sim", "run_partial_sim",
                     "run_evasion_probes", "run_av_bypass_tests",
                     "run_rootkit_detection", "run_firmware_verification", "restore_sim"):
            _queue(base, token, task)
        agent = c2.Agent(base, token, SANDBOX, master_key, log)
        done = agent.run_cycles(cycles=8, interval=0.3)
    finally:
        server.shutdown()
    evaluation = detections.evaluate(log.events, detections.negative_fixture_events())
    metrics, layer, report = detections.write_reports(evaluation, ROOT / "reports")
    print(f"tasks completed: {done}")
    print(f"validated coverage: {evaluation['validated_count']} of "
          f"{evaluation['total_rules']} ({evaluation['validated_coverage_pct']} percent)")
    print(f"median time-to-detect: {evaluation['ttd_median_s']} s")
    bench = bypass_tests.run_bench(SANDBOX, master_key, log)
    card = bypass_tests.write_scorecard(bench, ROOT / "reports" / "av_bypass_scorecard.md")
    print(f"av bench: {bench['cases']} cases, caught by tier {bench['caught_by_tier']}")
    print(f"reports: {metrics.name}, {layer.name}, {report.name}, {card.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
