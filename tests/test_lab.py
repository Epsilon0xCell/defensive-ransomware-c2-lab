import json
import threading
from pathlib import Path

import pytest

from lab import c2, detections, probes
from lab.crypto_lab import new_key
from lab.safety import SafetyError, ensure_dummy_file, ensure_localhost
from lab.simulator import make_dummies, restore_all, run_simulation
from lab.telemetry import TelemetryLog


@pytest.fixture()
def sandbox(tmp_path):
    sb = tmp_path / "sandbox"
    make_dummies(sb)
    return sb


def test_safety_gate_accepts_dummy(sandbox):
    p = sandbox / "originals" / "notes.txt"
    assert ensure_dummy_file(p, sandbox) == p.resolve()


def test_safety_gate_refuses_outside_and_unmarked(tmp_path, sandbox):
    outside = tmp_path / "evil.txt"
    outside.write_bytes(b"LAB-DUMMY-FILE\nx")
    with pytest.raises(SafetyError):
        ensure_dummy_file(outside, sandbox)
    unmarked = sandbox / "originals" / "real.txt"
    unmarked.write_bytes(b"real data")
    with pytest.raises(SafetyError):
        ensure_dummy_file(unmarked, sandbox)


def test_localhost_gate():
    assert ensure_localhost("127.0.0.1")
    with pytest.raises(SafetyError):
        ensure_localhost("192.168.1.10")


def test_full_roundtrip_and_originals_untouched(sandbox):
    key = new_key()
    before = {p.name: p.read_bytes() for p in (sandbox / "originals").glob("*")}
    run_simulation(sandbox, key, "full")
    results = restore_all(sandbox, key)
    assert results and all(r["restored"] and r["sha256_match"] for r in results)
    after = {p.name: p.read_bytes() for p in (sandbox / "originals").glob("*")}
    assert before == after


def test_partial_mode_entropy_below_full(sandbox):
    key = new_key()
    full = run_simulation(sandbox, key, "full")
    part = run_simulation(sandbox, key, "partial")
    f = sum(r["entropy_after"] for r in full) / len(full)
    p = sum(r["entropy_after"] for r in part) / len(part)
    assert p < f
    results = restore_all(sandbox, key)
    assert all(r["restored"] and r["sha256_match"] for r in results)


def test_tamper_breaks_aead(sandbox):
    key = new_key()
    run_simulation(sandbox, key, "full")
    target = sandbox / "encrypted" / "notes.txt.FAKECRYPT"
    blob = bytearray(target.read_bytes())
    blob[-1] ^= 0xFF
    target.write_bytes(bytes(blob))
    results = {r["name"]: r for r in restore_all(sandbox, key)}
    assert results["notes.txt"]["restored"] is False
    assert results["report.txt"]["restored"] is True


def test_detections_validate_and_negatives_silent(sandbox):
    key = new_key()
    log = TelemetryLog()
    log.emit("beacon", "agent", agent_id="t")
    run_simulation(sandbox, key, "full", log)
    run_simulation(sandbox, key, "partial", log)
    probes.probe_env_check(log)
    probes.probe_extension_variants(sandbox, key, log)
    probes.probe_masquerade(log)
    probes.probe_recovery_inhibition_fixtures(log)
    ev = detections.evaluate(log.events, detections.negative_fixture_events())
    assert ev["validated_count"] == ev["total_rules"], ev
    layer = detections.navigator_layer(ev)
    assert all(t["score"] == 1 for t in layer["techniques"])


def test_c2_integration_and_key_guard(tmp_path):
    sb = tmp_path / "sandbox"
    make_dummies(sb)
    log = TelemetryLog()
    token = c2.new_token()
    server = c2.make_server("127.0.0.1", 0, token, log)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        from lab.run_lab import _queue
        _queue(base, token, "run_ransomware_sim")
        _queue(base, token, "ping_sim")
        agent = c2.Agent(base, token, sb, new_key(), log)
        assert agent.run_cycles(cycles=3, interval=0.1) == 2
        bad = c2._contains_forbidden({"wrapped_key": "x"})
        assert bad == "wrapped_key"
    finally:
        server.shutdown()


def test_c2_refuses_non_localhost():
    with pytest.raises(SafetyError):
        c2.make_server("0.0.0.0", 8787, "t", TelemetryLog())
