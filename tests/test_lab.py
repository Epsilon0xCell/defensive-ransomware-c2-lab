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


def test_fake_av_tiers_and_bench(tmp_path):
    from lab import bypass_tests, fake_av
    from lab.telemetry import TelemetryLog as TL
    sb = tmp_path / "sandbox"
    make_dummies(sb)
    log = TL()
    bench = bypass_tests.run_bench(sb, new_key(), log)
    by_file = {r["file"]: r for r in bench["results"]}
    assert by_file["control_fakecrypt.FAKECRYPT"]["tiers"]["naive"] is True
    assert by_file["no_extension"]["checks"]["extension"] is False
    assert by_file["no_extension"]["tiers"]["naive"] is True  # magic saves it
    enc = by_file["encoded_container.txt"]
    assert enc["tiers"]["standard"] is False   # content scanning loses
    assert enc["tiers"]["behavioural"] is True  # behaviour wins
    part = by_file["partial_encryption.FAKECRYPT"]
    assert part["checks"]["entropy"] is False  # entropy-only would miss
    assert part["tiers"]["standard"] is True   # magic catches it
    assert bench["caught_by_tier"]["behavioural"] == bench["cases"]


def test_rootkit_detector_cross_view(tmp_path):
    from lab import rootkit_detector as rk
    assert rk.cross_view_diff(rk.make_views("clean")) == []
    for scenario, surface in (("hidden_process", "process"),
                              ("hidden_file", "file"),
                              ("hidden_module", "module")):
        found = rk.cross_view_diff(rk.make_views(scenario))
        assert len(found) == 1 and found[0]["surface"] == surface
        assert found[0]["attck"] == "T1014"


def test_firmware_verifier_clean_tamper_and_wrong_key(tmp_path):
    from lab import firmware_verifier as fw
    sb = tmp_path / "sandbox"
    key = b"unit-test-key"
    fw.make_dummy_firmware(sb, key)
    clean = fw.verify_firmware(sb, key)
    assert clean["verdict"] == "PASS" and clean["pcr_match"] is True
    target = sb / "firmware" / "bootloader.bin"
    blob = bytearray(target.read_bytes()); blob[10] ^= 0xFF
    target.write_bytes(bytes(blob))
    bad = fw.verify_firmware(sb, key)
    assert bad["verdict"] == "FAIL" and bad["hashes_ok"] is False
    assert bad["pcr_match"] is False
    fw.make_dummy_firmware(sb, key)
    wrong = fw.verify_firmware(sb, b"other-key")
    assert wrong["signature_ok"] is False and wrong["verdict"] == "FAIL"
