"""Fake ransomware simulator v2.

Hard limits, enforced in code and covered by tests:
- inputs are only dummy files created here, inside sandbox/originals,
  each starting with the LAB-DUMMY marker (see lab/safety.py);
- originals are NEVER modified, renamed or deleted; encrypted COPIES
  are written to sandbox/encrypted;
- modes: "full" (whole file) and "partial" (first segment encrypted,
  remainder left as plaintext in the copy), which reproduces the
  observable that intermittent/partial encryption defeats
  entropy-only detection (SentinelOne, see research report);
- no network, no persistence, no shadow copies, no service control.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import crypto_lab
from .safety import LAB_MARKER, MAX_FILES, ensure_dummy_file
from .telemetry import TelemetryLog, shannon_entropy

DUMMY_BODIES = {
    "notes.txt": "Meeting notes. " * 60,
    "report.txt": "Quarterly lab report, all figures invented. " * 45,
    "photo_index.txt": "IMG_0001 lake, IMG_0002 lab bench, IMG_0003 whiteboard. " * 30,
    "budget.txt": "item,cost\nservers,0\nsnacks,12\n" * 25,
    "canary_first.txt": "Canary file: alphabetically early, tripwire only. " * 20,
}


def make_dummies(sandbox: Path) -> list[Path]:
    originals = sandbox / "originals"
    originals.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, str] = {}
    paths: list[Path] = []
    for name, body in DUMMY_BODIES.items():
        p = originals / name
        data = LAB_MARKER + b"\n" + body.encode("utf-8")
        p.write_bytes(data)
        manifest[name] = hashlib.sha256(data).hexdigest()
        paths.append(p)
    (sandbox / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return paths


def _encrypt_copy(src: Path, sandbox: Path, master_key: bytes, mode: str,
                  log: TelemetryLog | None) -> dict:
    ensure_dummy_file(src, sandbox)
    data = src.read_bytes()
    aad = src.name.encode("utf-8")
    if mode == "partial":
        cut = max(1, len(data) // 2)
        header, ct_head = crypto_lab.encrypt_segment(data[:cut], master_key, aad)
        header["mode"] = "partial"
        header["segment_len"] = cut
        ct = ct_head + data[cut:]
    else:
        header, ct = crypto_lab.encrypt_segment(data, master_key, aad)
        header["mode"] = "full"
    out = sandbox / "encrypted" / (src.name + ".FAKECRYPT")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(crypto_lab.encode_file(header, ct))
    result = {"name": src.name, "mode": mode,
              "sha256_before": hashlib.sha256(data).hexdigest(),
              "entropy_before": shannon_entropy(data),
              "entropy_after": shannon_entropy(out.read_bytes()),
              "encrypted_copy": str(out)}
    if log is not None:
        log.emit("file_encrypt", "ransomware_sim", **result)
    return result


def run_simulation(sandbox: Path, master_key: bytes, mode: str = "full",
                   log: TelemetryLog | None = None) -> list[dict]:
    originals = sorted((sandbox / "originals").glob("*"))
    if len(originals) > MAX_FILES:
        raise ValueError("too many files for the lab cap")
    return [_encrypt_copy(p, sandbox, master_key, mode, log) for p in originals]


def restore_all(sandbox: Path, master_key: bytes,
                log: TelemetryLog | None = None) -> list[dict]:
    manifest = json.loads((sandbox / "manifest.json").read_text())
    restored_dir = sandbox / "restored"
    restored_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    for enc in sorted((sandbox / "encrypted").glob("*.FAKECRYPT")):
        name = enc.name[: -len(".FAKECRYPT")]
        header, ct = crypto_lab.decode_file(enc.read_bytes())
        try:
            if header.get("mode") == "partial":
                cut = int(header["segment_len"])
                # ciphertext total = encrypted segment (cut + 16-byte tag)
                # plus the untouched plaintext remainder
                seg_ct_len = len(ct) - (_orig_len(sandbox, name) - cut)
                plain = crypto_lab.decrypt_segment(header, ct[:seg_ct_len], master_key) + ct[seg_ct_len:]
            else:
                plain = crypto_lab.decrypt_segment(header, ct, master_key)
            (restored_dir / name).write_bytes(plain)
            ok = hashlib.sha256(plain).hexdigest() == manifest.get(name)
            entry = {"name": name, "restored": True, "sha256_match": ok}
        except Exception as exc:  # GCM tag failure lands here, by design
            entry = {"name": name, "restored": False,
                     "error": f"{type(exc).__name__}: AEAD verification failed"}
        results.append(entry)
        if log is not None:
            log.emit("file_restore", "restore_sim", **entry)
    return results


def _orig_len(sandbox: Path, name: str) -> int:
    return (sandbox / "originals" / name).stat().st_size
