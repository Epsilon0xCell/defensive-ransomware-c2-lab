"""Firmware and boot INTEGRITY VERIFIER, with a dummy image.

What this teaches, by building the defender's side (full lesson in
docs/firmware_integrity.md): Secure Boot checks signatures on boot
components against an allowed database; measured boot extends a
hash of each component into TPM PCR registers, PCR_new =
SHA256(PCR_old || measurement), so the final value is a fingerprint
of the whole chain that cannot be reordered or edited silently;
attestation compares that fingerprint to known-good values. A
firmware exploit, to survive, must defeat one of those checks,
which is why the verifier is where the teaching value lives.

Everything here is file-level and simulated: a dummy firmware image
and dummy boot components in the sandbox, a manifest of SHA-256
hashes, an HMAC standing in for a vendor signature (a real system
uses asymmetric keys, so the signer and verifier hold different
material; the check shape is the same), and a PCR-style chain
computed in software rather than in a TPM.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

COMPONENTS = ("bootloader.bin", "kernel.bin", "initrd.bin")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_dummy_firmware(sandbox: Path, signing_key: bytes) -> dict:
    fw_dir = sandbox / "firmware"
    fw_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, str] = {}
    for i, name in enumerate(COMPONENTS):
        blob = (b"LAB-DUMMY-FIRMWARE " + name.encode() + b" "
                + bytes([65 + i]) * 512)
        (fw_dir / name).write_bytes(blob)
        manifest[name] = _sha(blob)
    sig = hmac.new(signing_key, json.dumps(manifest, sort_keys=True).encode(),
                   hashlib.sha256).hexdigest()
    doc = {"manifest": manifest, "signature_hmac": sig,
           "note": "HMAC stands in for a vendor asymmetric signature in this lab"}
    (fw_dir / "manifest.json").write_text(json.dumps(doc, indent=2))
    return doc


def extend_pcr(pcr: bytes, measurement: bytes) -> bytes:
    """One PCR extension: SHA256(PCR || measurement). Order matters."""
    return hashlib.sha256(pcr + measurement).digest()


def measure_boot(sandbox: Path, manifest: dict[str, str]) -> str:
    pcr = bytes(32)
    for name in COMPONENTS:
        digest = hashlib.sha256((sandbox / "firmware" / name).read_bytes()).digest()
        pcr = extend_pcr(pcr, digest)
    return pcr.hex()


def verify_firmware(sandbox: Path, signing_key: bytes,
                    doc: dict | None = None) -> dict:
    fw_dir = sandbox / "firmware"
    if doc is None:
        doc = json.loads((fw_dir / "manifest.json").read_text())
    manifest = doc["manifest"]
    expected_sig = hmac.new(
        signing_key, json.dumps(manifest, sort_keys=True).encode(),
        hashlib.sha256).hexdigest()
    signature_ok = hmac.compare_digest(expected_sig, doc["signature_hmac"])
    hashes_ok = True
    mismatched = []
    for name, want in manifest.items():
        got = _sha((fw_dir / name).read_bytes())
        if got != want:
            hashes_ok = False
            mismatched.append(name)
    pcr_now = measure_boot(sandbox, manifest)
    good_dir = fw_dir  # PCR of the manifest state is recomputed from files;
    # a clean run is defined as: hashes match the signed manifest, so the
    # measured chain equals the chain over the manifest digests.
    pcr = bytes(32)
    for name in COMPONENTS:
        pcr = extend_pcr(pcr, bytes.fromhex(manifest[name]))
    pcr_match = (pcr.hex() == pcr_now)
    return {"hashes_ok": hashes_ok, "mismatched_components": mismatched,
            "signature_ok": signature_ok, "pcr_match": pcr_match,
            "pcr_value": pcr_now,
            "verdict": "PASS" if (hashes_ok and signature_ok and pcr_match)
                       else "FAIL"}
