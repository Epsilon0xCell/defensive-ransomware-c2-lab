"""Envelope encryption for the lab, AES-256-GCM (AEAD) throughout.

Structure taught and implemented here:
- a random 256-bit per-file key encrypts the file content (AES-GCM,
  fresh 12-byte nonce, 16-byte tag, filename bound as AAD);
- the per-file key is itself encrypted (wrapped) under a lab master
  key that never leaves this host and is never sent to the fake C2;
- real families wrap the per-file key with an asymmetric master
  public key instead, which is why their victims cannot unwrap it.
  The symmetric wrap here keeps the lab always recoverable.
See docs/encryption_lesson.md for the full lesson.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"FAKECRYPT-LAB-v1\n"


def new_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _ub64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def encrypt_segment(data: bytes, master_key: bytes, aad: bytes,
                    ) -> tuple[dict, bytes]:
    file_key = new_key()
    nonce = os.urandom(12)
    ct = AESGCM(file_key).encrypt(nonce, data, aad)
    wrap_nonce = os.urandom(12)
    wrapped = AESGCM(master_key).encrypt(wrap_nonce, file_key, b"lab-key-wrap")
    header = {"nonce": _b64(nonce), "wrapped_key": _b64(wrapped),
              "wrapped_key_nonce": _b64(wrap_nonce), "aad": aad.decode("utf-8")}
    return header, ct


def decrypt_segment(header: dict, ct: bytes, master_key: bytes) -> bytes:
    file_key = AESGCM(master_key).decrypt(
        _ub64(header["wrapped_key_nonce"]), _ub64(header["wrapped_key"]),
        b"lab-key-wrap")
    return AESGCM(file_key).decrypt(
        _ub64(header["nonce"]), ct, header["aad"].encode("utf-8"))


def encode_file(header: dict, ct: bytes) -> bytes:
    return MAGIC + json.dumps(header).encode("utf-8") + b"\n" + ct


def decode_file(blob: bytes) -> tuple[dict, bytes]:
    if not blob.startswith(MAGIC):
        raise ValueError("not a FAKECRYPT-LAB-v1 file")
    head, _, ct = blob[len(MAGIC):].partition(b"\n")
    return json.loads(head.decode("utf-8")), ct
