"""Code-enforced safety gate. These checks are the product, not a note.

The research that scopes this lab is blunt: a disclaimer with no gate
is a red flag. Every file operation in the simulator passes through
here first, and the tests prove the gate refuses.
"""
from __future__ import annotations

from pathlib import Path

LAB_MARKER = b"LAB-DUMMY-FILE"
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 50


class SafetyError(RuntimeError):
    pass


def ensure_dummy_file(path: Path, sandbox_root: Path) -> Path:
    p = path.resolve()
    root = sandbox_root.resolve()
    if root not in p.parents:
        raise SafetyError(f"refused: {p} is outside the sandbox {root}")
    if not p.is_file():
        raise SafetyError(f"refused: {p} is not a file")
    if p.stat().st_size > MAX_FILE_BYTES:
        raise SafetyError(f"refused: {p} exceeds {MAX_FILE_BYTES} bytes")
    with p.open("rb") as fh:
        head = fh.read(len(LAB_MARKER))
    if head != LAB_MARKER:
        raise SafetyError(f"refused: {p} lacks the LAB-DUMMY marker")
    return p


def ensure_localhost(host: str) -> str:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SafetyError(f"refused: non-localhost bind/connect target {host!r}")
    return host
