"""Fake C2 for the combined lab: localhost only, deliberately obvious.

Design mirrors real C2 shape (beacon, task, result) so defenders can
study and detect the pattern, with every stealth property removed:
fixed lab User-Agents, a marker header, plain HTTP on 127.0.0.1, a
fixed task enum (the agent can only run named local functions, never
a supplied command), and a server-side guard that REFUSES any result
payload containing key material or file contents.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import bypass_tests, probes
from .safety import ensure_localhost
from .simulator import restore_all, run_simulation
from .telemetry import TelemetryLog

ALLOWED_TASKS = ("ping_sim", "sysinfo_sim", "run_ransomware_sim",
                 "run_partial_sim", "run_evasion_probes", "restore_sim",
                 "run_av_bypass_tests")
FORBIDDEN_RESULT_KEYS = {"master_key", "key", "wrapped_key", "file_contents",
                         "file_key", "password", "token"}
MARKER_HEADER = "X-FakeC2-Lab"
MARKER_VALUE = "defensive-sim"


def _contains_forbidden(obj) -> str | None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in FORBIDDEN_RESULT_KEYS:
                return str(k)
            found = _contains_forbidden(v)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _contains_forbidden(v)
            if found:
                return found
    return None


class C2State:
    def __init__(self, token: str, log: TelemetryLog) -> None:
        self.token = token
        self.log = log
        self.tasks: list[dict] = []
        self.results: list[dict] = []
        self.lock = threading.Lock()


def make_server(host: str, port: int, token: str, log: TelemetryLog):
    ensure_localhost(host)
    state = C2State(token, log)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _auth(self) -> bool:
            return (self.headers.get("Authorization") == f"Bearer {token}"
                    and self.headers.get(MARKER_HEADER) == MARKER_VALUE)

        def _json(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802 (stdlib name)
            if not self._auth():
                return self._json(403, {"error": "lab auth failed"})
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/operator/queue":
                task = body.get("task")
                if task not in ALLOWED_TASKS:
                    return self._json(400, {"error": f"task not in enum: {task}"})
                item = {"task_id": uuid.uuid4().hex[:12], "task": task,
                        "status": "queued"}
                with state.lock:
                    state.tasks.append(item)
                state.log.emit("task_queued", "operator", **item)
                return self._json(200, item)
            if self.path == "/beacon":
                agent = body.get("agent_id", "unknown")
                state.log.emit("beacon", agent, agent_id=agent)
                with state.lock:
                    pending = [t for t in state.tasks if t["status"] == "queued"]
                    for t in pending:
                        t["status"] = "delivered"
                return self._json(200, {"tasks": pending})
            if self.path == "/result":
                bad = _contains_forbidden(body.get("result", {}))
                if bad:
                    state.log.emit("security_event", "c2_server",
                                   refused_result_key=bad)
                    return self._json(400, {"error": f"result refused: key {bad} "
                                                   "must never leave the host"})
                with state.lock:
                    state.results.append(body)
                state.log.emit("task_result", body.get("agent_id", "unknown"),
                               task_id=body.get("task_id"), status=body.get("status"))
                return self._json(200, {"ok": True})
            return self._json(404, {"error": "unknown path"})

    server = ThreadingHTTPServer((host, port), Handler)
    server.state = state  # type: ignore[attr-defined]
    return server


class Agent:
    """Simulated implant. Executes only its fixed local functions."""

    def __init__(self, base_url: str, token: str, sandbox: Path,
                 master_key: bytes, log: TelemetryLog,
                 agent_id: str | None = None) -> None:
        host = base_url.split("://", 1)[-1].split(":")[0]
        ensure_localhost(host)
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.sandbox = sandbox
        self.master_key = master_key
        self.log = log
        self.agent_id = agent_id or f"lab-agent-{uuid.uuid4().hex[:8]}"

    def _post(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            self.base_url + path, data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {self.token}",
                     MARKER_HEADER: MARKER_VALUE,
                     "User-Agent": "FakeC2Lab/2.0",
                     "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def _execute(self, task: str) -> dict:
        if task == "ping_sim":
            return {"reply": "pong (simulated, nothing was executed)"}
        if task == "sysinfo_sim":
            import platform
            return {"system": platform.system(), "release": platform.release()}
        if task == "run_ransomware_sim":
            r = run_simulation(self.sandbox, self.master_key, "full", self.log)
            return {"files": len(r), "entropies_after": [x["entropy_after"] for x in r]}
        if task == "run_partial_sim":
            r = run_simulation(self.sandbox, self.master_key, "partial", self.log)
            return {"files": len(r), "entropies_after": [x["entropy_after"] for x in r]}
        if task == "run_evasion_probes":
            probes.probe_env_check(self.log)
            probes.probe_timing_sleep(self.log, seconds=1.0)
            probes.probe_extension_variants(self.sandbox, self.master_key, self.log)
            probes.probe_masquerade(self.log)
            probes.probe_recovery_inhibition_fixtures(self.log)
            return {"probes": ["env_check", "timing_sleep", "extension_variants",
                               "masquerade_fixture", "recovery_fixtures"]}
        if task == "run_av_bypass_tests":
            bench = bypass_tests.run_bench(self.sandbox, self.master_key, self.log)
            return {"cases": bench["cases"], "caught_by_tier": bench["caught_by_tier"]}
        if task == "restore_sim":
            r = restore_all(self.sandbox, self.master_key, self.log)
            return {"restored": sum(1 for x in r if x["restored"]),
                    "verified": sum(1 for x in r if x.get("sha256_match"))}
        raise ValueError(f"unknown task refused: {task}")

    def run_cycles(self, cycles: int = 6, interval: float = 0.5) -> int:
        done = 0
        for _ in range(cycles):
            resp = self._post("/beacon", {"agent_id": self.agent_id})
            for task in resp.get("tasks", []):
                result = self._execute(task["task"])
                self._post("/result", {"agent_id": self.agent_id,
                                       "task_id": task["task_id"],
                                       "status": "done", "result": result})
                done += 1
            time.sleep(interval)
        return done


def new_token() -> str:
    return secrets.token_hex(16)
