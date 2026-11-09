"""Cross-view rootkit DETECTOR, with fixtures that teach the mechanism.

How rootkit hiding works, in one paragraph (full lesson in
docs/rootkit_detection.md): a process can be unlinked from the list
an API enumerates while its threads stay in the scheduler's own
structures, so it keeps running but a process listing stops showing
it. The same trick hides files from directory APIs and modules from
module lists. Defenders learned to compare independent views of the
same system and flag the disagreements. That comparison is a real,
professional anti-rootkit technique (RootkitRevealer worked exactly
this way), and it is what this module implements.

The fixtures are DATA: two views of the same simulated system, one
of which has an entry missing, exactly as a hidden entry presents to
a defender. There is no hiding code here; the detector is the code.
"""
from __future__ import annotations

from .telemetry import TelemetryLog

BASE_PROCESSES = [
    {"pid": 4, "name": "System"},
    {"pid": 812, "name": "explorer.exe"},
    {"pid": 1204, "name": "python.exe"},
]
BASE_FILES = ["notes.txt", "report.txt", "drivers.txt"]
BASE_MODULES = ["ntoskrnl.exe", "tcpip.sys", "labdrv.sys"]


def make_views(scenario: str) -> dict[str, list]:
    """Two independent views per surface, as a defender would collect."""
    api_processes = [dict(p) for p in BASE_PROCESSES]
    thread_scan = [dict(p) for p in BASE_PROCESSES]
    api_files = list(BASE_FILES)
    raw_files = list(BASE_FILES)
    module_list = list(BASE_MODULES)
    memory_modules = list(BASE_MODULES)
    if scenario == "hidden_process":
        # Present in the thread scan, absent from the API list: the
        # classic presentation of a process unlinked from the list.
        thread_scan.append({"pid": 4242, "name": "hidden_sim.exe"})
    elif scenario == "hidden_file":
        raw_files.append("hidden_sim.dat")
    elif scenario == "hidden_module":
        memory_modules.append("hidden_sim.sys")
    elif scenario != "clean":
        raise ValueError(f"unknown scenario: {scenario}")
    return {"api_processes": api_processes, "thread_scan": thread_scan,
            "api_files": api_files, "raw_files": raw_files,
            "module_list": module_list, "memory_modules": memory_modules}


def cross_view_diff(views: dict[str, list],
                    log: TelemetryLog | None = None) -> list[dict]:
    findings: list[dict] = []

    def compare(surface: str, a_name: str, a: list, b_name: str, b: list,
                key) -> None:
        a_keys = {key(x) for x in a}
        b_keys = {key(x) for x in b}
        for missing in b_keys - a_keys:
            findings.append({
                "surface": surface, "identifier": missing,
                "present_in": b_name, "absent_in": a_name,
                "attck": "T1014",
                "explanation": f"{missing} is visible in {b_name} but absent "
                               f"from {a_name}. Independent views of the same "
                               f"system disagree, which is the signature of "
                               f"hiding on the {surface} surface."})

    compare("process", "api_process_list", views["api_processes"],
            "thread_scan", views["thread_scan"], lambda p: p["name"])
    compare("file", "api_file_listing", views["api_files"],
            "raw_dir_read", views["raw_files"], lambda f: f)
    compare("module", "module_list", views["module_list"],
            "memory_map", views["memory_modules"], lambda m: m)
    if log is not None:
        for f in findings:
            log.emit("rootkit_finding", "rootkit_detector", **f)
    return findings


def run_all_scenarios(log: TelemetryLog | None = None) -> dict:
    out = {}
    for scenario in ("clean", "hidden_process", "hidden_file", "hidden_module"):
        found = cross_view_diff(make_views(scenario), log)
        out[scenario] = {"findings": len(found), "details": found}
    return out
