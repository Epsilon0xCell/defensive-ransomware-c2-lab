# Defensive Lab: Fake C2 + Fake Ransomware Simulator, With Detection Engineering

EDUCATIONAL AND DEFENSIVE USE ONLY. Read DISCLAIMER.md and
RESPONSIBLE_USE.md before running anything. This is a template
disclaimer set, not legal advice.

A combined, employer-grade defensive lab built for cyber courses and
detection engineering practice:

- a fake command-and-control server and simulated agent
  (127.0.0.1 only, lab token plus marker header, fixed task enum,
  no supplied-command execution, results refused if they contain
  key material);
- a fake ransomware simulator that encrypts COPIES of dummy files
  it creates itself, inside a sandbox, originals never touched,
  AES-256-GCM envelope encryption, always restorable;
- evasion-behaviour detection probes that perform the observable
  (environment checks, a timed sleep, variant extensions,
  masquerading and recovery-inhibition fixtures) in a logged,
  reversible, synthetic-fixture way, and never impair a defence;
- a detection engine that scores Sigma-style rules against positive
  and negative fixtures, reports time-to-detect and false-positive
  notes, and generates an honest MITRE ATT&CK Navigator layer from
  test results only (a rule that exists but did not fire scores 0).

## Quick start

    pip install -e ".[dev]"
    python -m lab.run_lab
    pytest -q

The run writes reports/report.md, reports/metrics.json and
reports/navigator_layer.json, plus a ground-truth telemetry log.

## Layout

- lab/telemetry.py: typed event schema and JSONL ground truth
- lab/safety.py: the code-enforced safety gate (sandbox, marker, localhost)
- lab/crypto_lab.py: AES-256-GCM envelope encryption, lesson in docs/
- lab/simulator.py: dummy files, full and partial encryption modes, restore
- lab/probes.py: safe evasion-behaviour detection probes and fixtures
- lab/c2.py: fake C2 server, operator queue, simulated agent
- lab/detections.py: rules as data, coverage ladder, metrics, Navigator export
- lab/run_lab.py: one-command end-to-end exercise
- lab/fake_av.py + lab/bypass_tests.py: a fake AV scanner and its bypass test bench (against the fake AV only), with a generated scorecard
- lab/rootkit_detector.py: cross-view rootkit detection (T1014) with mechanism fixtures and lesson docs
- lab/firmware_verifier.py: firmware integrity verification, signed-manifest simulation plus PCR-style measured boot (T1542.001)
- sigma/: Sigma-format rule pack (validated as YAML in CI)
- tests/: pytest suite, including safety-gate refusal tests
- docs/: architecture, threat model, detection design, encryption lesson

## Safety limits, structural not advisory

Localhost only, sandbox only, dummy files with a marker only, size
and count caps, originals never modified, master key never leaves
the host (enforced server-side), no persistence, no spreading,
no shadow-copy or service or log tampering, no stealth: the lab
announces itself in its User-Agents, headers and file magic.

## Portfolio write-up

What this project demonstrates, with resume and interview framing:
docs/portfolio_writeup.md

## Research basis

Built from a defensive research report on ransomware evasion and
stealth (MITRE ATT&CK, CISA, ESET, SentinelOne, Sophos, CrowdStrike
sources, 2025 to 2026), including the honest-coverage ladder and the
safe versus never versus describe-only testing line.
