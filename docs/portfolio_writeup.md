# Portfolio write-up: what this project demonstrates

For a resume or LinkedIn, in one paragraph:

Built and published a defensive security lab (Python, pytest, CI):
fake C2 and ransomware simulators with code-enforced safety limits,
detection-as-code with MITRE ATT&CK coverage generated from test
results, an AV detection test bench, cross-view rootkit detection
(T1014), and firmware measured-boot integrity verification
(T1542.001).

For an interview, the four stories this repo supports, each with a
file and a number behind it:

1. Safety as engineering, not policy. The simulator cannot touch a
   real file: sandbox, marker, size and count caps, localhost only,
   and a C2 server that refuses result payloads containing key
   material. Tests prove the refusals (tests/test_lab.py). This is
   the answer to "how do you keep offensive-adjacent coursework
   safe and presentable".
2. Detection-as-code with honest metrics. Seven rules scored on
   positive and negative fixtures; a rule that exists but does not
   fire scores zero. Validated coverage 7 of 7 on lab fixtures,
   median time-to-detect about 0.02 s in the lab run, false-positive
   notes written per rule (reports/report.md, reports/metrics.json).
3. Behaviour beats content scanning. The AV bench applies textbook
   transforms to inert lab artifacts and scores three scanner tiers:
   naive caught 5 of 7, standard 6 of 7, behavioural 7 of 7. The
   encoded container beat content scanning entirely and was caught
   by telemetry (reports/av_bypass_scorecard.md).
4. Learning offense through defense. Rootkit hiding and firmware
   exploitation are taught at mechanism depth, through the tools
   that catch them: a cross-view differ for T1014 and a Secure Boot
   plus measured-boot verifier for T1542.001 that passes a clean
   dummy image and fails a one-byte tamper on hash, manifest and
   PCR checks together (docs/rootkit_detection.md,
   docs/firmware_integrity.md).

Design and threat model: docs/architecture.md and
docs/threat_model.md. Research basis: a sourced defensive report on
ransomware evasion (MITRE, CISA, ESET, SentinelOne, Sophos,
CrowdStrike, 2025 to 2026), summarised in the repo docs.
