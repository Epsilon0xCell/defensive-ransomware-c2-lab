# Detection design notes

One deep detection, by design: recovery inhibition plus encryption
burst correlation.

Question: can we catch the pre-encryption window, not just the
encryption itself? The research says the highest-fidelity signal is
T1490 recovery inhibition, and the noisiest failure mode is firing
on read-only backup tooling.

Design: rule lab-1490 fires on a shadow-DELETION command line only;
the negative fixture is the read-only List variant, and the rule is
not validated unless it is silent there. Rule lab-1486 burst fires
on three or more file_encrypt events inside 30 seconds. Alone, each
is medium. In a real SIEM these two would be correlated inside a
10 minute window and raised to high, with the burst's time-to-detect
measured from the inhibition event, which is the number a detection
team should report.

False-positive budget, stated out loud as employers ask: on the lab
fixtures the FP count is zero by construction, which proves the
harness, not the rule's production quality. Production tuning notes
per rule live in lab/detections.py fp_notes: parent process, account
and change windows for T1490; host role and backup windows for the
burst. Intermittent encryption is handled by the partial-mode rule,
which fires on mode metadata joined to the burst precisely because
entropy-only detection misses partial encryption.
