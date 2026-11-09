# Threat model and non-goals

Assets this lab must protect, in order: the host it runs on, any
network it can reach, the user's reputation (this is a public
portfolio artifact), and the lab data itself.

Non-goals, explicitly: this project is not malware, not a C2
framework for real use, not an evasion toolkit, and not an exploit.
Features that would serve those goals are absent by design and
listed as prohibited changes in RESPONSIBLE_USE.md.

Abuse cases considered and the structural control for each:
- Pointing the C2 at a real host: localhost enforcement in code,
  tested.
- Using the simulator on real files: sandbox plus marker plus size
  and count caps in the safety gate, tested, originals immutable.
- Exfiltrating keys or content through results: server-side refusal
  of forbidden result keys, tested.
- Hiding the lab's activity: the opposite is implemented, marker
  headers, named User-Agents, file magic, full telemetry logging.
- Removing the limits in a fork: cannot be prevented by licence
  text, which the disclaimer states plainly; the published design
  makes removal a visible, deliberate act.

Residual risk: any encryption code can be studied. Mitigation is
context and framing: detections, fixtures, lessons and safety
engineering are the substance of the repo, and the encryption is a
standard library AEAD construction taught in the open.
