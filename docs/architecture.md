# Architecture

Four planes, one direction of trust:

1. Control plane: the fake C2 server (lab/c2.py). Localhost only.
   The operator queues tasks from a fixed enum. The server stores
   tasks and results and keeps the ground-truth telemetry log.
2. Execution plane: the simulated agent. It beacons, receives enum
   tasks, and dispatches only to fixed local functions: the
   ransomware simulator, the probes, and restore. It cannot execute
   supplied input, by construction.
3. Effect plane: the sandbox. All file effects happen on dummy
   copies under sandbox/. Originals are read-only inputs, verified
   by hash in tests. The encryption master key lives only here.
4. Detection plane: lab/detections.py reads telemetry (never the
   live system), evaluates rules against positive telemetry from the
   run and a built-in negative fixture set, and emits metrics and a
   Navigator layer. Detection results therefore reproduce offline
   from evidence/sample logs alone.

Data flow: operator -> queue -> beacon -> agent -> simulator/probes
-> sandbox copies -> result metadata (counts and hashes only) ->
server -> telemetry -> detection engine -> reports.
