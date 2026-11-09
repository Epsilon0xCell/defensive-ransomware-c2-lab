# Rootkit mechanisms, taught through their detection

ATT&CK: T1014 Rootkit. Purpose: persistence and defence evasion by
hiding. Classes, at the level published research teaches them:

1. User-mode hooking. Code inside a process intercepts the API calls
   other programs use to list processes, files or connections, and
   filters its own entries out of the results. Fragile, and blind to
   any tool that reads below the API.
2. Kernel DKOM (Direct Kernel Object Manipulation). On Windows a
   process object sits in a doubly linked list that process
   enumerators walk. Unlinking an entry hides the process from those
   enumerators, while the scheduler, which tracks threads through
   different structures, keeps running it. That asymmetry, runs but
   does not list, is the detection surface this lab implements.
3. Driver and module hiding. The same unlink idea applied to the
   loaded-module list, which is why this detector also compares the
   module list against a memory-map view.
4. Bootkits. Hiding and persistence moved below the OS into the
   boot chain, which is why firmware integrity (the companion
   module) became the counter.

Historical teaching cases: the 2005 Sony BMG rootkit (the scandal
that made RootkitRevealer famous), the TDL/TDSS family (bootkit
era), and Necurs. Each is documented in vendor and academic write
ups suitable for course reading.

The professional skill: cross-view diffing. Collect the same fact
two independent ways and trust the disagreement. GMER and
RootkitRevealer are the classic tools; modern EDRs fold the same
idea into kernel telemetry. lab/rootkit_detector.py implements it
against fixtures: one view of each surface has an entry missing,
exactly as hiding presents, and the detector must name the surface,
the identifier, and which view is lying.
