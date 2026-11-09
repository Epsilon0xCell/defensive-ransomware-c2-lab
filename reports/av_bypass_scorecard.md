# Fake AV bypass test bench scorecard (auto-generated)

Cases: 7 lab artifacts. Caught by tier: naive 5, standard 6, behavioural 7.

| File | Extension | Magic | Marker | Entropy check | Naive | Standard | Behavioural |
|---|---|---|---|---|---|---|---|
| control_fakecrypt.FAKECRYPT | True | True | False | True | True | True | True |
| encoded_container.txt | False | False | False | False | False | False | True |
| no_extension | False | True | False | True | True | True | True |
| partial_encryption.FAKECRYPT | True | True | False | False | True | True | True |
| renamed_dat.dat | False | True | False | True | True | True | True |
| split_chunk_a | False | True | False | True | True | True | True |
| split_chunk_b | False | False | False | True | False | True | True |

A miss at a tier is a finding about that tier, not a capability of the case file: every case is an inert dummy artifact inside the sandbox.

Per-case lessons:
- control_fakecrypt.FAKECRYPT: Unmodified lab artifact. Every tier must catch this.
- encoded_container.txt: Lab artifact base64-encoded into a text file. Content checks miss it; behaviour catches the encode action.
- no_extension: Extension removed. Extension-only checking misses it; magic catches it.
- partial_encryption.FAKECRYPT: Partial mode artifact. Entropy-only checking misses it; magic catches it.
- renamed_dat.dat: Renamed to a data-file name. Same lesson as no_extension.
- split_chunk_a: Second half of a split artifact. No magic, no marker; entropy and the split action are the only signals.
- split_chunk_b: Second half of a split artifact. No magic, no marker; entropy and the split action are the only signals.
