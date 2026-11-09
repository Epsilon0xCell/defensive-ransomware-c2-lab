# Firmware integrity: Secure Boot, measured boot, attestation

ATT&CK: T1542.001 System Firmware (pre-OS boot), T1014 for bootkits.

The boot chain in brief: firmware (UEFI) runs first in phases
(SEC, PEI, DXE), loads a bootloader, which loads the kernel. Whoever
controls an earlier stage controls everything after it, which is
why this layer is targeted and why it is verified, not trusted.

Two independent defences, and the verifier in this repo models both:

1. Secure Boot (authentication). Each component is signed. Firmware
   checks signatures against an allowed database chain: PK (platform
   key), KEK, db (allowed), dbx (revoked). An unsigned or revoked
   component is refused. Breaks in published research were mostly
   not cryptographic: BootHole (2020) was a GRUB2 parsing flaw in a
   signed component; LogoFAIL (2023) was image-parsing flaws in
   firmware itself; BlackLotus (2023) exploited a bootloader flaw
   (CVE-2022-21894) and the revocation lag that followed, the same
   lag problem the ransomware research in this repo notes for the
   vulnerable-driver blocklist.
2. Measured boot (evidence). Each component's hash is extended
   into a TPM Platform Configuration Register: PCR_new =
   SHA256(PCR_old || measurement). The chain is order-sensitive and
   append-only from software's point of view, so the final PCR
   value fingerprints the exact chain that ran. Attestation is a
   remote verifier comparing that fingerprint to known-good values.

lab/firmware_verifier.py models both checks at file level: a signed
manifest (HMAC standing in for the asymmetric vendor signature; the
shape of the check is identical) and a software PCR chain over
dummy boot components. Clean components pass. Flip one byte in any
component and three things fail at once: its hash, the manifest
check, and the PCR fingerprint. That triple failure is what a real
attestation report looks like, and reproducing it on dummy files is
the whole lesson, no boot chain harmed.
