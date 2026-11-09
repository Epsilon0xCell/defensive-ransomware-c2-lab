# The encryption lesson: what "good encryption" means here

This is the part your course is actually testing. Real ransomware
is not dangerous because it uses a secret cipher. It is dangerous
because it uses standard, well reviewed cryptography correctly,
at scale, with key management the victim cannot reverse.

## 1. AEAD: AES-256-GCM
Symmetric encryption with a 256 bit key, in Galois/Counter Mode.
You get two properties, not one:
- Confidentiality: without the key, ciphertext looks random.
- Authenticity: a 16 byte tag. Change any bit and decryption
  fails loudly (try it: flip a byte in a .FAKECRYPT copy, then
  run restore_sim.py - it reports DECRYPTION FAILED, it does not
  hand back corrupted text).
Unauthenticated modes (ECB, plain CBC) give only the first
property and have a long history of practical attacks. ECB also
leaks structure: identical plaintext blocks give identical
ciphertext blocks, the famous ECB penguin.

## 2. Fresh key and fresh nonce, every file
GCM security collapses if a (key, nonce) pair is ever reused:
the XOR of two plaintexts leaks, and the authentication key can
be recovered. So crypto_lab.py generates a new 256 bit key per
file from the operating system CSPRNG, and a new 12 byte random
nonce per encryption. Scale matters for real attackers too: per
file keys mean compromising one file key opens exactly one file.

## 3. Envelope / hybrid encryption
AES is fast but both sides need the same secret key. RSA and
other asymmetric schemes are slow but solve key distribution.
Real families combine them: a per file AES key is wrapped
(encrypted) under a master public key embedded in the sample.
Only the operator's private key, which never touches a victim
machine, can unwrap. That asymmetry is why "just find the key
on the box" usually fails against a competent family, and why
backups, not decryption, are the reliable recovery.
This lab mirrors the structure with a symmetric master key kept
in lab_master_key.json on purpose: the shape is identical, the
lockout is not. Study the shape, keep the recovery.

## 4. Associated data (AAD)
GCM can authenticate data it does not encrypt. The lab binds the
filename as AAD, so a ciphertext renamed to another file fails
verification. Lesson: metadata is part of the security claim,
not decoration.

## 5. Why defenders cannot just decrypt
- 2 to the 256 possible keys: brute force is not a plan at any
  budget, and correctly implemented GCM gives no shortcut.
- Keys are generated on the victim, wrapped immediately, and
  the plaintext per file keys are discarded. Memory forensics
  sometimes catches a key if you image RAM mid run, which is a
  real incident response lesson: do not power off first.
- Errors that DO break real families, and which researchers
  have used to build free decryptors: nonce reuse, weak random
  generators, keys left in memory or on disk, home grown ciphers,
  and time based seeds. When a decryptor exists for a family, it
  almost always exploits one of those implementation mistakes,
  never a break of AES itself.

## 6. What this means for defence
Because the cryptography will not save you, the controls that
work are around it: offline or immutable backups that the
encrypting process cannot reach, least privilege so one process
cannot read everything, application allowlisting, macro and
script controls at the entry point, and detection on behaviour:
mass file reads plus high entropy writes plus renames in a short
window (exactly the pattern in simulation_log.jsonl of this lab).
Recovery time from backups, tested, is the metric that decides
whether an incident is an outage or an extinction event.
