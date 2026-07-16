# Broker feasibility gate — findings

**Date:** 2026-07-16
**Machine:** darwin 25.5.0 (arm64), macOS 26.5.2, CC 2.1.211, YubiKey OTP+FIDO+CCID.
**Plan:** [`docs/superpowers/plans/2026-07-16-broker-feasibility-gate.md`](../docs/superpowers/plans/2026-07-16-broker-feasibility-gate.md)
**Spec:** [`docs/superpowers/specs/2026-07-16-cc-fido-gate-broker-design.md`](../docs/superpowers/specs/2026-07-16-cc-fido-gate-broker-design.md)

Verifies the four Section-4 questions before implementing v2. Probes need one-time `sudo` and
physical key touches; run un-sandboxed. Verdicts: ✅ GREEN / ⛔️ RED / 🟡 PARTIAL.

---

## Q3 — `uchg` file + directory lock enforcement — ✅ GREEN

`probe-q3-uchg.sh`. A root-owned (stand-in for `_ccfido`) `uchg` file placed inside a `sean`-owned
temp dir; then `sean` tries every tampering path:

```
-rw-r--r--@ 1 root  staff  uchg 9 ... /…/secret
  PASS: write -> denied            (Operation not permitted)
  PASS: unlink -> denied (immutable)
  PASS: rename -> denied
  PASS: chflags nouchg -> denied (not owner)
=== DIR LOCK: root-owned dir, mode 0755, sean cannot create ===
  PASS: create-in-dir -> denied
RESULT: GREEN — uchg + dir-ownership lock out the agent uid
```

**Interpretation.** The file-custody guarantee's kernel primitive holds on APFS: a file owned by a
principal the agent isn't, plus `uchg`, cannot be written, deleted, renamed, or unflagged by the
agent uid — *even though the agent owns the parent directory* (immutable blocks unlink/rename). A
directory owned by another principal blocks creation. This is enforced with **no hook and no
runtime root**. The remaining half — that the *owner* (`_ccfido`, non-root) can toggle `uchg` to
perform legitimate writes — is proven in Q1/Task 4.

## Account — `_ccfido` service account — ✅ GREEN

`account-setup.sh` / `account-teardown.sh`. Result:

```
_ccfido (uid 309), gid=20(staff), hidden service-account range
su _ccfido  ->  "su: Sorry"   (sean cannot become _ccfido — no login, /usr/bin/false shell)
```

A dedicated non-login service account exists, can own files and serve as a LaunchDaemon
`UserName`, and the agent uid (`sean`) cannot act as it. (Pre-existed on this machine from an
earlier attempt; removed at the gate's teardown.)
