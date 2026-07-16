# cc-fido-gate — handoff for the next agent

You are continuing work on **cc-fido-gate**, a macOS tool that requires a physical FIDO/security-key
touch before Claude Code performs a high-risk action. Everything below is committed on `main`. Read
this, then read the three referenced docs before acting.

## Your immediate next step

**Write the v2 implementation plan** via the `superpowers:writing-plans` skill, targeting the
**revised** design in `docs/superpowers/specs/2026-07-16-cc-fido-gate-broker-design.md` (Section 1 is
capability-split — see below). Save to `docs/superpowers/plans/2026-07-16-cc-fido-gate-v2-impl.md`.
The **first task must be an end-to-end integration of the split ceremony**
(client-sign → unix socket → daemon-verify → `uchg`-write); it composes only pieces the feasibility
gate already proved. Then broker daemon, file/dir custody, best-effort hook, install/enroll CLIs.

Do NOT start coding until the plan is written and the user approves it (brainstorming already
happened; the spec is approved). After the plan, the user chose **subagent-driven execution** — but
note the caveat below about sudo/touch.

## What this project is

A Claude Code plugin/tool. Two equal partners driven by one FIDO key:
1. **Crown-jewel file/dir custody (HARD guarantee):** sensitive paths owned by an unprivileged
   `_ccfido` service account + the `uchg` immutable flag → the agent-uid literally can't
   write/delete/rename (files) or create (dirs). **Kernel-enforced, no hook in the path** — survives
   even if the gate is killed/disabled. Legit changes go through a broker that requires a touch.
2. **Best-effort touch-gate (BROAD):** a `PreToolUse` hook gates the advisory set
   (Write/Edit tiers, MCP, advisory Bash). Raises the bar; **defeatable by a same-uid agent** (see
   Task 0.1) — stated honestly.

## How we got here (the load-bearing findings)

Read `task0/REPORT.md` and `task0-broker/REPORT.md` for the actual commands/outputs.

- **Task 0 (synchronous v1 feasibility) — killed the original design.** The old design
  (`docs/design.md`) was a synchronous in-hook gate. Task 0.1 proved empirically that **Claude Code
  fails OPEN when a PreToolUse hook is killed/crashes/times-out** (deterministic): a hook that
  returns `exit 2` blocks, but a killed hook → CC runs the tool anyway. That fail-open is in CC's
  harness, unfixable by us. A same-uid agent can `pkill` the hook via an un-gated Bash call. So **no
  hook-based design can hard-guarantee against a determined same-uid agent.** This mandated the
  broker/file-custody model. (Other Task 0 results: 0.2 deny works under
  `--dangerously-skip-permissions`; 0.3 `allowManagedHooksOnly:true` suppresses user/project hooks;
  0.4 negative blink-test works on the real YubiKey; 0.5 osascript renders under `env -i`; 0.6 hook
  env is hostile/unscrubbed; 0.7 same-uid debugger attach is denied.)

- **v2 spec** (`docs/superpowers/specs/2026-07-16-cc-fido-gate-broker-design.md`) — the approved
  hybrid design. Key user decisions (do not relitigate):
  - **Hybrid** guarantee level (both partners).
  - **No runtime root:** broker runs as an unprivileged `_ccfido` service account; only a one-time
    `sudo` install (create account, `chown` enrolled paths, drop LaunchDaemon + root-owned
    `managed-settings.json`). `uchg` (owner-togglable) not `schg` (root-only).
  - **Softened dialog accepted:** no trusted-path dialog without root, so WYSIWYS degrades to the
    display-spoof residual `design.md` already conceded. Core kernel lock unaffected.
  - Credential-custody and MCP-proxy custody are **out of scope** for v2 (future specs).

- **Broker feasibility gate** (`task0-broker/REPORT.md`) — ran inline, **verdict GO**, but produced
  **one architecture revision** that is already folded into the spec:
  - **Q1 finding (the important one):** a **system LaunchDaemon cannot reach the USB FIDO device**
    (`device not found`); the **console/login session can** (proven: root-console and `sean`-console
    both sign). Verified it's the session context, not a stuck device.
  - **Resolution — capability-split ceremony (now in spec Section 1):** the **console-session
    client** does USB + GUI (arm the key, sign the daemon's challenge, draw the dialog); the
    **daemon** (`_ccfido`) issues the challenge, **verifies the signature** (`ssh-keygen -Y verify`
    needs no USB), owns the files, toggles `uchg` + writes, and audits. Q2 (cross-process touch
    binding) is thereby subsumed. **Trade accepted (user chose option A):** the `sk` handle is
    readable by the console signer, so the agent can *arm/blink* the key but **cannot sign** without
    a physical touch; the signature is challenge-bound. Single-armed-signer drops to a parked
    hardening upgrade (a tiny setuid-root signer — declined to keep zero root).
  - Q3 (`uchg` file+dir lock + owner toggle) ✅ GREEN; Q4 (socket + `LOCAL_PEERCRED`) ✅ GREEN.

## The revised ceremony (build against THIS)

```
client (console session, runs as the login user)      daemon (_ccfido, LaunchDaemon, unprivileged)
  request write {path, content}  ───────socket───────►  validate + canonicalize
                                                          derive challenge (canonical signed_document
                                                          binding path+content+context) + human_rendering
  draw dialog (softened WYSIWYS)  ◄──────socket───────  return {challenge, human_rendering}
  arm key + ssh-keygen -Y sign(challenge); TOUCH
  return signature  ─────────────socket──────────────►  ssh-keygen -Y verify(sig over challenge)  [no USB]
                                                          on success: nouchg → write → fsync → uchg
                                                          append to _ccfido-owned audit log
```

## Empirical gotchas learned (save yourself the rediscovery)

- **`claude -p` needs the sandbox OFF** (Anthropic API host isn't in the sandbox allowlist, and it
  reads `~/.claude/.credentials.json` which the sandbox denies). Also, the *inner* `claude -p` Bash
  tool re-applies its own sandbox — put any sentinel files it writes under `/tmp/claude/…` so the
  inner sandbox permits them.
- **osascript:** the box's default OSA language is **JavaScript** — force `-l AppleScript`. And
  `display dialog` needs StandardAdditions, which **won't load under a sandbox-exec** (`-10810`
  errors) — run un-sandboxed.
- **FIDO signing:** stock `/usr/bin/ssh-keygen` (10.2p1) **verifies** `sk-` keys but **can't sign**
  them — use `/opt/homebrew/opt/openssh/bin/ssh-keygen` for the *sign* side. `-O resident=no` is
  invalid (non-resident is default). A **hard-killed ceremony leaves the device transiently
  `device not found`** — the next arm needs a short retry/backoff.
- **Sockets:** the daemon socket must live in a `0755` traversable dir (e.g. `/var/ccfido-run/`), NOT
  the `0700` keydir (`/var/ccfido/`) — else clients get `EPERM`. macOS `LOCAL_PEERCRED` = option
  `0x001`, level `0`; parse `cr_uid` from bytes `[4:8]` of the `xucred` struct.
- **Service account:** create `_ccfido` (hidden, uid in 200–400, `/usr/bin/false` shell) via `dscl`.
  See `task0-broker/probes/account-setup.sh` / `account-teardown.sh`.
- **This machine:** darwin 25.5.0 arm64, macOS 26.5.2, Claude Code **2.1.211** (real binary at
  `/Users/sean/.local/bin/claude`, NOT the cmux shim on PATH). No global PreToolUse hooks. YubiKey
  OTP+FIDO+CCID present. User is `sean` (uid 501).

## Process / working agreements

- Follow the superpowers flow: brainstorming (done) → writing-plans (your next step) →
  subagent-driven-development for execution. Route reviewer/TDD subagent work through the relevant
  skills (see `~/.claude/CLAUDE.md`).
- **Anything needing `sudo` or a physical touch must be run by the user** (a subagent can't enter a
  password or touch the key). The feasibility gate ran *inline* for this reason — the user ran each
  privileged probe via `! bash …` and pasted output. Plan the implementation so hardware-in-the-loop
  steps are user-run; pure code/tests can be subagent-driven.
- Commit style: conventional commits, committed directly to `main` (this repo's established pattern
  for its design/docs history). Commit only when the work is a coherent unit; the user said commit
  as we go.
- The user makes the architecture calls — surface forks with a recommendation (AskUserQuestion),
  don't decide unilaterally. They chose: hybrid, no-root, softened dialog, capability-split option A.

## Key files

- `docs/design.md` — original synchronous v1 (superseded; kept for its threat model + review history)
- `docs/superpowers/specs/2026-07-16-cc-fido-gate-broker-design.md` — **the v2 spec (build this)**
- `docs/superpowers/plans/2026-07-16-broker-feasibility-gate.md` — the gate plan (done)
- `task0/REPORT.md` + `task0/probes/` — Task 0 findings + probes
- `task0-broker/REPORT.md` + `task0-broker/probes/` — broker gate findings + probes
- `README.md` — public framing
