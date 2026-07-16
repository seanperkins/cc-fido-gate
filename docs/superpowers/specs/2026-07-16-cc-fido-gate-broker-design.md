# cc-fido-gate v2 — broker + file-custody design

**Date:** 2026-07-16
**Status:** Design approved in brainstorming; broker feasibility gate in progress
([`task0-broker/REPORT.md`](../../../task0-broker/REPORT.md)). **Gate Q1 already forced one revision:
the ceremony is capability-split** (client signs, daemon verifies+writes) because a system
LaunchDaemon can't reach the USB key. Section 1 reflects it.
**Supersedes the enforcement model of** [`docs/design.md`](../../design.md) (the synchronous
in-hook v1), which [Task 0](../../../task0/REPORT.md) proved cannot deliver its guarantee.
**Builds on:** [`task0/REPORT.md`](../../../task0/REPORT.md) — every platform fact cited here (0.1–0.7)
comes from that spike.

---

## Why v2 exists

Task 0.1 answered the make-or-break question empirically: **Claude Code fails open when a
PreToolUse hook dies.** A hook that returns `exit 2` blocks the tool (0.1a ✅), but if the hook
crashes, is `kill -9`'d mid-ceremony, or its outer timeout expires, **CC runs the tool anyway**
(0.1b, deterministic 3/3). That fail-open lives in CC's harness, not in our code — we cannot change
it. A same-uid agent can launch a background killer via an un-gated Bash call and `pkill` the
gate-hook, so **no hook-based design can hard-guarantee against a determined same-uid agent.**

The synchronous in-hook v1 is therefore dead as a *guaranteed* design. v2 keeps the useful hook as
an honest best-effort layer and adds a second layer whose guarantee does **not** depend on any hook.

## What v2 guarantees

A **hybrid** of two equal partners driven by one FIDO key:

1. **Crown-jewel file-custody (hard guarantee).** A configurable set of sensitive files is made
   **un-writable by the agent-uid at the kernel level**. There is no hook in the enforcement path,
   so 0.1b is irrelevant: the files stay locked even if the gate is disabled, killed, or never ran.
   The only way to modify them is a broker request that requires a physical touch.
2. **Best-effort touch-gate (broad).** The `PreToolUse` hook still gates the broad advisory set
   (Write/Edit tiers, MCP, advisory Bash). It raises the bar and catches mistakes and
   non-adversarial agents, but is **defeatable by a same-uid agent** (0.1b) — stated honestly.

> **Guarantee, precisely:** *An enrolled crown-jewel **file** cannot be modified, deleted, or
> renamed without a physical touch of an enrolled key; and no file can be **created** inside an
> enrolled crown-jewel **directory** without one — both enforced by filesystem permissions and the
> `uchg` immutable flag, independent of any hook. All other gated actions get a best-effort touch
> prompt that a determined same-uid agent can bypass.*

The **file** vs **directory** distinction is load-bearing: `uchg` on a leaf file stops
modify/delete/rename of *that file* but cannot stop creation of a *new* sensitive file (a fresh
`.env`, a new `~/Library/LaunchAgents/x.plist`). Preventing creation requires **directory custody**
(the containing dir owned by `_ccfido`, non-agent-writable). See Section 2.

## Privilege model — no runtime root

To make a file the agent-uid can't write, it must be owned by a principal the agent isn't. On a
single-user Mac the agent is `sean`, so that principal is a **dedicated unprivileged service
account, `_ccfido`** — not root.

- The broker **runs as `_ccfido`**, never root.
- Crown-jewel files are **owned by `_ccfido`**, plus the **user-immutable flag `uchg`** (togglable
  by the *owner* — no root at runtime, unlike `schg`).
- **`sudo` is required only for one-time setup:** create `_ccfido`, `chown` enrolled files to it
  (giving away ownership is the sole root-only step), install the LaunchDaemon and the root-owned
  `managed-settings.json`. After install, nothing runs as root and you never `sudo` again except to
  enroll a new file or key.

The only fully zero-privilege alternative is best-effort-only (no crown-jewel guarantee); it was
considered and rejected — the kernel lock is the point.

### Consequence of no-root: softened dialog (accepted)

On macOS, only **root** (`launchctl asuser`) or **you** can draw UI into your GUI session. A
non-root `_ccfido` daemon cannot (it lives outside the session — the `-10810`/no-WindowServer wall
seen under sandbox in 0.5). So the WYSIWYS dialog is rendered by the **user-session client**, which
runs as you and is therefore agent-influenceable.

- **Core guarantee — untouched.** "No crown-jewel write without a touch" rests on the kernel lock,
  not the dialog.
- **WYSIWYS — softened.** "You see the exact bytes" degrades to the **display-spoofing residual
  `design.md` already conceded** (NEW-2): a same-uid agent can draw a benign decoy to harvest a
  touch. Bounded by low crown-jewel frequency and the fact that they are your files.
- **Signing runs in the console session (broker-gate Q1).** Because the daemon can't reach USB, the
  signer runs client-side, so the `sk` **handle is readable by the agent uid** → the agent can
  *arm/blink* the key (not sign). This re-opens the **touch-redirection residual** (NEW-1) that the
  daemon-exclusive-arming upgrade would have closed. Core guarantee (no write without a touch)
  unaffected — the touch is still physical and the signature is challenge-bound.
- **A tiny setuid-root helper (signer + trusted-path dialog) would close both NEW-1 and NEW-2** but
  reintroduces a root attack surface; **declined in favor of zero runtime root**, parked as a
  hardening upgrade (Out of scope).

---

## Section 1 — The broker, capability-split (unprivileged)

**Why split (broker-gate Q1 finding):** a system LaunchDaemon **cannot reach the USB FIDO device** —
`ssh-keygen -Y sign` from the daemon returns `device not found`, while the same sign in the console
session succeeds. USB HID access requires the login session. So the ceremony splits by *capability*:
the **console-session client** does the USB + GUI steps (arm, sign, dialog); the **daemon** does the
privileged, USB-free steps (issue challenge, verify, own files, `uchg`-toggle + write, audit).
`ssh-keygen -Y verify` needs no USB, which is what makes the split work.

- **Daemon:** a LaunchDaemon with `UserName=_ccfido`. Binary at a root-owned absolute path (agent
  can't modify it) but **executes unprivileged**; **hardened-runtime signed** so a same-uid agent
  can't `task_for_pid`/attach even if developer mode is on (0.7). Holds `allowed_signers` (the
  enrolled **pubkey**) for verification and owns the crown-jewel files + audit log.
- **Key handle custody:** the `sk` **handle must be readable by the console-session signer** (the
  client runs as the login user, so the handle is group-readable to it — not `_ccfido`-`0600`).
  **Consequence:** the agent uid can *arm* (blink) the enrolled key, but **cannot sign** without a
  physical touch, and any signature it could coax is bound to the daemon's challenge. This means
  **single-armed-signer is NOT a boundary here** (that was a *recorded* v2 upgrade in `design.md`,
  not a v1 requirement); the anti-redirection story is **challenge-binding + the conceded
  display-spoof residual**. Closing it needs the parked setuid-root signer (Out of scope).
- **Interface:** one unix domain socket at a `_ccfido`-owned path. **Authorization is by touch,
  never by caller identity** — any local caller may request; none can satisfy without a finger.
  `LOCAL_PEERCRED` records caller uid/pid for the audit log only. Two operations:
  - `execute-write {path, content}` → the hard-guarantee partner (daemon performs the write).
  - `approve {tool, input, cwd}` → the best-effort partner (daemon returns a verdict).
- **Ceremony (shared):**
  1. **Daemon** validates + canonicalizes the request and derives the `challenge` (the canonical
     `signed_document` binding path+content+context) and the `human_rendering` (escaped,
     confusable-safe, byte-length + short hash — `design.md`'s WYSIWYS rules).
  2. Daemon returns `challenge` + `human_rendering` to the **console-session client**.
  3. **Client** draws the dialog **and** arms the signer (`/usr/bin/ssh-keygen -Y sign` over the
     `challenge`, root-owned `ssh-sk-helper`) → the key blinks → **touch** → client returns the
     signature. Cancel/withhold/timeout → client reports abort.
  4. **Daemon verifies** the signature is over exactly its `challenge` (`ssh-keygen -Y verify`,
     non-seekable `/dev/fd` transport — 0.4/NEW-8; **no USB needed**) → on success it acts (writes,
     or returns `allow`); else `deny`. A daemon-side watchdog bounds the wait.
  5. Append to the **`_ccfido`-owned authenticated audit log** (agent can't forge/flood — a real
     improvement over `design.md`'s best-effort syslog).
- **Serialization:** one global ceremony at a time (flock/internal). Kernel releases on death; no
  hand-rolled PID recovery.
- **Operational note (0.4):** a hard-killed ceremony can leave the FIDO device transiently
  `device not found`; the *next* arm must tolerate a short retry/backoff.

## Section 2 — File-custody (hard-guarantee partner)

- **File custody** — `sudo cc-fido enroll-file <path>`: `chown` to `_ccfido`; set mode (`0600`
  full-lock or `0644` read-allowed — **per-file policy**); set **`uchg`**; record in the
  `_ccfido`-owned policy. The agent then can't write (perms), can't delete/rename (immutable blocks
  unlink even though it owns the parent dir), can't clear the flag (not the owner). Protects
  *existing* files against modify/delete/rename. **Kernel-enforced, no hook, no runtime root.**
- **Directory custody** — `sudo cc-fido enroll-dir <path>`: `chown` the directory to `_ccfido`,
  mode that denies agent-uid create/unlink. This is what stops *creation* of new sensitive files
  (the deferred-exec path). Used for directories legit tooling doesn't routinely write —
  `~/Library/LaunchAgents`, the crontab spool, `.git/hooks`. **Caveat:** do *not* dir-custody
  directories a legit tool writes on its own (e.g. `~/.ssh`, where `ssh` rewrites `known_hosts`) —
  those get file-custody on the specific dangerous files instead. Creating a legit new file in a
  custodied dir goes through `cc-fido write` (touch).
- **Default enrolled set (configurable):** dir-custody for the design's named *primary adversary
  path* — `~/Library/LaunchAgents`, per-user crontab, `.git/hooks` — plus file-custody opt-ins:
  `.env*`, specific `~/.ssh/*` keys + `authorized_keys`, credential files. Together these close
  deferred/detached execution *and* tampering with existing secrets.
- **Legit writes go through the broker.** Target is locked, so Claude calls `cc-fido write <path>`
  (Bash call; content on stdin) → broker renders the diff → touch → broker (`_ccfido`, the owner)
  does `nouchg → write → fsync → uchg` (for a custodied dir it creates the file directly) → logs.
- **Hook does double duty:** a *direct* `Write`/`Edit` to a locked path is **denied with a nudge**
  ("FIDO-locked; use `cc-fido write`"). That denial is only UX — a bypassed hook still yields
  `EACCES`. **The kernel is the backstop; the hook is courtesy.**
- **Documented edge:** `uchg` protects the leaf file's write/unlink/rename; exotic
  ancestor-directory / symlink games in an agent-owned parent are a known residual (enroll-time
  checks warn; full path-integrity is a hardening follow-on).

## Section 3 — Best-effort hook (broad partner)

- **Installed un-disableably (one-time sudo):** a root-owned `managed-settings.json` +
  `allowManagedHooksOnly:true`. 0.3 confirmed this *suppresses* user/project hooks, so the agent
  can't add a sibling or disable it by editing `settings.json`. (A root-owned config file, not a
  running root process — consistent with no runtime root.)
- **Thin client of the broker.** Launches hardened (near-empty env per 0.5/0.6: scrub
  `NODE_OPTIONS`/`PATH`/`DYLD_*`/`SSH_*`, absolute paths), then:
  - **Not gated →** `exit 0`, no decision (passthrough) — preserves CC's own prompts; never a
    blanket auto-approve (`[R2-crit]`).
  - **Gated →** `approve` op; daemon returns `challenge` + `human_rendering`; hook draws the dialog
    (softened WYSIWYS) **and** arms+signs the challenge; daemon verifies → verdict → `allow` /
    `exit 2`.
  - **Direct write to a locked path →** deny-with-nudge (Section 2).
- **Gated tiers** (`_ccfido`-owned policy, unchanged from `design.md`): Write/Edit/NotebookEdit
  default-gate with an allow-tier for enrolled worktrees where **sensitive globs win**; **advisory**
  Bash danger-list; **default-gate MCP** + a small read-only `(server,tool)` allowlist.
- **Honestly best-effort:** the hook's watchdog (`exit 2` before outer timeout) fails closed for
  catchable failures (0.1a), but **0.1b stands** — a same-uid agent that kills the hook makes CC
  proceed. Managed-settings stops *disabling*; nothing stops *killing*. Crown jewels carry the load
  for anything that truly must not happen.

## Section 4 — Enroll / install + broker feasibility gate

**Three privileged CLIs, all one-time `sudo`:**
- `cc-fido install` — create `_ccfido`; install the LaunchDaemon; drop root-owned
  `managed-settings.json` + hook; verify every control-file ancestor is `_ccfido`/root-owned and
  non-agent-writable; run an **e2e canary** (a known gated call is actually blocked); refuse until
  ≥1 key enrolled; **re-probe on CC version change**.
- `cc-fido enroll` — dedicated `sk-` key(s); **negative blink-test** (validated in 0.4); ≥2 keys
  under one principal for recovery.
- `cc-fido enroll-file` / `cc-fido enroll-dir` — Section 2's file- and directory-custody locks.

**Broker feasibility gate — v2's mini-Task-0 (must pass before implementation).** Task 0 ran as
*you* in the GUI session; the broker moves work to a non-console `_ccfido` daemon, which opens fresh
unknowns:
1. **Daemon USB access (load-bearing):** can a LaunchDaemon as `_ccfido` (no GUI session) drive
   `ssh-keygen -Y sign` against the YubiKey — arm the blink and block for a touch? IOKit/TCC HID
   access from a non-console daemon was **not** proven by 0.4 (which ran as `sean`). If it fails,
   signing must move to the user-session client (reintroducing key-handle exposure) — so this gates
   the architecture.
2. **Cross-process touch binding:** the daemon arms the signer, a separate user-session client shows
   the dialog; confirm the physical touch completes the daemon's armed sign.
3. **`uchg` on APFS (load-bearing):** confirm a `_ccfido`-owned `uchg` file resists `sean`'s
   unlink/rename/write while `sean` owns the parent dir.
4. **Socket:** `sean`↔`_ccfido` unix-socket reachability + `LOCAL_PEERCRED`.

Deliverable, like Task 0: actual commands + outputs; all green before implementation.

## Section 5 — Threat model & testing

**Threat model (deltas from `design.md`):**
- **A — disable the gate:** best-effort hook can't be *disabled* (managed-settings, 0.3) but can be
  *killed* (0.1b) → best-effort. Crown jewels: kernel lock, unbypassable even if the whole gate is
  killed/removed. Residual floor shifts from `root` to **`_ccfido` account compromise** (a new asset
  to protect: its login/keychain/handle files).
- **B — unrecognized action:** crown-jewel lock **closes** the primary deferred/detached path
  (LaunchAgents/cron/git-hooks locked); everything else stays advisory.
- **C — consent forgery:** two residuals *leaned on*, both already conceded in `design.md` and both
  closeable only by the parked setuid-root helper — (NEW-2) display-spoof, no trusted-path dialog
  without root; (NEW-1) touch-redirection, since the console-session signer exposes the handle so
  the agent can arm the key. Bounded by low crown-jewel frequency, challenge-binding (a coaxed touch
  signs the daemon's specific write, not an arbitrary one), and a dedicated key (useless elsewhere).
- **New:** broker socket abuse (mitigated: touch-not-identity auth); `_ccfido` compromise; `uchg`
  ancestor/symlink edge.

**Testing:**
- Broker ceremony: arm / verify / serialize; watchdog `exit 2`; device-busy-after-kill retry.
- **File-lock enforcement:** direct write → `EACCES`; unlink blocked; `nouchg` blocked for `sean`;
  broker write succeeds; per-file read policy (`0600` vs `0644`).
- **Dir-lock enforcement:** agent-uid create/unlink inside a custodied dir → `EACCES`; broker
  creates on request; legit-writer caveat (a file-custody-only dir like `~/.ssh` still lets `ssh`
  write `known_hosts`).
- enroll-file / enroll-dir idempotence + rollback; ancestor-ownership checks.
- Negative blink-test (withhold → no sig; touch → signs; stock verifier).
- Hook tiers: passthrough / gate / deny-nudge / advisory Bash / default-gate MCP incl. hyphenated
  names; passthrough triggers CC's normal prompt.
- Install canary + CC-version re-probe.
- The feasibility-gate probes become regression tests.

---

## Out of scope (this spec) — future custody backends

The crown-jewel *set* is configurable; the *custody mechanism* per resource is pluggable. v2 ships
the **file/directory-custody** backend only (alongside both partners — the broker and the
best-effort hook). Designed-for-later, each its own spec:
- **Credential-custody** — broker holds ssh keys / npm tokens / kubeconfig so `git push --force` /
  `npm publish` / `kubectl` need a touch. Lock = credential possession, not file perms.
- **MCP-proxy custody** — broker holds server tokens and mediates mutating MCP calls.
- **Setuid-root signer + trusted-path dialog** — one narrow setuid-root helper that keeps the `sk`
  handle root-secret (restoring single-armed-signer, closing NEW-1) *and* renders the dialog via
  `launchctl asuser` (restoring trusted-path, closing NEW-2). Declined for v2 to keep zero runtime
  root; the upgrade if the softened posture proves inadequate.

Also out (unchanged from `design.md`): non-macOS; headless/SSH gating; WebAuthn/passkeys; defending
the `_ccfido` account itself against a local root attacker.
