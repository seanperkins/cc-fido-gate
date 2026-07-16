# cc-fido-gate — design

**Date:** 2026-07-16
**Status:** Revised after **three** full multi-model review rounds. R1 + R2 were unanimous
REVISE; **R3 came back 4 APPROVED / 1 REVISE**, and the lone REVISE (the lock-is-not-a-real-
security-boundary point) was independently *agreed* by two of the approvers as a wording fix +
future-hardening path, not a blocker — so the panel consensus is **implementable, with Task 0 as
the hard go/no-go gate.** This doc folds all R3 findings (tagged **[R3]**). The core guarantee
(no touch → no execution) survives every round; what's left is Task 0's platform facts and a set
of named must-fixes at policy-authoring/impl time.
**Prior art:** Switchyard supervised-sessions **phase 2** on `feat/affirmation-relay`
(`MobilityLabs/switchyard`, PR #194 / SYD-242) — **not on `main`**. Proven on a real key
2026-07-16. NB: the prior-art `src/services/ssh-verify.ts` calls **bare `ssh-keygen`** and
writes `allowed_signers` to an **agent-writable tmpdir** — a live example of exactly the
bypasses this design must not inherit (see Execution invariant, NEW-5).

---

## Review status & the load-bearing uncertainty

Two rounds, 2026-07-16, reviewers: codex, gemini, Claude fable/opus/pentester.
- **R1** (unanimous REVISE): four theater-grade holes — env scrubbing, canonical-doc binding,
  fail-open-on-timeout, no-touch keys. Fixed; tagged **[R1]**.
- **R2** (unanimous REVISE): called R1 "a massive step forward" but found deeper issues,
  several correcting the R1 fixes. Fixed; tagged **[R2]**.

**Verified true on this machine (credit):** `allowManagedHooksOnly` is a real key in the
Claude Code binary (v2.1.211); `/dev/fd/N` sign→verify works; stock `/usr/bin/ssh-keygen`
10.4p1 has a **fully root-owned** FIDO signing chain (via `/usr/libexec/ssh-sk-helper`) — no
Homebrew needed for sign or verify; PreToolUse hooks fire and a `deny` blocks even under
`--dangerously-skip-permissions` (so Task 0.2 is likely green).

**The finding that decides whether this is buildable at all (Task 0.1):** a PreToolUse hook can
block a tool *only* by exiting `2` (or a `deny` on clean exit `0`); **exit 1 is non-blocking,
and timeout-kill/crash behavior is undocumented and likely fail-open.** stdout is read only on
a clean exit — there is **no "emit deny then flip to allow"** channel (the R1 "deny-first"
mechanism was mechanically wrong). Fail-closed is therefore realizable only for what the hook
*itself* catches, via an **internal watchdog that exits `2` before the outer hook timeout**; an
external `pkill -9` mid-ceremony or a crash is intrinsically fail-open. The trigger needs zero
agent effort — the hook blocks ~seconds waiting for a touch that never comes. If Task 0.1 finds
timeout/kill → *proceed*, the synchronous in-hook model is **dead** and the async
park-then-affirm queue (Switchyard's model — `defer` is honored only in non-interactive `-p`
mode, so it can't be used interactively) is mandatory, not a fallback.

---

## The idea, in one paragraph

A `PreToolUse` hook is the enforcement surface. For a *gated* call it renders the exact effect,
asks an enrolled hardware key to sign a canonical document binding that call, verifies the
signature, and allows only on success. An agent can run `ssh-keygen -Y sign` freely but cannot
produce a valid signature: a security key requires a physical touch per signature and an agent
has no finger. The guarantee is enforced by the **token at signing time**, not the verifier
(`ssh-keygen -Y verify` cannot observe the touch — its four `ALLOWED SIGNERS` options assert no
presence). Presence is protected at **enrollment**, not verified after.

---

## Honest scope of the guarantee

> **A *recognized* gated action cannot proceed *synchronously* without a valid hardware
> signature from an enrolled, touch-required key — provided Task 0.1 (harness denies on
> hook kill/timeout) and enrollment (negative blink-test) both hold.**

Explicitly **not** covered:
1. **Unrecognized actions** (undecidable). Bash matching is **advisory** (naive-case only).
   The default-deny guarantee is the **structured-write tier** (Write/Edit/NotebookEdit) and
   **default-gated MCP** (below). Bash file-writes, and any spelling the advisory list misses,
   are out.
2. **Deferred/detached execution** — an un-gated `printf > ~/Library/LaunchAgents/x.plist`,
   cron, at, or git hook runs outside any hook. **This, combined with (1), is the *primary*
   adversary path**, and it is outside the guarantee by construction. Stated plainly so the
   reader isn't misled.
3. **Consent forgery on a shared display** (NEW-2, below) — cannot be fully closed on macOS.
4. **The host `root` user.**

MCP name-matching is **not "non-launderable"** [R2]: an agent-controlled MCP server can name a
destructive op benignly, and a verb-denylist leaks (this session's live surface includes
`create_payment`, `send_invoice`, `create_draft`, and hyphenated `delete-bill` that a
`(delete|…)_` regex never matches). So MCP gating is **default-gate + a small read-only
allowlist (get/list/search/read), scoped to trusted/managed servers** — not a destructive-verb
denylist.

---

## Task 0 — the feasibility gate (must pass before any implementation)

1. **Fail-closed reality.** (a) internal watchdog < outer timeout → hook exits `2` → blocked?
   (b) **the load-bearing one:** outer-timeout expiry, **agent-initiated `pkill -9 gate-hook`
   mid-ceremony**, and crash — does the tool get **denied or proceed**? If proceed, adopt the
   async model. Outer hook timeout default is **600s** (configurable), not 60s [R2].
2. **Hooks fire + `deny` blocks under `--dangerously-skip-permissions`.** (Docs say yes.)
3. **Managed hook is active, un-overridable, and no sibling can mutate input.** Confirm
   `allowManagedHooksOnly:true` suppresses **user, project, *and plugin*** PreToolUse hooks
   (not just deprioritizes), and that no permitted hook (SDK/managed/force-enabled-plugin) can
   return `updatedInput` in the same round — otherwise a last-writer-wins `updatedInput`
   **swaps the approved input after the gate signed it** (NEW-4). Confirm not superseded by
   MDM/remote policy.
4. **Interactive sign in the hook env** — a real `sk-` key blinks and blocks within the
   timeout; a `verify-required` PIN key works given **no controlling terminal** and scrubbed
   `SSH_ASKPASS*` (needs an explicit root-owned askpass or native PIN path, else PIN is
   unsupported).
5. **`osascript` survives the scrub** [R2] — determine the exact `env -i` allowlist that both
   renders a dialog (WindowServer needs `USER`, `HOME`, `__CF_USER_TEXT_ENCODING`, XPC) **and**
   still drops `DYLD_*`/`PATH`/injection vectors.
6. **What environment does Claude Code hand a PreToolUse hook, and can the agent influence it?**
   (NEW-6) — via `.claude/settings.json` `env`, direnv, launch profiles, etc. Per-Bash-call
   `export` does not persist into CC's process env; confirm nothing else does. Drives how hard
   the interpreter-launch hardening must be.
7. **Running-process integrity** [R3/pentester-New-A] — against the *shipped* binary while it
   executes a ceremony, a same-uid `lldb -p` / `task_for_pid` attach must **fail** (else the
   agent forces `exit 0`/`allow` with zero touches — a total bypass through none of the FIDO
   machinery). Mitigated on default macOS (developer mode off → `task_for_pid` is auth-gated),
   but this is a *developer's* machine, so the gate binary must ship **hardened-runtime, signed,
   `get-task-allow` disabled** (or setuid-root). Probe that attach fails — the runtime analogue
   of the install-time file-ownership canary.

Deliverable: a report answering all seven with actual commands and outputs. Only on seven green
does implementation start. **Note the asymmetry [R3/codex+opus-R3-B]: a `0.1(b)=proceed` result
is NOT a green — it *terminates* the interactive synchronous v1** (the async park-then-affirm
escape covers only headless `-p` mode, not the interactive product), and would require a
separately specified and re-reviewed async/broker architecture.

---

## Provenance of the "proven" claims

Reproduced with a **software** `ed25519` key against real `ssh-keygen` (OpenSSH **10.2p1–10.4p1**
— the exact patchlevel varies by which OpenSSH is installed on the target; the FIDO surface the
design needs is present across them, so don't hard-cite a single version as a verified fact):
headless stdin sign; verify; **tamper** rejection (255); wrong-namespace rejection; `-n`
mandatory; and `/dev/fd/N` transport — a reviewer confirmed `-Y verify` accepts a **non-seekable
pipe** fd for both signature and message, so the in-memory handoff is realizable. **Not**
reproducible here (don't cite as fact): hardware-touch blocking (Switchyard spike; link the
transcript) and in-hook behavior (Task 0.4).

---

## Architecture & components

Trust rests on OS permissions (**every path component root-owned**, NEW-5) + managed-settings
precedence + an **interpreter launched already-hardened** — not on the agent respecting config,
and not on the inherited environment.

| Component | Role | Privilege |
|---|---|---|
| launcher | **[R2]** Compiled, root-owned entrypoint invoked by the managed hook on an absolute path, with the interpreter **hardened at launch** (`bash --noprofile --norc` / ignore `BASH_ENV`; `python -E -I`) so no agent-influenced bootstrap runs before scrubbing (NEW-6). | root-owned, agent-exec-only |
| `gate-hook` | Ceremony; **exits `2` on any internal failure/watchdog**, emits `allow` only after verify. | root-owned |
| `policy.json` | Matchers + **exhaustive per-tool accepted-field allowlist** (deny any unrecognized field — you can't tell at runtime which are effect-bearing). | root-owned, agent-read-only |
| `signing-registry.json` | `fingerprint → principal → pubkey → private-handle path`. | root-owned, agent-read-only |
| `allowed_signers` | Enrolled hardware pubkeys, namespace-scoped, one install-fixed principal. | root-owned, agent-read-only |
| `enroll` CLI | Privileged, offline. **[R2] Negative blink-test** (below). Requires a **dedicated** `sk` key not usable for SSH auth (NEW-1/touch-theft); warns if the key is referenced in `~/.ssh/config`. Derives the pubkey from the private handle; exact-fingerprint match. | sudo |
| `install` CLI | Privileged. `managed-settings.d` drop-in (merge/refuse/rollback, warns it changes global behavior); registers hook + `allowManagedHooksOnly:true`; **verifies every ancestor dir of every control file + both binaries is root-owned, non-agent-writable** (NEW-5); e2e **canary** block-probe; refuses until ≥1 key enrolled. **Re-probe on Claude Code version change** (auto-update can silently flip semantics fail-open). | sudo |
| audit sink | `os_log`/syslog — **best-effort operational log**, tamper-*resistant* to deletion (needs root to erase) but **not authenticated** (a same-uid agent can forge/flood entries). | OS logging |

### Execution invariant [R1, hardened R2 — load-bearing]

Root-owning the script does nothing about what `ssh-keygen`/`osascript` resolve to, nor about
the interpreter's own startup. Required:
- **Absolute root-owned paths** for every helper (`/usr/bin/ssh-keygen`, `/usr/bin/osascript`,
  `/usr/bin/env`), and every ancestor directory root-owned/non-agent-writable (NEW-5).
- **Interpreter hardened at launch** (NEW-6) — not merely `env -i` in the body, which runs
  *after* `BASH_ENV`/`PYTHONPATH` bootstrap.
- **Allowlist-only** env scrub (a deny-list is a spec violation): keep only the Task-0.5
  WindowServer set; drop `SSH_SK_PROVIDER`, **`SSH_SK_HELPER`** [R2], `SSH_AUTH_SOCK`,
  `SSH_ASKPASS*`, `DYLD_*`, `LD_*`, `BASH_ENV`, `ENV`, `IFS`. Force the built-in FIDO provider.
- Signing handle from the root-owned registry.
- Unit test: hostile `PATH`/`SSH_SK_PROVIDER`/`SSH_SK_HELPER`/`BASH_ENV` still verifies via the
  real binary.

---

## The gate flow

```
tool call ─► PreToolUse ─► hardened launcher (scrub env) ─► gate-hook
  ├─ NOT gated?  exit 0 with NO decision (passthrough).                                   [R2-crit]
  │      Emitting "allow" here BYPASSES Claude Code's own prompts for every un-matched call —
  │      turning the gate into a global auto-approver that DELETES the user's soft gates.
  └─ gated:
       0. acquire the global ceremony lock — AFTER the gated-check (lock-before-check stalls    [R2-crit]
          every unrelated call host-wide during a pending touch). **The lock is a CORRECTNESS   [R3]
          mechanism, NOT a security boundary** — it prevents accidental concurrent arming and
          cross-satisfaction under honest conditions, but a same-uid agent can arm its OWN
          `ssh-keygen -Y sign` outside the lock (its signer never joins the gate's lock), and
          can even `kill` the gate's holder and stale-reclaim. That does not break the core
          guarantee (a stolen touch produces a signature the gate never accepts — the gate does
          its own internal ceremony per call and takes no external signature; the enrolled key
          handle is useless to the agent without a touch it cannot perform), but it means the
          real anti-touch-redirection guarantee is **challenge-binding + WYSIWYS display
          integrity, bounded by the conceded display-spoofing residual (NEW-2)** — not the lock.
          Use flock(2)/fcntl (macOS has no flock(1)); the kernel releases the lock on process
          death, so **do not** hand-roll PID/kill(pid,0) recovery (redundant, adds TOCTOU, and
          `kill(pid,0)` on a reused/foreign PID returns EPERM which misreads as "alive"). **The
          lock file/dir is itself a control path** [R3/fable] — root-owned in an
          ancestor-checked location, else the agent `unlink`s and recreates it to defeat the
          lock. (Ancestor + writability checks cover key handles, the lock, and spool dirs too.)
          *Robust upgrade (recorded, not v1): a privileged signing broker* that exclusively
          holds the key handle and serializes signing internally would make single-armed-signer
          a true boundary AND close the pkill-fail-open (Task 0.1) and audit-authenticity gaps
          at once — the natural v2 direction if Task 0.1 forces a rethink.
       1. from ONE validated internal object (derived from Claude Code's own tool_input
          serialization — no second raw re-parse; reject duplicate keys) derive:               [R2/NEW-9]
            • execution_input  — the untouched input CC will run (never NFC-normalized)
            • signed_document  — canonical bytes binding execution_input + cwd + context
            • human_rendering  — deterministic, escaped; a human-READABLE effect summary
              (path, size, diff-stat — NOT a bare SHA), or a read-only spool-file path to inspect
       2. arm signer AND render, concurrently, each in its OWN process group:
            • /usr/bin/ssh-keygen -Y sign -f <handle> -n cc-fido-gate@<domain>
            • /usr/bin/osascript   (human_rendering passed as ARGV, never interpolated)
          Cancel WINS over an already-emitted signature; watchdog (< outer timeout) reaps the
          CHILDREN's groups and makes the hook exit 2.
       3. /usr/bin/ssh-keygen -Y verify -I <principal> -n cc-fido-gate@<domain> -s <sig /dev/fd/N>
          message = signed_document bytes from memory/stdin (never a tmpfile — TOCTOU).
          (Task 0: confirm -Y verify accepts a non-seekable pipe fd; if not, fail CLOSED.)     [NEW-8]
       4. verified? emit allow on clean exit 0.  else exit 2.  log (best-effort).
```

### Canonical document / three artifacts [R2]

Do **not** claim byte-equality across all three. Invariants: all derive from the one validated
object; `human_rendering` == displayed bytes (WYSIWYS); `signed_document` uniquely determines
`execution_input`; **and `execution_input → human_rendering` must be injective** [R3/pentester-New-B]
— else two different inputs render identically and the human signs the malicious one while
reading the benign one. "Reject invalid Unicode" does **not** catch *valid* confusables
(zero-width joiners/spaces, bidi overrides, homoglyph path components — `/Users/sean/.zshrc` vs
a Cyrillic-`е` twin — trailing whitespace/newlines): the renderer must **escape non-ASCII /
zero-width / bidi and surface a disambiguator** (byte length + a short hash of `execution_input`
beside the readable summary), with golden fixtures for each confusable class. **WYSIWYS holds
literally only when full content is rendered**; for digest-bound large writes the human approves
"this path + this hash + this diff-stat" — a weaker, explicitly-stated property. Enumerate what
`context` binds and confirm no component is agent-mutable between sign and execution. `signed_document` is byte-level canonical (UTF-8, recursive
key sort, defined array/number/newline rules, reject invalid Unicode **and duplicate keys**),
pinned by golden-byte fixtures, and binds **`cwd`** (relative Bash meaning). Namespace
**`cc-fido-gate@<domain>`** (OpenSSH recommends domain-qualified). Replay is a non-issue
(one-invocation, never stored). **`NotebookEdit`** must be fully specified (schema + rendering)
or dropped from the gated tier — otherwise "unknown tool → deny" denies it permanently.

---

## Gating config (`policy.json`)

```json
{
  "rules": [
    { "tool": "Bash", "advisory_command_matches": ["git push .*(--force|--force-with-lease|-f)\\b", "\\brm\\b.*-[rf]", "npm run deploy", "\\bkubectl\\b.*\\bdelete\\b"] },
    { "tool": ["Write", "Edit", "NotebookEdit"], "write_default": "gate", "allow_tier": ["<enrolled worktrees pass through — but sensitive globs win, see below>"] },
    { "mcp": { "trusted_servers_only": true, "default": "gate", "read_only_allowlist": ["<explicit operator-reviewed (server,tool) identities — NOT prefix-only>"] } }
  ],
  "rule_precedence": "sensitive gate globs are evaluated BEFORE allow_tier",
  "path_match": "nearest_existing_ancestor_then_lexical_suffix",
  "fail": "closed"
}
```

- **allow_tier precedence** [R3/opus-R3-A]: a sensitive gate glob (`**/.env*`, ssh/secret
  paths) **wins over** `allow_tier`. Otherwise `<worktree>/.env` — a `.env` at the repo root,
  *inside* the enrolled worktree — is silently un-gated, re-opening exactly the create-new-`.env`
  case the path-match hardening exists to catch. `allow_tier` applies only to paths that match
  **no** sensitive glob (and that secret-glob list must be treated as exhaustive-enough for the
  guarantee). The ceremony budget failing over must **deny/retain gating, never** silently enter
  the allow tier.
- **MCP allowlist is explicit `(server,tool)` identities** [R3/codex+fable], operator-reviewed,
  not a `get_*`/`read_*` prefix (a trusted server can still name a mutator `get_or_create_x`;
  "trusted server" attests provenance, not tool semantics). Prefixes may *generate candidates*;
  they don't grant exemptions.

- **Bash = advisory only.** No Bash is hard-gated; so the "expansion/`eval` gated-or-denied"
  idea is scoped out for Bash (you can't render post-expansion effect without executing) — F is
  simply **out-of-scope for Bash**, consistent with the honest carve-out [R2/pentester-F].
- **Write allow-tier + ceremony budget** [R2]: coding sessions do hundreds of writes; gating
  *every* write manufactures touch-fatigue that destroys the consent the crypto certifies.
  Writes under enrolled project worktrees pass through; only the sensitive set is gated, tuned
  to a stated ceremonies-per-hour budget.
- **MCP inverted to default-gate** + read-only allowlist, trusted servers only (NEW-7).
- **Path match** resolves the **nearest existing ancestor + lexical suffix** — macOS
  `/bin/realpath` errors on a not-yet-existing target and has no `-m`, so naive `realpath` would
  fail to match a Write that *creates* `.env` (the security-relevant case) [R2/NEW-1]. Note the
  check→execute symlink-swap TOCTOU: path conclusions are advisory against a concurrent
  attacker (content digests are not).

---

## Threat model

### A — agent disables the gate
Managed hook + `allowManagedHooksOnly:true` (Task 0.3 must confirm plugin-scope + no-sibling-
`updatedInput`); root-owned read-only files **with every ancestor root-owned** (NEW-5);
hardened interpreter launch + absolute paths + allowlist scrub; negative-blink-tested,
dedicated-key enrollment; gate gates its own control files. Residual: `root` (floor).

### B — unrecognized action
Undecidable. `write_default:gate` + advisory Bash + default-gate MCP + honest scope.
Deferred/detached exec is *out* (the primary adversary path — named).

### C — consent forgery (the crux weakness of a WYSIWYS gate on a shared display)
- **AppleScript injection** → argv-not-source + WYSIWYS test. (Closed.)
- **Touch-redirection** (NEW-1) → the global lock as a death-proven single-armed-signer
  boundary; **dedicated key** so the agent can't harvest a touch via its own `ssh` auth blink.
- **Display spoofing** (NEW-2) → an agent that co-owns the display can `screencapture` and clone
  the dialog, front-run a decoy timed to a real signer arming, and steal the touch. **Cannot be
  fully closed on macOS** (no non-root trusted-path UI). Named as a residual; mitigated only by
  low prompt frequency (the allow-tier/budget) and action-specific readable content — accepting
  the agent can mimic it. This + NEW-1 is the most realistic end-to-end bypass.

### PIN vs presence
Presence default. no-touch-required `sk` keys sign with no finger and still verify, so the
**negative blink-test** is the guarantee: arm the signer, instruct **withhold** touch, require
signing does **not** complete within a window, *then* touch and require completion (the
**positive control** — so a never-signing/broken key can't pass the negative phase vacuously)
[R3/pentester-New-D]. A positive-only "did you touch?" cannot distinguish (a no-touch key
accepts a touch too) [R2, grounded on the prior art's `affirmation-keys.ts:25`]. Key-type check only proves hardware-backed. PIN keys
experimental pending Task 0.4 (needs a root-owned askpass, not the scrubbed inherited one).

---

## Recovery / degraded env

2+ dedicated keys under one install-fixed principal; each in the registry. Lose all → sudo
re-enroll. Command hooks have **no controlling terminal**, so there is **no `/dev/tty`
fallback** [R2] — render is **GUI → deny**, making v1 a **local-desktop** tool; headless/SSH
gating requires the async model.

---

## Testing

Env-hygiene (hostile `PATH`/`SSH_SK_PROVIDER`/`SSH_SK_HELPER`/`BASH_ENV` still verifies via the
real binary); crypto plumbing (green); three-artifact canonicalization (golden fixtures, nested
MCP, `signed_document`→`execution_input`, duplicate-key rejection, unknown-field→deny,
NotebookEdit specified-or-absent); WYSIWYS (full-content == displayed; digest mode =
path+hash+diffstat); **negative blink-test** (withhold→must block); enroll (dedicated-key,
pubkey-from-handle, two-keys-one-principal, TOCTOU-safe); policy (`write_default:gate` +
allow-tier; **Write-creates-new-file under a gated glob**; nearest-ancestor realpath; symlink
TOCTOU; default-gate MCP incl. hyphenated names; passthrough triggers the normal prompt);
lock (death-proven recovery, single-armed-signer, touch-then-Cancel→deny); Task-0 harness
(watchdog-exit-2 blocks; **agent `pkill` + timeout + crash characterized**; bypass-mode;
managed+plugin precedence; no-sibling-updatedInput; concurrent serialization; osascript
survives scrub; hook env influenceability); install (canary probe, ancestor-ownership check,
version-change re-probe); not-automatable: that a touch happened.

---

## Out of scope (v1)

Non-macOS + headless/SSH gating (async model); WebAuthn/passkeys; push transport;
session-unlock windows; per-project policy; security-grade authenticated audit; defending host
`root`, deferred/detached execution, and shared-display consent-spoofing (NEW-2) — explicit
non-goals, documented so the gate isn't over-trusted.
