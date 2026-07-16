# cc-fido-gate — design

**Date:** 2026-07-16
**Status:** Approved (brainstorm complete); implementation not started
**Prior art / spike this generalizes:**
Switchyard's supervised-sessions phase 2 — the signed-affirmation gate for issue
`done`-stamps (`ssh-keygen -Y sign` over a canonical action doc, verified server-side).
That spike proved end-to-end on real hardware on 2026-07-16; this project lifts the
primitive out of Switchyard into a standalone, server-less Claude Code plugin.

## The idea, in one paragraph

A `PreToolUse` hook is the entire enforcement surface. Before Claude Code runs any tool,
the hook decides whether that specific call is *gated*. For a gated call it renders the
exact command to the human, asks an enrolled hardware key to sign a canonical document of
that call, and verifies the signature — allowing the call only on success. An agent can
run the hook's `ssh-keygen -Y sign` as often as it likes and still cannot produce a valid
signature, because a security key requires a physical touch (and optionally a PIN) for
every signature, and an agent has no finger. Presence is proven by the one thing the agent
structurally cannot do.

This is the same inversion Switchyard's design documented: the guarantee is enforced by
the **token at signing time**, not by the verifier. The server (here, the hook) verifies a
valid signature from an enrolled key in the right namespace; it cannot itself observe the
touch. The hardware-key-type check at enrollment is the only server-side hardware
guarantee.

## Proven vs. unproven

**Proven** (real `ssh-keygen` 10.4p1, headless, no TTY — run during brainstorming):

- Signing a canonical doc from stdin with `-n cc-fido-gate` works with no controlling terminal.
- `ssh-keygen -Y verify` against a namespace-scoped `allowed_signers` line succeeds.
- A signature over one action **fails** to verify against a different action — replay/tamper
  protection is *structural*, falling out of "verify by re-deriving the same bytes," not a
  check we implement.
- A signature in the wrong namespace fails.

**Unproven — the one gating risk, to spike first (see Task 1):** that a Claude Code
`PreToolUse` hook can run an *interactive* `ssh-keygen -Y sign`, surface the touch prompt,
and block on the physical touch within the hook timeout. This depends on Claude Code's hook
execution model (TTY availability, timeout ceiling, whether a subprocess GUI dialog works
mid-hook). If it behaves badly, the UX falls back to deny-with-challenge + a separate
`affirm` terminal (Switchyard's async park-then-affirm model). Everything else is low-risk.

## Architecture & components

Trust rests on OS permissions + Claude Code managed-settings precedence — **not** on the
agent choosing to respect a config file.

| Component | Role | Location |
|---|---|---|
| `gate-hook` | The `PreToolUse` script. Reads `{tool_name, tool_input}` on stdin; gated → run ceremony; returns `allow`/`deny`. | root-owned |
| `policy.json` | The gated-set definition (matchers). | root-owned, agent-read-only |
| `allowed_signers` | Enrolled hardware public keys, namespace-scoped. Written only by `enroll`. | root-owned |
| `enroll` CLI | Privileged, offline. Adds an `sk-*@openssh.com` public key; **rejects software keys**. | run with sudo |
| `install` CLI | Privileged. Places files above root-owned; registers the hook in `managed-settings.json`. | run with sudo |
| audit log | Append-only record of every decision (allow-with-sig / deny). Tamper-evident. | root-owned |

## The gate flow (per-call, action-bound)

```
tool call ─► PreToolUse ─► gate-hook
  ├─ not gated?  exit 0  (normal flow, ~instant)
  └─ gated:
       1. canonicalize the call → {v, tool, action, cwd, ts}   (sorted keys)
       2. RENDER via a native macOS dialog (osascript):
            "Claude wants to run:  git push --force origin main
             Touch your key to approve, or Cancel to deny."
       3. pipe canonical bytes to  ssh-keygen -Y sign -f <key> -n cc-fido-gate
            → the key blinks; human touches (or enters PIN if verify-required)
       4. ssh-keygen -Y verify against root-owned allowed_signers
       5. verified → permissionDecision:"allow"; cancelled/timeout/bad → "deny" + reason
```

- **The renderer is a native GUI dialog, not terminal text.** The dialog is not
  agent-controlled, and it shows the human exactly what they are touching for — this
  addresses the "trusted renderer" risk (the CLI renderer that the human must be able to
  believe). The physical key-blink is the un-spoofable presence signal.
- **Replay is a non-issue here** — simpler than Switchyard. Switchyard parks an action and
  affirms it later, so it needs TTL + freshness. This plugin signs and verifies *in the
  same hook invocation*: the signature is produced and consumed inline, never stored. The
  structural tamper-rejection means a signature can only ever authorize the exact bytes
  rendered. A timestamp is included for the audit log, not for replay defense.

### Canonical document

Deterministic serialization (`JSON.stringify` over `Object.keys(doc).sort()`), one `v`
field for migration, absent optional fields omitted (never `null`), NFC-normalized:

```json
{"v":1,"tool":"Bash","action":"git push --force origin main","cwd":"/Users/sean/x","ts":1784180000}
```

Namespace `-n cc-fido-gate` prevents a signature solicited here being replayable in another
domain of use (e.g. a git commit signature).

## Gating config (`policy.json`)

Matchers gate on the **effect surface** wherever possible (a path-write glob catches every
command that writes there, regardless of how the command is spelled):

```json
{
  "rules": [
    { "tool": "Bash", "command_matches": ["git push .*--force", "rm -rf ", "npm run deploy", "\\bkubectl .*delete"] },
    { "tool": "Write", "path_globs": ["**/.env*", "infra/**", "**/managed-settings.json"] },
    { "tool": "Edit",  "path_globs": ["**/.env*", "infra/**"] },
    { "mcp_tool": "mcp__.*__(delete|drop|deploy)_.*" }
  ],
  "fail": "closed"
}
```

Ships with a conservative default danger-list. `fail:"closed"` means any error — `ssh-keygen`
missing, no keys enrolled, malformed policy — results in **deny**, never a soft-allow (a
verifier that fails open is worse than no verifier). The policy also implicitly protects its
own files, `allowed_signers`, and `managed-settings.json` (note the glob) as
defense-in-depth on top of the OS permissions.

## Threat model

Two distinct threats with very different answers.

### Threat A — the agent disables the gate itself
Edits the config to drop a pattern, unregisters the hook, rewrites the hook script, or
enrolls a software key it controls. **Fully addressed:**

1. **Hook registered in Claude Code *managed settings*** (`/Library/Application
   Support/ClaudeCode/managed-settings.json` on macOS) — the enterprise-policy tier, which
   outranks user and project settings and cannot be overridden or disabled from `~/.claude`
   or `.claude/`.
2. **Policy, hook script, and `allowed_signers` are root-owned**, agent-user-unwritable.
   Bypass is not a pattern-matching problem — the OS denies the write, so no `sed` / `python
   -c` / redirect trick helps.
3. **Enrollment is a privileged, offline step**, so the agent cannot add a key whose private
   half it holds (a software key would sign with no touch — the cleanest bypass, closed by
   the `sk-*`-only enrollment check).
4. **The gate treats its own control files as gated paths** — tampering is at minimum
   tamper-evident even if a file were left writable.

Residual: someone with `root` can still edit managed settings. That is the intended
boundary — the gate defends against the *agent*, not the *host owner*.

### Threat B — the agent crafts an action the matcher does not recognize
Obfuscates a destructive command past the danger-list. **Not fully solvable** — inspecting
an arbitrary shell string for "is this dangerous" is undecidable in general. Mitigations:
gate on the effect surface (path-write globs beat command-string parsing), keep matchers
conservative, lean on default-deny for the most destructive tier. Honest guarantee: *a
**recognized** dangerous action cannot proceed without a touch* — not *nothing dangerous
ever slips through*.

## User verification (PIN) vs. presence (touch)

v1 requires **presence** (a touch), which every `sk-*` key enforces by default and which
needs no terminal I/O inside the hook. Keys generated `-O verify-required` additionally
demand a PIN/fingerprint; the plugin supports them transparently (the token prompts), but
does not *require* UV in v1 — because, per the Switchyard correction, the verifier
**cannot** prove UV occurred anyway (`ssh-keygen -Y verify` has no UV check). Copy rule:
never promise "fingerprint/biometric" as guaranteed; say "PIN or fingerprint, depending on
your key," and never claim the verifier checked it.

## Recovery / key loss

Enroll two or more keys (one on the keyring, one in a drawer). Losing one is an
inconvenience, not a lockout. `allowed_signers` is multi-line by construction. Lose all keys
→ re-enroll via the privileged `enroll` CLI on the host. That is host access, which is below
the gate's floor — not a bypass.

## Testing

- **Crypto plumbing** (already green in the brainstorm proof) — software `ed25519` key, real
  `ssh-keygen -Y verify`, no mocks: verify, namespace enforcement, principal mismatch,
  tamper/replay rejection.
- **Canonicalization** — deterministic key order; absent fields omitted-not-null; unicode
  stability; extra input properties must not reach the output.
- **Policy matching** — each rule type; `fail:"closed"` on error / no keys enrolled.
- **`enroll` key-type check** — accepts real `sk-ssh-ed25519@openssh.com` and
  `sk-ecdsa-sha2-nistp256@openssh.com` wire spellings; rejects software keys and junk. This
  is the only server-side hardware guarantee, so it carries weight.
- **Not automatable, stated plainly** — that a touch/PIN actually happened. The verifier
  never sees it. The manual run on real hardware is the deliverable, exactly as the spike
  was.

## Out of scope (v1)

- Non-macOS renderers (Linux/Windows touch prompt) — follow-up.
- WebAuthn/passkeys, push-notification transport — the hook is synchronous and local.
- Session-unlock / windowed authorization — v1 is strictly per-call action-bound.
- Per-project policy — v1 policy is install-global and root-owned.
