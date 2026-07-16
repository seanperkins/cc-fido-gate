# cc-fido-gate

**Require a physical FIDO/security-key touch before Claude Code runs a high-risk tool call.**

`cc-fido-gate` is a Claude Code plugin that binds a hardware security key to an agent's
most dangerous actions. When a gated tool call fires — a force-push, an `rm -rf`, a prod
deploy, a write to `.env` — a `PreToolUse` hook renders the exact command and demands a
signature from an enrolled hardware key before it will allow the call to proceed.

The agent can *trigger* the prompt as often as it likes. It cannot satisfy it: producing
the signature requires touching the key (and optionally entering a PIN), and an agent has
no finger. That inversion is the whole idea.

```
Claude wants to run:  git push --force origin main
Touch your key to approve, or Cancel to deny.
   🔑  *blink*
```

## Why this exists

Cryptographically binding a human presence gesture to an agent's high-risk action is,
as of this writing, **absent from the ecosystem** — no known Claude Code plugin, hook, or
MCP server does it. This plugin is that artifact. It generalizes a proven spike
([Switchyard](https://github.com/MobilityLabs/switchyard)'s signed-affirmation gate for
issue `done`-stamps) into a reusable, self-contained tool with no server dependency.

## What it guarantees — stated honestly

A **recognized** gated action cannot proceed without a physical touch on an enrolled
**hardware** key. The agent cannot disable the gate (it is registered via Claude Code
*managed settings* and its policy files are root-owned) and cannot forge the touch.

It does **not** guarantee that every dangerous action is *recognized* — matching an
arbitrary shell command against a danger-list is inherently incomplete. And it does not
defend against the host's `root` user (that's you). See [docs/design.md](docs/design.md)
for the full threat model.

## Status

🚧 Design complete, implementation not started. See [docs/design.md](docs/design.md).

## Requirements

- macOS (the touch renderer uses a native dialog; other platforms are a follow-up)
- A FIDO2 / security key that supports SSH `sk-*` keys (e.g. YubiKey 5+)
- OpenSSH with FIDO support for *signing*: `brew install openssh` (stock macOS
  `ssh-keygen` has no FIDO provider). *Verification* works with stock `ssh-keygen`.
- Claude Code

## License

MIT — see [LICENSE](LICENSE).
