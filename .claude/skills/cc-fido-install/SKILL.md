---
name: cc-fido-install
description: Guided install/enroll/activate (and repair/uninstall) of cc-fido-gate. Use when the user wants to install, set up, activate, check, repair, or remove cc-fido-gate — it drives the privileged cc-fido subcommands, prompting the user for sudo/touch at each step.
---

# Guided cc-fido-gate install

You orchestrate the `cc-fido` subcommands. You CANNOT type the user's sudo password or touch their key —
you are a guide: tell the user the ONE command to run next, have them run it in their terminal (with the
`! ` prefix, so sudo can prompt and the key can blink), read the output, and advance.

## Always start by reading state
Ask the user to run `cc-fido status --json` (or run it yourself if unprivileged reads suffice) and parse
the `rollup`. Branch:
- `clean` → Step 1 (install)
- `prereqs-only` → Step 2 (enroll)
- `enrolled` → Step 3 (activate)
- `active` → already installed; offer `status`, a smoke test, or `uninstall`
- `degraded` → diagnose which component is false in the JSON and repair (usually re-run install or activate)

## Step 1 — Prereqs (0 touches; one sudo prompt)
Tell the user: `! sudo cc-fido install --policy <path-to-their-policy-or-install/policy.json>`
(If they haven't authored a policy, note the default gates sensitive/home paths; a `/cc-fido:policy`
skill can build one.) Confirm `status` rollup is now `prereqs-only`.

## Step 2 — Enroll a key (touch; runs as the user)
Tell the user: `! cc-fido enroll`  (add `--keys 2` if they want a backup, enrolled one at a time).
Tell them to TOUCH the key when it blinks. If they see `invalid format` swapping two keys, that's the
authenticator not settling — retry with the intended key plugged in. Confirm rollup is now `enrolled`.

## Step 3 — Activate the daemon (one sudo prompt)
Tell the user: `! sudo cc-fido activate`. It prints whether the socket is reachable. If NOT reachable,
have them run it again (it re-kickstarts a fresh socket — the known stale-socket fix). Confirm `active`.

## Verify
`cc-fido status` should read `active`. Optionally have them prove the gate end-to-end via
`scripts/userrun/task7_accept.sh` (needs a touch).

## Repair / Uninstall
- Broker unreachable / stale socket → `! sudo cc-fido activate`.
- Full reset → `! sudo cc-fido uninstall` → confirm `status` = `clean`.

Never run a `sudo` command yourself — always hand it to the user. After each step, re-read `status` before
advancing; every subcommand is idempotent, so resuming after an interruption is safe.
