#!/bin/bash
# tests/userrun/bootstrap.sh — one-time setup for the Task 1 e2e. Requires sudo + ONE enrollment touch.
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SIGN=/opt/homebrew/opt/openssh/bin/ssh-keygen
sudo bash "$REPO/task0-broker/probes/account-setup.sh"
sudo mkdir -p /var/ccfido /var/ccfido-run
sudo chown _ccfido /var/ccfido /var/ccfido-run
sudo chmod 700 /var/ccfido ; sudo chmod 755 /var/ccfido-run
mkdir -p "$HOME/.ccfido" ; chmod 700 "$HOME/.ccfido"
echo ">>> TOUCH THE KEY WHEN IT BLINKS (enrollment) <<<"
"$SIGN" -t ed25519-sk -O application=ssh:cc-fido-gate -N '' -C 'cc-fido-broker' -f "$HOME/.ccfido/gate_sk"
chmod 600 "$HOME/.ccfido/gate_sk"
sudo sh -c "printf 'gate-principal %s\n' \"\$(cat '$HOME/.ccfido/gate_sk.pub')\" > /var/ccfido/allowed_signers"
sudo chown _ccfido /var/ccfido/allowed_signers ; sudo chmod 600 /var/ccfido/allowed_signers
# crown-jewel target OUTSIDE the keydir (isControlPath denies keydir targets) + register it in the allowlist.
# Same path task1_e2e.sh uses, so the enrolled-target write path is actually exercised.
TARGET=/Users/Shared/ccfido-target.txt
echo seed | sudo tee "$TARGET" >/dev/null
sudo chown _ccfido "$TARGET" ; sudo chflags uchg "$TARGET"
printf '{"files":["%s"],"dirs":[]}' "$TARGET" | sudo tee /var/ccfido/custody.json >/dev/null
sudo chown _ccfido /var/ccfido/custody.json ; sudo chmod 600 /var/ccfido/custody.json
echo "expect denied (keydir unreadable by sean):"; cat /var/ccfido/allowed_signers 2>&1 | head -1 || true
echo "bootstrap complete."
