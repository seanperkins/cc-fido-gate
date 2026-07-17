#!/bin/bash
# scripts/userrun/task7_enroll.sh
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"; SIGN=/opt/homebrew/opt/openssh/bin/ssh-keygen
swift build -c release --package-path "$REPO"; BIN="$REPO/.build/release/cc-fido"
mkdir -p "$HOME/.ccfido"; chmod 700 "$HOME/.ccfido"
# Enroll KEYS keys, default 1. A backup key (KEYS=2) is wise for real use — losing your only enrolled
# key means recovering custody by hand (sudo chflags nouchg) — but enroll them ONE AT A TIME, swapping
# the authenticator between prompts (hot-swapping mid-ssh-keygen can throw "invalid format").
KEYS="${KEYS:-1}"
for n in $(seq 1 "$KEYS"); do
  echo ">>> TOUCH to enroll key #$n of $KEYS <<<"
  "$SIGN" -t ed25519-sk -O application=ssh:cc-fido-gate -N '' -C "cc-fido-key$n" -f "$HOME/.ccfido/gate_sk$n"
  chmod 600 "$HOME/.ccfido/gate_sk$n"
  sudo sh -c "printf 'gate-principal %s\n' \"\$(cat '$HOME/.ccfido/gate_sk$n.pub')\" >> /var/ccfido/allowed_signers"
done
# Point the active handle at key #1 — BOTH private and public, or ssh-keygen -Y sign errors
# "Public key doesn't match private" (a stale/mismatched .pub aborts signing before the key ever blinks).
ln -sf "$HOME/.ccfido/gate_sk1" "$HOME/.ccfido/gate_sk"
ln -sf "$HOME/.ccfido/gate_sk1.pub" "$HOME/.ccfido/gate_sk.pub"
sudo chown _ccfido /var/ccfido/allowed_signers; sudo chmod 600 /var/ccfido/allowed_signers
echo "=== negative blink-test (key #1) ==="
"$BIN" _blink-test "$HOME/.ccfido/gate_sk1" && echo "PASS: touch-required verified" || echo "FAIL"
