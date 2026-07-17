#!/bin/bash
# tests/userrun/task1_e2e.sh — daemon as _ccfido, client ceremony, ONE touch writes the enrolled target.
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET=/Users/Shared/ccfido-target.txt
swift build -c release --package-path "$REPO"; BIN="$REPO/.build/release/cc-fido"
BEFORE=$(sudo cat "$TARGET" 2>/dev/null)
sudo -u _ccfido "$BIN" daemon & DPID=$!; sleep 1
echo ">>> APPROVE the dialog, then TOUCH the key <<<"
printf 'WRITTEN-BY-CEREMONY' | "$BIN" write "$TARGET"; RC=$?
sudo kill "$DPID" 2>/dev/null
AFTER=$(sudo cat "$TARGET" 2>/dev/null)
echo "before=$BEFORE after=$AFTER rc=$RC"
[ "$AFTER" = "WRITTEN-BY-CEREMONY" ] && echo "PASS: ceremony wrote through the uchg lock" || echo "FAIL"
echo "=== control-path denial (expect deny, no touch) ==="; printf 'x' | "$BIN" write /var/ccfido/allowed_signers
echo "=== unenrolled-path denial (expect deny) ==="; printf 'x' | "$BIN" write /tmp/not-enrolled
echo "=== audit tail ==="; sudo tail -3 /var/ccfido/audit.log
echo "=== target re-locked ==="; sudo ls -lO "$TARGET"
