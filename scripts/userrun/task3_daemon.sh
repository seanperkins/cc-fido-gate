#!/bin/bash
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"; TARGET=/Users/Shared/ccfido-target.txt
swift build -c release --package-path "$REPO"; BIN="$REPO/.build/release/cc-fido"
sudo -u _ccfido "$BIN" daemon & DPID=$!; sleep 1
echo "=== cancel -> deny, target unchanged ==="; BEFORE=$(sudo cat "$TARGET")
echo ">>> CANCEL the dialog (do NOT touch) <<<"; printf 'NOPE' | "$BIN" write "$TARGET"; echo "rc=$?"
[ "$(sudo cat "$TARGET")" = "$BEFORE" ] && echo "PASS: cancel wrote nothing" || echo "FAIL"
echo "=== accept still serves after a slow client (DoS: per-conn thread) ==="
( sleep 30 | nc -U /var/ccfido-run/gate.sock ) &   # slow-loris one connection
sleep 1; echo ">>> APPROVE + TOUCH to prove a second client is NOT starved <<<"
printf 'WRITTEN-2' | "$BIN" write "$TARGET"; [ "$(sudo cat "$TARGET")" = "WRITTEN-2" ] && echo "PASS: not starved" || echo "FAIL"
sudo kill "$DPID" 2>/dev/null
echo "=== audit chain ==="; sudo -u _ccfido "$BIN" _verify-audit 2>/dev/null || echo "(add _verify-audit or check manually)"
