#!/bin/bash
# scripts/userrun/task7_accept.sh — Step 10 full-system acceptance (run AFTER install + enroll).
# Exercises the live LaunchDaemon install end-to-end: dir-custody of the design's primary adversary
# path, file-custody with broker-write-after-touch, the C-3 control-path denial, and audit integrity.
set -u
BIN=/opt/cc-fido-gate/cc-fido
LA="$HOME/Library/LaunchAgents"
BENIGN=/Users/Shared/ccfido-accept.txt
FAILED=0
pass(){ echo "  PASS: $1"; }; fail(){ echo "  FAIL: $1"; FAILED=1; }

echo "=== 1. enroll-dir the primary adversary path (~/Library/LaunchAgents) ==="
mkdir -p "$LA"
"$BIN" enroll-dir "$LA" || { echo "  enroll-dir failed — ABORT"; exit 1; }

echo "=== 2. agent-uid CANNOT create a plist in the enrolled dir (C-3 dir custody) ==="
touch "$LA/x.plist" 2>/dev/null && fail "created plist in locked dir" || pass "create denied in ~/Library/LaunchAgents"

echo "=== 3. enroll a benign file: direct write EACCES, broker write works after a touch ==="
[ -e "$BENIGN" ] || echo before > "$BENIGN"
"$BIN" enroll-file "$BENIGN" || { echo "  enroll-file failed — ABORT"; exit 1; }
echo hostile > "$BENIGN" 2>/dev/null && fail "direct write succeeded (should be denied)" || pass "direct write denied (uchg/EACCES)"
echo ">>> APPROVE + TOUCH to write via the broker <<<"
printf 'ACCEPTED-VIA-BROKER' | "$BIN" write "$BENIGN"
[ "$(sudo cat "$BENIGN" 2>/dev/null)" = "ACCEPTED-VIA-BROKER" ] && pass "broker write landed after touch" || fail "broker write after touch"

echo "=== 4. C-3: cc-fido write to a control path is DENIED with NO touch prompt ==="
OUT=$(printf 'x' | "$BIN" write /var/ccfido/allowed_signers 2>&1 || true)
echo "$OUT" | grep -qi 'deny\|not an enrolled' && pass "control-path write denied (no prompt)" || { fail "control-path not denied"; echo "    $OUT"; }

echo "=== 5. audit chain valid AND at least one write_ok present (empty-chain guard) ==="
sudo -u _ccfido "$BIN" _verify-audit && pass "audit chain OK" || fail "audit chain broken"
sudo grep -q '"event":"write_ok"' /var/ccfido/audit.log && pass "write_ok event present" || fail "no write_ok event in log"

echo
[ "$FAILED" = 0 ] && echo "RESULT: GREEN" || echo "RESULT: RED"
