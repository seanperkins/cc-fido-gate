#!/bin/bash
set -u
D=$(mktemp -d); chmod 755 "$D"; FAILED=0     # 755 so sudo -u _ccfido can traverse (test-only)
pass(){ echo "  PASS: $1"; }; fail(){ echo "  FAIL: $1"; FAILED=1; }
echo original > "$D/secret"; sudo chown _ccfido "$D/secret"; sudo chflags uchg "$D/secret"
echo hostile > "$D/secret" 2>/dev/null && fail "wrote locked" || pass "write denied"
rm -f "$D/secret" 2>/dev/null && fail "deleted" || pass "unlink denied"
mv "$D/secret" "$D/s2" 2>/dev/null && fail "renamed" || pass "rename denied"
chflags nouchg "$D/secret" 2>/dev/null && fail "cleared uchg" || pass "nouchg denied"
sudo mkdir "$D/dir"; sudo chown _ccfido "$D/dir"; sudo chmod 755 "$D/dir"
touch "$D/dir/new" 2>/dev/null && fail "created in locked dir" || pass "create denied"
sudo -u _ccfido chflags nouchg "$D/secret" && pass "owner cleared uchg" || fail "owner blocked"
sudo chflags nouchg "$D/secret" 2>/dev/null; sudo rm -rf "$D"
[ "$FAILED" = 0 ] && echo "RESULT: GREEN" || echo "RESULT: RED"
