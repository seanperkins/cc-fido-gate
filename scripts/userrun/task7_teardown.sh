#!/bin/bash
# scripts/userrun/task7_teardown.sh — full uninstall. Stops+removes the LaunchDaemon and the managed
# settings (ungates Claude Code), unlocks+restores every enrolled target, deletes the install tree,
# daemon state, and the _ccfido account. Idempotent; continues through failures (no set -e).
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LA="$HOME/Library/LaunchAgents"
OWNER="$(id -un):$(id -gn)"

echo "=== stop + remove the LaunchDaemon ==="
sudo launchctl bootout system /Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist 2>/dev/null || true
sudo pkill -f 'cc-fido daemon' 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist

echo "=== remove managed settings (ungates Claude Code) ==="
sudo rm -f "/Library/Application Support/ClaudeCode/managed-settings.json"

echo "=== unlock + restore every enrolled target BEFORE deleting the registry ==="
# From the registry (all "/…"-quoted paths in custody.json) + known test targets, in case a write failed:
{ sudo cat /var/ccfido/custody.json 2>/dev/null | grep -oE '"/[^"]+"' | tr -d '"'
  printf '%s\n' "$LA" /Users/Shared/ccfido-accept.txt /Users/Shared/ccfido-target.txt
} | sort -u | while read -r p; do
  [ -e "$p" ] || continue
  sudo chflags nouchg "$p" 2>/dev/null && echo "  unlocked $p" || true
  sudo chown "$OWNER" "$p" 2>/dev/null || true
done

echo "=== remove install tree + daemon state ==="
sudo rm -rf /opt/cc-fido-gate /var/ccfido /var/ccfido-run

echo "=== remove the _ccfido service account ==="
sudo bash "$REPO/task0-broker/probes/account-teardown.sh" || true

echo "=== remove enrolled key material ==="
rm -f "$HOME/.ccfido/gate_sk" "$HOME"/.ccfido/gate_sk1* "$HOME"/.ccfido/gate_sk2* 2>/dev/null || true

echo "=== verify clean ==="
FAIL=0
chk(){ if [ -e "$2" ]; then echo "  LEFT: $1 ($2)"; FAIL=1; else echo "  gone: $1"; fi; }
chk "install tree"     /opt/cc-fido-gate
chk "daemon state"     /var/ccfido
chk "run dir"          /var/ccfido-run
chk "LaunchDaemon"     /Library/LaunchDaemons/com.cc-fido-gate.brokerd.plist
chk "managed settings" "/Library/Application Support/ClaudeCode/managed-settings.json"
id _ccfido >/dev/null 2>&1 && { echo "  LEFT: _ccfido account"; FAIL=1; } || echo "  gone: _ccfido account"
echo
[ "$FAIL" = 0 ] && echo "RESULT: CLEAN" || echo "RESULT: RESIDUE (see LEFT above — remove manually)"
