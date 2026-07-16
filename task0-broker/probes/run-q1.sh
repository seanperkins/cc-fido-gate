#!/bin/bash
# Installs the throwaway LaunchDaemon, kickstarts the _ccfido job, and shows a
# user-session dialog (as sean) concurrently for Q2. Requires sudo + a touch.
set -u
PLIST=/Library/LaunchDaemons/com.cc-fido-gate.brokerprobe.plist
sudo cp task0-broker/probes/brokerd-probe.sh /var/ccfido/brokerd-probe.sh
sudo chown _ccfido /var/ccfido/brokerd-probe.sh; sudo chmod 755 /var/ccfido/brokerd-probe.sh
sudo cp task0-broker/probes/com.cc-fido-gate.brokerprobe.plist "$PLIST"
sudo chown root:wheel "$PLIST"
sudo launchctl bootstrap system "$PLIST" 2>/dev/null || true
echo ">>> TOUCH THE KEY WHEN IT BLINKS (daemon is arming the sign) <<<"
# Q2: user-session dialog as sean, concurrent with the daemon's arm.
( /usr/bin/osascript -l AppleScript -e 'display dialog "broker-gate Q2: daemon is signing; touch the key" giving up after 12' >/dev/null 2>&1 ) &
sudo launchctl kickstart -k system/com.cc-fido-gate.brokerprobe
sleep 12
echo "=== daemon result (/var/ccfido/q1.log) ==="; sudo cat /var/ccfido/q1.log
echo "=== teardown ==="
sudo launchctl bootout system "$PLIST" 2>/dev/null
sudo rm -f "$PLIST"
