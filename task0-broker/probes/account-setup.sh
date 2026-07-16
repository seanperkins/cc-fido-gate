#!/bin/bash
# Create a hidden _ccfido service account (uid in the system range, no login).
# Idempotent: exits 0 if it already exists. Requires sudo.
set -eu
USERNAME=_ccfido
if dscl . -read "/Users/$USERNAME" >/dev/null 2>&1; then
  echo "already exists: $USERNAME (uid $(id -u "$USERNAME"))"; exit 0
fi
# Pick a free uid in the 200-400 service range.
UID_NEW=$(sudo dscl . -list /Users UniqueID | awk '$2>=200 && $2<400 {print $2}' | sort -n | tail -1)
UID_NEW=$(( ${UID_NEW:-299} + 1 ))
sudo dscl . -create "/Users/$USERNAME"
sudo dscl . -create "/Users/$USERNAME" UserShell /usr/bin/false
sudo dscl . -create "/Users/$USERNAME" RealName "cc-fido broker"
sudo dscl . -create "/Users/$USERNAME" UniqueID "$UID_NEW"
sudo dscl . -create "/Users/$USERNAME" PrimaryGroupID 20
sudo dscl . -create "/Users/$USERNAME" NFSHomeDirectory /var/empty
sudo dscl . -create "/Users/$USERNAME" IsHidden 1
echo "created: $USERNAME uid=$UID_NEW"
