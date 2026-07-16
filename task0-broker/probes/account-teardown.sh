#!/bin/bash
# Remove the _ccfido account. Requires sudo. Safe to run repeatedly.
set -u
USERNAME=_ccfido
sudo dscl . -delete "/Users/$USERNAME" 2>/dev/null && echo "deleted $USERNAME" || echo "$USERNAME not present"
