#!/bin/bash
# packaging/build-distribution.sh — build the NOTARIZED, Developer-ID-distributable cc-touch-id.app.
#
# [USER-RUN] — needs a full Xcode, a valid `Developer ID Application: … (HH3SJBAS42)` signing identity,
# a notarytool credential profile, and network access to Apple. An agent sandbox cannot run it
# (no keychain identity, no Apple network). Hand it to the human on the signing machine.
#
# WHY THIS WORKS (and build-signed.sh's author-machine build does not, for distribution):
#   The persistent Secure Enclave key is a data-protection-keychain item and MUST land in an
#   authorized keychain access group. A bare Developer ID signature has none:
#     - asserting `keychain-access-groups` with no profile -> amfid SIGKILL at launch (rc 137);
#     - asserting nothing -> app launches but `SecKeyCreateRandomKey` fails -34018
#       (errSecMissingEntitlement, "failed to add key to keychain").
#   (Both confirmed empirically on macOS 26 — see docs/superpowers/specs/2026-07-19-*-notarized-*.md.)
#   The fix is a *Developer ID* provisioning profile, which grants `application-identifier`
#   (= HH3SJBAS42.com.seanperkins.cc-touch-id) — exactly the access group the SE key needs — WITHOUT
#   the `get-task-allow` that the Development profile forces. Xcode's `archive` + `-exportArchive`
#   with `method: developer-id` (ExportOptions.plist) + `-allowProvisioningUpdates` creates/embeds
#   that profile, signs Developer ID + hardened runtime, and strips get-task-allow — all automatically.
#
# Usage: NOTARY_PROFILE=cc-touch-id-notary bash packaging/build-distribution.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGING_DIR="$SCRIPT_DIR"
NOTARY_PROFILE="${NOTARY_PROFILE:-cc-touch-id-notary}"
DERIVED_DATA="$PACKAGING_DIR/.dd"

echo "=== packaging/build-distribution.sh: notarized Developer-ID cc-touch-id.app ==="
cd "$PACKAGING_DIR"

# --- a. project generation --------------------------------------------------------------------
echo "--- Step a: xcodegen generate (or use the committed .xcodeproj) ---"
if command -v xcodegen >/dev/null 2>&1; then
  xcodegen generate
else
  echo "xcodegen not found — using committed .xcodeproj (packaging/CCTouchIDGate.xcodeproj)"
fi

# --- b. archive (automatic signing; Xcode manages the Developer ID profile) -------------------
echo "--- Step b: xcodebuild archive (Release, automatic signing) ---"
rm -rf "$DERIVED_DATA"
xcodebuild -project "$PACKAGING_DIR/CCTouchIDGate.xcodeproj" -scheme cc-touch-id -configuration Release \
  -derivedDataPath "$DERIVED_DATA" -allowProvisioningUpdates \
  archive -archivePath "$DERIVED_DATA/cc-touch-id.xcarchive"

# --- c. export as Developer ID (embeds Developer ID profile, strips get-task-allow) -----------
echo "--- Step c: xcodebuild -exportArchive (method: developer-id) ---"
xcodebuild -exportArchive -archivePath "$DERIVED_DATA/cc-touch-id.xcarchive" \
  -exportOptionsPlist "$PACKAGING_DIR/ExportOptions.plist" -exportPath "$DERIVED_DATA/export" \
  -allowProvisioningUpdates

APP="$DERIVED_DATA/export/cc-touch-id.app"
[ -d "$APP" ] || { echo "FAIL: exported app not found at $APP" >&2; exit 1; }
echo "exported: $APP"

# --- d. verify the distribution signature BEFORE spending a notarization round -----------------
# (capture-then-grep to avoid the pipefail/SIGPIPE false-fail — see build-signed.sh Step c.)
echo "--- Step d: verify Developer ID + runtime + NO get-task-allow + embedded profile + launches ---"
SIG_OUT="$(codesign -dvvv "$APP" 2>&1 || true)"
case "$SIG_OUT" in *"Developer ID Application"*) : ;; *) echo "FAIL: not Developer ID signed" >&2; exit 1 ;; esac
case "$SIG_OUT" in *"flags=0x10000(runtime)"*|*"runtime"*) : ;; *) echo "FAIL: hardened runtime missing" >&2; exit 1 ;; esac
ENT_OUT="$(codesign -d --entitlements :- "$APP" 2>/dev/null || true)"
case "$ENT_OUT" in *get-task-allow*) echo "FAIL: get-task-allow present — not TID-5 clean" >&2; exit 1 ;; esac
case "$ENT_OUT" in *keychain-access-groups*|*application-identifier*) : ;; *) echo "FAIL: no access-group entitlement — SE key will fail -34018" >&2; exit 1 ;; esac
[ -f "$APP/Contents/embedded.provisionprofile" ] \
  || { echo "FAIL: no embedded provisioning profile — SE keychain-access-group unauthorized" >&2; exit 1; }
"$APP/Contents/MacOS/cc-touch-id" status --json >/dev/null 2>&1 \
  || { echo "FAIL: exported app amfid-killed at launch (rc $?)" >&2; exit 1; }
echo "PASS: Developer ID, hardened runtime, no get-task-allow, profile embedded, launches"

# --- e. notarize + staple ----------------------------------------------------------------------
echo "--- Step e: notarize (profile: $NOTARY_PROFILE) + staple ---"
ZIP="$DERIVED_DATA/cc-touch-id.app.zip"
ditto -c -k --keepParent "$APP" "$ZIP"

# Submit and PARSE the verdict — do not blindly staple. If notarization is Invalid, print the log
# (which names the offending binary/entitlement) and abort; stapling a non-notarized app fails anyway.
SUBMIT_JSON="$(xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait --output-format json)"
echo "$SUBMIT_JSON"
SUB_ID="$(printf '%s' "$SUBMIT_JSON" | jq -r '.id // empty')"
SUB_STATUS="$(printf '%s' "$SUBMIT_JSON" | jq -r '.status // empty')"
if [ "$SUB_STATUS" != "Accepted" ]; then
  echo "FAIL: notarization status is '$SUB_STATUS' (not Accepted)." >&2
  [ -n "$SUB_ID" ] && xcrun notarytool log "$SUB_ID" --keychain-profile "$NOTARY_PROFILE" >&2 || true
  exit 1
fi

# Staple (best-effort). Stapling only adds OFFLINE Gatekeeper validation; the app is already notarized
# (asserted Accepted above), so an un-stapled build still passes Gatekeeper via the online check. On
# some macOS builds `stapler` is broken (macOS 26: Error 73, "could not remove existing ticket …
# Contents/CodeResources") — warn and continue rather than fail the whole build. Retry a couple times
# first in case it is only CDN propagation lag.
STAPLED=0
for attempt in 1 2 3; do
  if xcrun stapler staple "$APP" 2>/dev/null; then STAPLED=1; break; fi
  sleep 15
done
if [ "$STAPLED" = 1 ]; then
  echo "stapled OK (offline Gatekeeper validation embedded)"
else
  echo "WARN: could not staple (notarization IS Accepted — likely a macOS-26 stapler bug, see docs/FOLLOWUPS.md)."
  echo "      Shipping notarized-but-unstapled: passes Gatekeeper ONLINE; first launch needs network."
fi

# --- f. verification --------------------------------------------------------------------------
# Hard gate: the signature is structurally valid (works on every macOS). Best-effort: spctl/stapler
# (Gatekeeper convenience tools, broken on macOS 26 — informational only here).
echo "--- Step f: verify ---"
codesign --verify --strict "$APP" || { echo "FAIL: codesign --verify failed" >&2; exit 1; }
echo "codesign --verify: valid"
SPCTL="$(spctl -a -vvv -t exec "$APP" 2>&1 || true)"
case "$SPCTL" in *accepted*) echo "spctl: accepted" ;; *) echo "spctl: (unavailable/errored on this OS — notarization already Accepted via notarytool)" ;; esac

echo "=== build-distribution.sh complete ==="
echo "notarized .app: $APP  (stapled: $([ "$STAPLED" = 1 ] && echo yes || echo 'no — see WARN above'))"
echo "NEXT: bash packaging/publish-release.sh   (then install + 'cc-touch-id enroll')."
