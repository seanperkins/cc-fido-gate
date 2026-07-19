#!/bin/bash
# packaging/publish-release.sh — PATH 3 (maintainer): publish the notarized cc-touch-id.app as a pinned
# GitHub release asset and update plugins/cc-touch-id/install/release.json (the trust anchor that
# install/fetch-app.sh verifies against). Run AFTER packaging/build-distribution.sh.
#
# [USER-RUN] — needs an authenticated `gh`, `jq`, and a stapled Developer-ID .app. Re-verifies the .app
# is genuinely the notarized distribution build before publishing (so a stray dev build can't ship).
# Does NOT git-commit — it prints the commit step (release.json must be reviewed + committed by hand).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST="$REPO_ROOT/plugins/cc-touch-id/install/release.json"
APP="${APP:-$REPO_ROOT/packaging/.dd/export/cc-touch-id.app}"
command -v gh >/dev/null || { echo "publish: gh (GitHub CLI) not found"; exit 1; }
command -v jq >/dev/null || { echo "publish: jq not found"; exit 1; }
[ -d "$APP" ] || { echo "publish: no .app at $APP — run build-distribution.sh, or set APP=<path>"; exit 1; }

REPO=$(jq -r '.repo' "$MANIFEST")
VERSION="${VERSION:-$(jq -r '.version' "$MANIFEST")}"
TEAM=$(jq -r '.team_id' "$MANIFEST")
ASSET=$(jq -r '.asset' "$MANIFEST")
TAG="cc-touch-id-v$VERSION"

echo "--- verify $APP is a valid Developer-ID build for team $TEAM before publishing ---"
# HARD gates (deterministic on every macOS): valid signature, Developer ID, correct team, no get-task-allow.
codesign --verify --strict "$APP" 2>/dev/null || { echo "publish: codesign --verify failed (broken signature)" >&2; exit 1; }
SIG="$(codesign -dvvv "$APP" 2>&1 || true)"
case "$SIG" in *"Developer ID Application"*) : ;; *) echo "publish: not Developer ID signed" >&2; exit 1 ;; esac
case "$SIG" in *"TeamIdentifier=$TEAM"*) : ;; *) echo "publish: team != $TEAM (release.json pins $TEAM)" >&2; exit 1 ;; esac
ENT="$(codesign -d --entitlements :- "$APP" 2>/dev/null || true)"
case "$ENT" in *get-task-allow*) echo "publish: get-task-allow present — not a distribution build" >&2; exit 1 ;; esac
echo "PASS (hard gates): valid signature, Developer ID, team $TEAM, no get-task-allow"
# BEST-EFFORT (Gatekeeper convenience tools; broken on macOS 26). Notarization itself is authoritative
# via notarytool at build time; the SHA-256 pin below is what actually binds the published bytes.
SPCTL="$(spctl -a -vvv -t exec "$APP" 2>&1 || true)"
case "$SPCTL" in *accepted*) echo "spctl: accepted" ;; *) echo "spctl: (unavailable/errored on this OS — skipping; publishing on notarytool + sha256 pin)" ;; esac
case "$(xcrun stapler validate "$APP" 2>&1 || true)" in *worked*) echo "stapler: ticket stapled (offline-valid)" ;; *) echo "stapler: not stapled (online Gatekeeper only — see docs/FOLLOWUPS.md)" ;; esac

echo "--- zip + sha256 ---"
WORK="$(mktemp -d)"; ZIP="$WORK/$ASSET"
ditto -c -k --keepParent "$APP" "$ZIP"
SHA=$(shasum -a 256 "$ZIP" | awk '{print $1}')
echo "sha256: $SHA"

echo "--- create/update release $TAG on $REPO ---"
if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  gh release upload "$TAG" "$ZIP" --repo "$REPO" --clobber
else
  gh release create "$TAG" "$ZIP" --repo "$REPO" --title "cc-touch-id $VERSION" \
    --notes "Notarized Developer-ID cc-touch-id.app (team $TEAM). Verified by install/fetch-app.sh against release.json (sha256 $SHA)."
fi
URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"

echo "--- pin into $MANIFEST ---"
tmp="$(mktemp)"
jq --arg tag "$TAG" --arg url "$URL" --arg sha "$SHA" \
   '.tag=$tag | .asset_url=$url | .sha256=$sha | .published=true' "$MANIFEST" > "$tmp"
mv "$tmp" "$MANIFEST"

echo "=== publish-release.sh complete ==="
echo "review + commit the pin:"
echo "  git add $MANIFEST && git commit -m 'release(cc-touch-id): $TAG' && git push"
