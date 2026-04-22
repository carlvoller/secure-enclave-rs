#!/usr/bin/env bash
#
# Build the Secure Enclave test bundle with py2app, embed a macOS development
# provisioning profile, codesign it with matching entitlements (including
# keychain-access-groups), then run the bundled binary and propagate its
# exit code.
#
# Required one-time setup:
#
#   1. In Xcode, create a new macOS App project.
#   2. Set the Bundle Identifier to match $BUNDLE_ID below.
#   3. Select your development Team.
#   4. Add the "Keychain Sharing" capability.
#   5. Product → Build once.
#      This registers a macOS provisioning profile in
#      ~/Library/Developer/Xcode/UserData/Provisioning Profiles/.
#
# Usage:
#   BUNDLE_ID=is.carlvoller.secure-enclave-tests ./run_tests.sh
#
# Optional overrides:
#   VENV=/path/to/.venv                  # default: ../../.venv
#   IDENTITY="Apple Development: ..."    # default: auto-pick by matching team
#   PROFILE=/path/to/profile             # default: auto-detect by BUNDLE_ID
#
# $BUNDLE_ID must match the Bundle Identifier you set on the Xcode project
# that generated your macOS provisioning profile (see one-time setup in
# the project README).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APP_NAME="SecureEnclaveTests"

if [[ -z "${BUNDLE_ID:-}" ]]; then
    cat >&2 <<'ERR'
error: BUNDLE_ID env var is required.

Set it to the Bundle Identifier you gave the Xcode project used to generate
your macOS provisioning profile, e.g.:

    BUNDLE_ID=is.carlvoller.secure-enclave-tests ./run_tests.sh
ERR
    exit 1
fi
export BUNDLE_ID

VENV="${VENV:-$(cd "$SCRIPT_DIR/../.." && pwd)/.venv}"

if [[ ! -x "$VENV/bin/python" ]]; then
    echo "error: no venv found at $VENV. Create it or set VENV=..." >&2
    exit 1
fi
PYTHON="$VENV/bin/python"

# Locate a macOS provisioning profile matching our bundle id
#
# Xcode drops profiles in ~/Library/Developer/Xcode/UserData/Provisioning
# Profiles/. For macOS they have a .provisionprofile extension; for iOS they
# have .mobileprovision. We accept either suffix but require Platform == OSX
# and the application-identifier to end in .$BUNDLE_ID.
#
# plutil -extract uses '.' as a path separator, so it can't access the
# 'com.apple.application-identifier' key directly. We use PlistBuddy (which
# uses ':' as separator) against a decoded tempfile instead.
profile_get() {
    local profile="$1" keypath="$2" tmp
    tmp="$(mktemp -t se-prof)"
    security cms -D -i "$profile" -o "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    /usr/libexec/PlistBuddy -c "Print $keypath" "$tmp" 2>/dev/null
    local rc=$?
    rm -f "$tmp"
    return $rc
}

find_profile() {
    local dir="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
    [[ -d "$dir" ]] || return 1
    local p platform appid
    while IFS= read -r -d '' p; do
        platform="$(profile_get "$p" ":Platform")" || continue
        [[ "$platform" == *"OSX"* ]] || continue
        appid="$(profile_get "$p" ":Entitlements:com.apple.application-identifier")" || continue
        if [[ "$appid" == *".${BUNDLE_ID}" ]]; then
            printf '%s\n' "$p"
            return 0
        fi
    done < <(find "$dir" -maxdepth 1 -type f \( -name '*.provisionprofile' -o -name '*.mobileprovision' \) -print0 2>/dev/null)
    return 1
}

if [[ -n "${PROFILE:-}" ]]; then
    if [[ ! -f "$PROFILE" ]]; then
        echo "error: PROFILE='$PROFILE' not found." >&2
        exit 1
    fi
else
    PROFILE="$(find_profile)" || {
        cat >&2 <<ERR
error: no macOS provisioning profile found for bundle id '$BUNDLE_ID'.

Create one in Xcode (one-time):
  1. File → New → Project → macOS → App
  2. Set Bundle Identifier to '$BUNDLE_ID'
  3. Pick your Team under Signing & Capabilities
  4. Add the "Keychain Sharing" capability
  5. Product → Build (⌘B) once

This will drop a .provisionprofile at:
  ~/Library/Developer/Xcode/UserData/Provisioning Profiles/
ERR
        exit 1
    }
fi

# Extract team id from the profile's application-identifier
APP_IDENTIFIER="$(profile_get "$PROFILE" ":Entitlements:com.apple.application-identifier")"
TEAM_ID="${APP_IDENTIFIER%%.*}"
PROFILE_NAME="$(profile_get "$PROFILE" ":Name" 2>/dev/null || echo '(unnamed)')"

# Pick a codesigning identity that matches the profile's team
if [[ -z "${IDENTITY:-}" ]]; then
    # Prefer an identity whose cert OU matches TEAM_ID. Fall back to the first
    # Apple Development identity if we can't match — the profile will reject
    # signatures that don't match, so a mismatch will fail loudly downstream.
    while IFS= read -r candidate; do
        [[ -z "$candidate" ]] && continue
        hash="${candidate%% *}"
        name="${candidate#* }"
        # Pull the cert's OU (the real team id).
        cert_ou="$(security find-certificate -c "$name" -p 2>/dev/null | \
            openssl x509 -noout -subject 2>/dev/null | \
            sed -n 's/.*OU=\([A-Z0-9]*\).*/\1/p')"
        if [[ "$cert_ou" == "$TEAM_ID" ]]; then
            IDENTITY="$name"
            break
        fi
    done < <(security find-identity -v -p codesigning | \
        awk -F'"' '/Apple Development/ {print $(NF-1)}' | \
        awk 'NF' | \
        while read -r n; do
            hash="$(security find-identity -v -p codesigning | awk -v n="$n" -F'"' '$0 ~ n {print $1}' | awk '{print $2}' | head -1)"
            printf '%s %s\n' "$hash" "$n"
        done)

    if [[ -z "${IDENTITY:-}" ]]; then
        IDENTITY="$(security find-identity -v -p codesigning | awk -F'"' '/Apple Development/ {print $(NF-1); exit}')"
    fi
fi

if [[ -z "${IDENTITY:-}" ]]; then
    echo "error: no Apple Development codesigning identity found." >&2
    exit 1
fi

echo "==> profile:   $(basename "$PROFILE")"
echo "              ($PROFILE_NAME)"
echo "==> app-id:    $APP_IDENTIFIER"
echo "==> team id:   $TEAM_ID"
echo "==> identity:  $IDENTITY"
echo "==> bundle id: $BUNDLE_ID"

# Render entitlements.plist from the template
ENTITLEMENTS="$SCRIPT_DIR/entitlements.plist"
sed -e "s/@TEAM_ID@/$TEAM_ID/g" -e "s|@BUNDLE_ID@|$BUNDLE_ID|g" \
    entitlements.plist.template > "$ENTITLEMENTS"
echo "==> rendered entitlements:"
sed 's/^/      /' "$ENTITLEMENTS"

# Build the .app via py2app
echo "==> cleaning build/ and dist/"
rm -rf build dist

echo "==> running py2app"
"$PYTHON" setup.py py2app --no-strip

APP_PATH="$SCRIPT_DIR/dist/$APP_NAME.app"
if [[ ! -d "$APP_PATH" ]]; then
    echo "error: expected bundle not found at $APP_PATH" >&2
    exit 1
fi

# Embed the provisioning profile
# For macOS apps the profile lives at Contents/embedded.provisionprofile.
# AMFI reads it at launch time to authorize the restricted entitlements we're
# about to sign into the binary.
cp "$PROFILE" "$APP_PATH/Contents/embedded.provisionprofile"
echo "==> embedded provisioning profile"

# Codesign the bundle
# --deep recursively signs every embedded Mach-O (the _native.so extension,
# the embedded Python framework, dylibs py2app copied in). A plain --sign on
# just the outer .app would leave inner binaries with their py2app ad-hoc
# signatures, which AMFI would reject under our entitled host.
echo "==> codesigning (recursive)"
codesign --force --deep \
    --entitlements "$ENTITLEMENTS" \
    --sign "$IDENTITY" \
    "$APP_PATH"

echo "==> verifying signature"
codesign --verify --verbose=2 "$APP_PATH"
echo "==> effective entitlements:"
codesign --display --entitlements :- "$APP_PATH" 2>/dev/null | sed 's/^/      /' || true

# Run the signed binary and surface its output
EXECUTABLE="$APP_PATH/Contents/MacOS/$APP_NAME"
LOG="$SCRIPT_DIR/dist/test_output.log"
rm -f "$LOG"

echo "==> launching $EXECUTABLE"
set +e
"$EXECUTABLE"
STATUS=$?
set -e

if [[ -f "$LOG" ]]; then
    echo " test output"
    cat "$LOG"
    echo ""
fi

if [[ $STATUS -eq 0 ]]; then
    echo "==> PASS"
else
    echo "==> FAIL (exit $STATUS)" >&2
fi
exit $STATUS
