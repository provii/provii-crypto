#!/usr/bin/env bash
set -euo pipefail

# check-zk-param-consistency.sh
#
# Verifies that all downstream repos have consistent ZK parameter references
# matching the canonical manifest in provii-crypto.
#
# Usage:
#   ./scripts/check-zk-param-consistency.sh --provii-root /path/to/Provii
#   ./scripts/check-zk-param-consistency.sh --manifest /path/to/zk-params-manifest.json --provii-root /path/to/Provii

MANIFEST=""
PROVII_ROOT=""
ERRORS=0
CHECKS=0

usage() {
    echo "Usage: $0 --provii-root <path> [--manifest <path>]"
    echo ""
    echo "  --provii-root   Path to the Provii monorepo root (contains all repos)"
    echo "  --manifest      Path to zk-params-manifest.json (default: provii-root/provii-crypto/zk-params-manifest.json)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --provii-root) PROVII_ROOT="$2"; shift 2 ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1"; usage ;;
    esac
done

if [[ -z "$PROVII_ROOT" ]]; then
    echo "ERROR: --provii-root is required"
    usage
fi

if [[ -z "$MANIFEST" ]]; then
    MANIFEST="$PROVII_ROOT/provii-crypto/zk-params-manifest.json"
fi

if [[ ! -f "$MANIFEST" ]]; then
    echo "ERROR: Manifest not found at $MANIFEST"
    exit 1
fi

echo "=== ZK Parameter Consistency Check ==="
echo "Manifest: $MANIFEST"
echo "Provii root: $PROVII_ROOT"
echo ""

# Extract values from manifest
VK_ID=$(jq -r '.vk_id' "$MANIFEST")
PK_SIZE=$(jq -r '.pk_size_bytes' "$MANIFEST")
PK_BLAKE2S=$(jq -r '.pk_blake2s_hash' "$MANIFEST")
VK_BLAKE2B512=$(jq -r '.vk_blake2b512_hash' "$MANIFEST")
PK_URL=$(jq -r '.pk_url' "$MANIFEST")
VK_SIZE=$(jq -r '.vk_size_bytes' "$MANIFEST")
EXPECTED_PUBLIC_INPUTS=$(jq -r '.expected_public_inputs' "$MANIFEST")

echo "Expected values from manifest:"
echo "  VK_ID:                  $VK_ID"
echo "  PK_SIZE:                $PK_SIZE"
echo "  PK_BLAKE2S:             $PK_BLAKE2S"
echo "  VK_BLAKE2B512:          $VK_BLAKE2B512"
echo "  PK_URL:                 $PK_URL"
echo "  VK_SIZE:                $VK_SIZE"
echo "  EXPECTED_PUBLIC_INPUTS: $EXPECTED_PUBLIC_INPUTS"
echo ""

check_file_contains() {
    local file="$1"
    local pattern="$2"
    local description="$3"
    CHECKS=$((CHECKS + 1))

    if [[ ! -f "$file" ]]; then
        echo "  SKIP: $file not found"
        return
    fi

    if grep -q "$pattern" "$file"; then
        echo "  OK: $description"
    else
        echo "  FAIL: $description"
        echo "        File: $file"
        echo "        Expected pattern: $pattern"
        ERRORS=$((ERRORS + 1))
    fi
}

check_file_not_contains() {
    local file="$1"
    local pattern="$2"
    local description="$3"
    CHECKS=$((CHECKS + 1))

    if [[ ! -f "$file" ]]; then
        echo "  SKIP: $file not found"
        return
    fi

    if grep -q "$pattern" "$file"; then
        echo "  FAIL: $description (stale reference found)"
        echo "        File: $file"
        echo "        Unexpected pattern: $pattern"
        ERRORS=$((ERRORS + 1))
    else
        echo "  OK: $description (no stale references)"
    fi
}

# ─────────────────────────────────────────────
# provii-verifier
# ─────────────────────────────────────────────
echo "── provii-verifier ──"
VAPI="$PROVII_ROOT/provii-verifier"

check_file_contains "$VAPI/src/lib.rs" "VK_ID: u32 = $VK_ID" "VK_ID constant"
check_file_contains "$VAPI/src/lib.rs" "vk\.$VK_ID\.bin" "include_bytes! VK path"
check_file_contains "$VAPI/src/lib.rs" "$VK_BLAKE2B512" "Blake2b-512 checksum"
check_file_contains "$VAPI/src/lib.rs" "expected_inputs != $EXPECTED_PUBLIC_INPUTS" "Expected public inputs check"

# Check VK binary exists with correct size
VK_BIN="$VAPI/assets/vk.$VK_ID.bin"
CHECKS=$((CHECKS + 1))
if [[ -f "$VK_BIN" ]]; then
    ACTUAL_SIZE=$(wc -c < "$VK_BIN" | tr -d ' ')
    if [[ "$ACTUAL_SIZE" == "$VK_SIZE" ]]; then
        echo "  OK: VK binary exists ($ACTUAL_SIZE bytes)"
    else
        echo "  FAIL: VK binary size mismatch (expected $VK_SIZE, got $ACTUAL_SIZE)"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "  FAIL: VK binary not found at $VK_BIN"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ─────────────────────────────────────────────
# provii-mobile-sdk
# ─────────────────────────────────────────────
echo "── provii-mobile-sdk ──"
WSDK="$PROVII_ROOT/provii-mobile-sdk"

check_file_contains "$WSDK/crates/ffi/src/proving_key.rs" "VK_ID: u32 = $VK_ID" "VK_ID constant"
check_file_contains "$WSDK/crates/ffi/src/proving_key.rs" "$PK_URL" "PK_URL"
check_file_contains "$WSDK/crates/ffi/src/proving_key.rs" "$PK_BLAKE2S" "PK_BLAKE2S hash"

# Check PK_SIZE (formatted with underscores in Rust)
# Convert 51419928 to regex matching 51_419_928 or 51419928
PK_SIZE_UNDERSCORE=$(echo "$PK_SIZE" | sed 's/\([0-9]\{1,3\}\)\(\([0-9]\{3\}\)*\)$/\1_\2/' | sed 's/_$//' | sed 's/\([0-9]\{3\}\)\([0-9]\)/\1_\2/g')
CHECKS=$((CHECKS + 1))
if grep -q "PK_SIZE.*$PK_SIZE\|PK_SIZE.*${PK_SIZE_UNDERSCORE}" "$WSDK/crates/ffi/src/proving_key.rs" 2>/dev/null; then
    echo "  OK: PK_SIZE value"
else
    echo "  FAIL: PK_SIZE value (expected $PK_SIZE or $PK_SIZE_UNDERSCORE)"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ─────────────────────────────────────────────
# provii-agegate
# ─────────────────────────────────────────────
echo "── provii-agegate ──"
AGE="$PROVII_ROOT/provii-agegate"

check_file_contains "$AGE/src/agegate/AgeGateConfig.ts" "DEFAULT_VERIFYING_KEY_ID = $VK_ID" "DEFAULT_VERIFYING_KEY_ID"
echo ""

# ─────────────────────────────────────────────
# provii-management
# ─────────────────────────────────────────────
echo "── provii-management ──"
MGMT="$PROVII_ROOT/provii-management"

check_file_contains "$MGMT/src/services/verifier-manager.ts" "$VK_ID" "VK_ID in verifier-manager"
check_file_contains "$MGMT/src/schemas/verifier.ts" "default(\[$VK_ID\])" "VK_ID in schema default"
echo ""

# ─────────────────────────────────────────────
# provii-admin-portal
# ─────────────────────────────────────────────
echo "── provii-admin-portal ──"
ADMIN="$PROVII_ROOT/provii-admin-portal"

check_file_contains "$ADMIN/src/index.tsx" "$VK_ID" "VK_ID in index.tsx"
check_file_contains "$ADMIN/src/routes/verifier.ts" "$VK_ID" "VK_ID in verifier route"
check_file_contains "$ADMIN/src/routes/admin.ts" "$VK_ID" "VK_ID in admin route"
check_file_contains "$ADMIN/src/routes/customers.ts" "$VK_ID" "VK_ID in customers route"
check_file_contains "$ADMIN/src/components/verifier/AddVerifierForm.tsx" "$VK_ID" "VK_ID in AddVerifierForm"
check_file_contains "$ADMIN/src/components/verifier/PolicyCreateForm.tsx" "$VK_ID" "VK_ID in PolicyCreateForm"
check_file_contains "$ADMIN/src/components/verifier/PolicyEditor.tsx" "$VK_ID" "VK_ID in PolicyEditor"
check_file_contains "$ADMIN/src/middleware/provii-verifier-proxy.ts" "$VK_ID" "VK_ID in provii-verifier-proxy"
echo ""

# ─────────────────────────────────────────────
# provii-mobile
# ─────────────────────────────────────────────
echo "── provii-mobile ──"
WMOB="$PROVII_ROOT/provii-mobile"

check_file_contains "$WMOB/ios/ProviiWallet/ProviiWallet/Core/Repositories/WalletRepository.swift" "vkID = $VK_ID" "VK_ID in iOS WalletRepository"
check_file_contains "$WMOB/ios/ProviiWallet/ProviiWallet/Utils/Helpers/QRUtils.swift" "verifyingKeyId: $VK_ID" "VK_ID in iOS QRUtils"
check_file_contains "$WMOB/android/app/src/main/java/com/provii/wallet/data/WalletRepository.kt" "VK_ID = $VK_ID" "VK_ID in Android WalletRepository"
echo ""

# ─────────────────────────────────────────────
# provii-verifier (hosted path)
# ─────────────────────────────────────────────
echo "── provii-verifier (hosted path) ──"
HB="$PROVII_ROOT/provii-verifier"

check_file_contains "$HB/backend/src/types/responses.rs" "verifying_key_id: $VK_ID" "VK_ID in test responses"
echo ""

# ─────────────────────────────────────────────
# Check for stale OLD VK_ID references
# ─────────────────────────────────────────────
echo "── Stale reference scan ──"
echo "  Scanning for any remaining references to old VK IDs..."

# Known old VK IDs to check for
OLD_IDS=("4233343644" "1621794318" "2031517468")

for OLD_ID in "${OLD_IDS[@]}"; do
    if [[ "$OLD_ID" == "$VK_ID" ]]; then
        continue  # Skip current VK_ID
    fi

    for REPO in provii-verifier provii-mobile-sdk provii-agegate provii-management provii-admin-portal provii-mobile; do
        REPO_PATH="$PROVII_ROOT/$REPO"
        if [[ ! -d "$REPO_PATH" ]]; then
            continue
        fi

        # Search source files only (exclude node_modules, target, build dirs, binary files)
        STALE=$(grep -r --include='*.rs' --include='*.ts' --include='*.tsx' --include='*.swift' --include='*.kt' \
            -l "$OLD_ID" "$REPO_PATH/src" "$REPO_PATH/backend/src" "$REPO_PATH/crates" \
            "$REPO_PATH/ios" "$REPO_PATH/android" 2>/dev/null || true)

        if [[ -n "$STALE" ]]; then
            CHECKS=$((CHECKS + 1))
            echo "  FAIL: Stale VK_ID $OLD_ID found in $REPO:"
            echo "$STALE" | while read -r f; do echo "        $f"; done
            ERRORS=$((ERRORS + 1))
        fi
    done
done

echo "  OK: Stale reference scan complete"
echo ""

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo "=== Summary ==="
echo "Checks: $CHECKS"
echo "Errors: $ERRORS"
echo ""

if [[ $ERRORS -gt 0 ]]; then
    echo "FAILED: $ERRORS inconsistencies found!"
    exit 1
else
    echo "PASSED: All references are consistent with manifest."
    exit 0
fi
