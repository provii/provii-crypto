#!/usr/bin/env bash
set -euo pipefail

##############################################################################
# propagate-zk-params.sh
#
# Propagates ZK parameter updates to downstream repos by reading values from
# a zk-params-manifest.json and performing repo-specific sed replacements.
#
# Usage:
#   ./scripts/propagate-zk-params.sh \
#     --manifest <path-to-manifest.json> \
#     --repo-type <type> \
#     --repo-path <path> \
#     [--vk-binary <path-to-vk-binary>]
#
# Arguments:
#   --manifest    Path to zk-params-manifest.json
#   --repo-type   One of: provii-verifier, provii-mobile-sdk, provii-agegate, provii-management,
#                 provii-admin-portal, provii-mobile
#   --repo-path   Path to the cloned target repo
#   --vk-binary   (Optional) Path to the VK binary file (required for provii-verifier)
##############################################################################

MANIFEST=""
REPO_TYPE=""
REPO_PATH=""
VK_BINARY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="$2"
      shift 2
      ;;
    --repo-type)
      REPO_TYPE="$2"
      shift 2
      ;;
    --repo-path)
      REPO_PATH="$2"
      shift 2
      ;;
    --vk-binary)
      VK_BINARY="$2"
      shift 2
      ;;
    *)
      echo "ERROR: Unknown argument: $1"
      echo "Usage: $0 --manifest <path> --repo-type <type> --repo-path <path> [--vk-binary <path>]"
      exit 1
      ;;
  esac
done

if [[ -z "$MANIFEST" || -z "$REPO_TYPE" || -z "$REPO_PATH" ]]; then
  echo "ERROR: --manifest, --repo-type, and --repo-path are required."
  echo "Usage: $0 --manifest <path> --repo-type <type> --repo-path <path> [--vk-binary <path>]"
  exit 1
fi

if [[ ! -f "$MANIFEST" ]]; then
  echo "ERROR: Manifest file not found: $MANIFEST"
  exit 1
fi

if [[ ! -d "$REPO_PATH" ]]; then
  echo "ERROR: Repo path is not a directory: $REPO_PATH"
  exit 1
fi

# Validate repo-type
VALID_TYPES="provii-verifier provii-verifier-hosted provii-mobile-sdk provii-agegate provii-management provii-admin-portal provii-mobile"
if ! echo "$VALID_TYPES" | grep -qw "$REPO_TYPE"; then
  echo "ERROR: Invalid repo-type '$REPO_TYPE'. Must be one of: $VALID_TYPES"
  exit 1
fi

##############################################################################
# Parse manifest with jq
##############################################################################

echo "=== Parsing manifest: $MANIFEST ==="

NEW_VK_ID=$(jq -r '.vk_id' "$MANIFEST")
PK_SIZE_BYTES=$(jq -r '.pk_size_bytes' "$MANIFEST")
PK_BLAKE2S_HASH=$(jq -r '.pk_blake2s_hash' "$MANIFEST")
VK_BLAKE2B512_HASH=$(jq -r '.vk_blake2b512_hash' "$MANIFEST")
PK_URL=$(jq -r '.pk_url' "$MANIFEST")
EXPECTED_PUBLIC_INPUTS=$(jq -r '.expected_public_inputs' "$MANIFEST")
VK_SIZE_BYTES=$(jq -r '.vk_size_bytes' "$MANIFEST")

echo "  vk_id:                  $NEW_VK_ID"
echo "  pk_size_bytes:          $PK_SIZE_BYTES"
echo "  pk_blake2s_hash:        $PK_BLAKE2S_HASH"
echo "  vk_blake2b512_hash:     $VK_BLAKE2B512_HASH"
echo "  pk_url:                 $PK_URL"
echo "  expected_public_inputs: $EXPECTED_PUBLIC_INPUTS"
echo "  vk_size_bytes:          $VK_SIZE_BYTES"
echo ""

##############################################################################
# Helper: format integer with Rust-style underscores (e.g. 51419928 -> 51_419_928)
##############################################################################
format_rust_underscores() {
  local num="$1"
  # Reverse the string, insert underscores every 3 digits, reverse back
  echo "$num" | rev | sed 's/.\{3\}/&_/g' | sed 's/_$//' | rev
}

##############################################################################
# Helper: auto-detect old VK_ID from source file
# Args: $1 = file path, $2 = pattern to grep
# Returns the old VK_ID via stdout
##############################################################################
detect_old_vk_id() {
  local file="$1"
  local pattern="$2"
  local old_id

  if [[ ! -f "$file" ]]; then
    echo "ERROR: Cannot detect old VK_ID - file not found: $file" >&2
    exit 1
  fi

  old_id=$(grep -oE "$pattern" "$file" | head -1 | grep -oE '[0-9]+')
  if [[ -z "$old_id" ]]; then
    echo "ERROR: Cannot detect old VK_ID from $file using pattern: $pattern" >&2
    exit 1
  fi
  echo "$old_id"
}

##############################################################################
# Helper: sed in-place (portable across macOS and Linux)
##############################################################################
sed_inplace() {
  if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' "$@"
  else
    sed -i "$@"
  fi
}

##############################################################################
# Repo-specific propagation
##############################################################################

case "$REPO_TYPE" in

  #=========================================================================
  # provii-verifier
  #=========================================================================
  provii-verifier)
    echo "=== Propagating to provii-verifier ==="
    SRC_FILE="$REPO_PATH/src/lib.rs"

    OLD_VK_ID=$(detect_old_vk_id "$SRC_FILE" 'const VK_ID: u32 = [0-9]+')
    echo "  Detected old VK_ID: $OLD_VK_ID"

    # Detect old expected_inputs count
    OLD_INPUTS=$(grep -oE 'expected_inputs != [0-9]+' "$SRC_FILE" | head -1 | grep -oE '[0-9]+')
    echo "  Detected old expected_inputs: $OLD_INPUTS"

    # Detect old VK size from test assertions
    OLD_VK_SIZE=$(grep -oE 'VK file size should be [0-9]+ bytes' "$SRC_FILE" | head -1 | grep -oE '[0-9]+' | head -1)
    echo "  Detected old VK size: $OLD_VK_SIZE"

    # Copy VK binary
    if [[ -n "$VK_BINARY" ]]; then
      echo "  Removing old VK binaries not matching new VK_ID..."
      for f in "$REPO_PATH"/assets/vk.*.bin; do
        if [[ -f "$f" && "$f" != "$REPO_PATH/assets/vk.${NEW_VK_ID}.bin" ]]; then
          echo "    Removing: $f"
          rm -f "$f"
        fi
      done
      echo "  Copying VK binary to assets/vk.${NEW_VK_ID}.bin"
      cp "$VK_BINARY" "$REPO_PATH/assets/vk.${NEW_VK_ID}.bin"
    else
      echo "  WARNING: --vk-binary not provided, skipping VK binary copy"
    fi

    # Replace include_bytes path
    echo "  Replacing include_bytes!(...) VK path"
    sed_inplace "s|include_bytes!(\"../assets/vk\.${OLD_VK_ID}\.bin\")|include_bytes!(\"../assets/vk.${NEW_VK_ID}.bin\")|g" "$SRC_FILE"

    # Replace VK_ID constant
    echo "  Replacing VK_ID constant"
    sed_inplace "s|VK_ID: u32 = ${OLD_VK_ID}|VK_ID: u32 = ${NEW_VK_ID}|g" "$SRC_FILE"

    # Replace VK checksum (128-char hex string after EXPECTED_VK_CHECKSUM_BLAKE2B512)
    echo "  Replacing EXPECTED_VK_CHECKSUM_BLAKE2B512"
    sed_inplace "s|\(EXPECTED_VK_CHECKSUM_BLAKE2B512.*= *\"\)[0-9a-f]\{1,128\}\"|\1${VK_BLAKE2B512_HASH}\"|" "$SRC_FILE"

    # Replace expected_inputs check
    echo "  Replacing expected_inputs != $OLD_INPUTS -> != $EXPECTED_PUBLIC_INPUTS"
    sed_inplace "s|expected_inputs != ${OLD_INPUTS}|expected_inputs != ${EXPECTED_PUBLIC_INPUTS}|g" "$SRC_FILE"

    # Replace "expects N public inputs" strings
    echo "  Replacing 'expects $OLD_INPUTS public inputs' strings"
    sed_inplace "s|expects ${OLD_INPUTS} public inputs|expects ${EXPECTED_PUBLIC_INPUTS} public inputs|g" "$SRC_FILE"

    # Replace "Expected N but VK wants" strings
    echo "  Replacing 'Expected $OLD_INPUTS but VK wants' string"
    sed_inplace "s|Expected ${OLD_INPUTS} but VK wants|Expected ${EXPECTED_PUBLIC_INPUTS} but VK wants|g" "$SRC_FILE"

    # Replace test VK_ID assertion
    echo "  Replacing test VK_ID assertion"
    sed_inplace "s|VK_ID, ${OLD_VK_ID},|VK_ID, ${NEW_VK_ID},|g" "$SRC_FILE"

    # Replace test VK size assertion
    if [[ -n "$OLD_VK_SIZE" ]]; then
      echo "  Replacing test VK size assertion: $OLD_VK_SIZE -> $VK_SIZE_BYTES"
      sed_inplace "s|VK file size should be ${OLD_VK_SIZE} bytes for version ${OLD_VK_ID}|VK file size should be ${VK_SIZE_BYTES} bytes for version ${NEW_VK_ID}|g" "$SRC_FILE"
      sed_inplace "s|, ${OLD_VK_SIZE},|, ${VK_SIZE_BYTES},|g" "$SRC_FILE"
    fi

    echo "  Done: provii-verifier"
    ;;

  #=========================================================================
  # provii-mobile-sdk
  #=========================================================================
  provii-mobile-sdk)
    echo "=== Propagating to provii-mobile-sdk ==="

    PK_FILE="$REPO_PATH/crates/ffi/src/proving_key.rs"
    VERIFY_FILE="$REPO_PATH/crates/ffi/src/verify.rs"

    OLD_VK_ID=$(detect_old_vk_id "$PK_FILE" 'VK_ID: u32 = [0-9]+')
    echo "  Detected old VK_ID: $OLD_VK_ID"

    # Detect old PK_SIZE (with possible underscores)
    OLD_PK_SIZE_RAW=$(grep -oE 'PK_SIZE: u64 = [0-9_]+' "$PK_FILE" | head -1 | sed 's/PK_SIZE: u64 = //')
    echo "  Detected old PK_SIZE (raw): $OLD_PK_SIZE_RAW"

    # Detect old PK_BLAKE2S
    OLD_PK_BLAKE2S=$(grep -oE 'PK_BLAKE2S.*= *"[0-9a-f]+"' "$PK_FILE" | head -1 | grep -oE '"[0-9a-f]+"' | tr -d '"')
    echo "  Detected old PK_BLAKE2S: $OLD_PK_BLAKE2S"

    # Format new PK_SIZE with underscores
    NEW_PK_SIZE_FORMATTED=$(format_rust_underscores "$PK_SIZE_BYTES")
    echo "  New PK_SIZE formatted: $NEW_PK_SIZE_FORMATTED"

    # proving_key.rs replacements
    echo "  Replacing VK_ID in proving_key.rs"
    sed_inplace "s|VK_ID: u32 = ${OLD_VK_ID}|VK_ID: u32 = ${NEW_VK_ID}|g" "$PK_FILE"

    echo "  Replacing PK_URL in proving_key.rs"
    sed_inplace "s|PK_URL:.*=.*\"https://[^\"]*\"|PK_URL: \&str = \"${PK_URL}\"|" "$PK_FILE"

    echo "  Replacing PK_SIZE in proving_key.rs"
    sed_inplace "s|PK_SIZE: u64 = ${OLD_PK_SIZE_RAW}|PK_SIZE: u64 = ${NEW_PK_SIZE_FORMATTED}|g" "$PK_FILE"

    echo "  Replacing PK_BLAKE2S hash in proving_key.rs"
    if [[ -n "$OLD_PK_BLAKE2S" ]]; then
      sed_inplace "s|${OLD_PK_BLAKE2S}|${PK_BLAKE2S_HASH}|g" "$PK_FILE"
    fi

    # Test assertions in proving_key.rs
    echo "  Replacing test VK_ID assertion in proving_key.rs"
    sed_inplace "s|ProvingKeyManager::VK_ID, ${OLD_VK_ID}|ProvingKeyManager::VK_ID, ${NEW_VK_ID}|g" "$PK_FILE"

    echo "  Replacing test PK_SIZE assertion in proving_key.rs"
    sed_inplace "s|ProvingKeyManager::PK_SIZE, ${OLD_PK_SIZE_RAW}|ProvingKeyManager::PK_SIZE, ${NEW_PK_SIZE_FORMATTED}|g" "$PK_FILE"

    # verify.rs replacements
    if [[ -f "$VERIFY_FILE" ]]; then
      echo "  Replacing verifying_key_id in verify.rs"
      sed_inplace "s|\"verifying_key_id\": *${OLD_VK_ID}u32|\"verifying_key_id\": ${NEW_VK_ID}u32|g" "$VERIFY_FILE"
      sed_inplace "s|\"verifying_key_id\": *${OLD_VK_ID}|\"verifying_key_id\": ${NEW_VK_ID}|g" "$VERIFY_FILE"
    fi

    echo "  Done: provii-mobile-sdk"
    ;;

  #=========================================================================
  # provii-agegate
  #=========================================================================
  provii-agegate)
    echo "=== Propagating to provii-agegate ==="

    CONFIG_FILE="$REPO_PATH/src/agegate/AgeGateConfig.ts"

    OLD_VK_ID=$(detect_old_vk_id "$CONFIG_FILE" 'DEFAULT_VERIFYING_KEY_ID = [0-9]+')
    echo "  Detected old VK_ID: $OLD_VK_ID"

    echo "  Replacing DEFAULT_VERIFYING_KEY_ID"
    sed_inplace "s|DEFAULT_VERIFYING_KEY_ID = ${OLD_VK_ID}|DEFAULT_VERIFYING_KEY_ID = ${NEW_VK_ID}|g" "$CONFIG_FILE"

    echo "  Replacing JSDoc verifyingKeyId example"
    sed_inplace "s|verifyingKeyId: ${OLD_VK_ID}|verifyingKeyId: ${NEW_VK_ID}|g" "$CONFIG_FILE"

    echo "  Replacing @default value"
    sed_inplace "s|@default ${OLD_VK_ID}|@default ${NEW_VK_ID}|g" "$CONFIG_FILE"

    echo "  Done: provii-agegate"
    ;;

  #=========================================================================
  # provii-management
  #=========================================================================
  provii-management)
    echo "=== Propagating to provii-management ==="

    VM_FILE="$REPO_PATH/src/services/verifier-manager.ts"
    SCHEMA_FILE="$REPO_PATH/src/schemas/verifier.ts"

    OLD_VK_ID=$(detect_old_vk_id "$VM_FILE" '\[[0-9]\+\]')
    # Fallback: try to detect from the schema file
    if [[ -z "$OLD_VK_ID" ]]; then
      OLD_VK_ID=$(detect_old_vk_id "$SCHEMA_FILE" '\.default\(\[[0-9]+\]\)')
    fi
    echo "  Detected old VK_ID: $OLD_VK_ID"

    echo "  Replacing array element in verifier-manager.ts"
    sed_inplace "s|\[${OLD_VK_ID}\]|\[${NEW_VK_ID}\]|g" "$VM_FILE"

    echo "  Replacing .default([...]) in verifier.ts"
    sed_inplace "s|\.default(\[${OLD_VK_ID}\])|.default([${NEW_VK_ID}])|g" "$SCHEMA_FILE"

    echo "  Done: provii-management"
    ;;

  #=========================================================================
  # provii-admin-portal
  #=========================================================================
  provii-admin-portal)
    echo "=== Propagating to provii-admin-portal ==="

    # Auto-detect OLD_VK_ID from one of the known files
    DETECT_FILE="$REPO_PATH/src/index.tsx"
    if [[ ! -f "$DETECT_FILE" ]]; then
      # Try to find any .ts or .tsx file that contains a VK ID pattern
      DETECT_FILE=$(grep -rl "${NEW_VK_ID}\|[0-9]\{10\}" "$REPO_PATH/src/" --include='*.ts' --include='*.tsx' 2>/dev/null | head -1 || true)
    fi

    # Try to detect from known files
    ADMIN_FILES=(
      "$REPO_PATH/src/index.tsx"
      "$REPO_PATH/src/routes/verifier.ts"
      "$REPO_PATH/src/routes/admin.ts"
      "$REPO_PATH/src/routes/customers.ts"
      "$REPO_PATH/src/components/verifier/AddVerifierForm.tsx"
      "$REPO_PATH/src/components/verifier/PolicyCreateForm.tsx"
      "$REPO_PATH/src/components/verifier/PolicyEditor.tsx"
      "$REPO_PATH/src/middleware/provii-verifier-proxy.ts"
    )

    # Detect OLD_VK_ID from any available source file
    OLD_VK_ID=""
    for f in "${ADMIN_FILES[@]}"; do
      if [[ -f "$f" ]]; then
        OLD_VK_ID=$(grep -oE '[0-9]{10}' "$f" | head -1 || true)
        if [[ -n "$OLD_VK_ID" && "$OLD_VK_ID" != "$NEW_VK_ID" ]]; then
          echo "  Detected old VK_ID from $(basename "$f"): $OLD_VK_ID"
          break
        fi
        OLD_VK_ID=""
      fi
    done

    if [[ -z "$OLD_VK_ID" ]]; then
      echo "ERROR: Cannot detect old VK_ID from provii-admin-portal source files"
      exit 1
    fi

    echo "  Replacing $OLD_VK_ID -> $NEW_VK_ID across .ts and .tsx files in src/"
    for f in "${ADMIN_FILES[@]}"; do
      if [[ -f "$f" ]]; then
        if grep -q "$OLD_VK_ID" "$f"; then
          echo "    Updating: $f"
          sed_inplace "s|${OLD_VK_ID}|${NEW_VK_ID}|g" "$f"
        fi
      fi
    done

    echo "  Done: provii-admin-portal"
    ;;

  #=========================================================================
  # provii-mobile
  #=========================================================================
  provii-mobile)
    echo "=== Propagating to provii-mobile ==="

    # iOS Swift files
    echo "  Processing iOS Swift files..."
    OLD_VK_ID=""
    while IFS= read -r swift_file; do
      if [[ -z "$OLD_VK_ID" ]]; then
        OLD_VK_ID=$(grep -oE 'vkID = [0-9]+' "$swift_file" 2>/dev/null | head -1 | grep -oE '[0-9]+' || true)
        if [[ -n "$OLD_VK_ID" ]]; then
          echo "  Detected old VK_ID from Swift: $OLD_VK_ID"
        fi
      fi
    done < <(find "$REPO_PATH/ios" -name '*.swift' -type f 2>/dev/null)

    if [[ -z "$OLD_VK_ID" ]]; then
      # Try Kotlin files for detection
      while IFS= read -r kotlin_file; do
        OLD_VK_ID=$(grep -oE 'VK_ID = [0-9]+' "$kotlin_file" 2>/dev/null | head -1 | grep -oE '[0-9]+' || true)
        if [[ -n "$OLD_VK_ID" ]]; then
          echo "  Detected old VK_ID from Kotlin: $OLD_VK_ID"
          break
        fi
      done < <(find "$REPO_PATH/android" -name '*.kt' -type f 2>/dev/null)
    fi

    if [[ -z "$OLD_VK_ID" ]]; then
      echo "ERROR: Cannot detect old VK_ID from provii-mobile source files"
      exit 1
    fi

    # Replace in iOS Swift files
    while IFS= read -r swift_file; do
      if grep -qE "(vkID = ${OLD_VK_ID}|verifyingKeyId: ${OLD_VK_ID})" "$swift_file" 2>/dev/null; then
        echo "    Updating iOS: $swift_file"
        sed_inplace "s|vkID = ${OLD_VK_ID}|vkID = ${NEW_VK_ID}|g" "$swift_file"
        sed_inplace "s|verifyingKeyId: ${OLD_VK_ID}|verifyingKeyId: ${NEW_VK_ID}|g" "$swift_file"
      fi
    done < <(find "$REPO_PATH/ios" -name '*.swift' -type f 2>/dev/null)

    # Replace in Android Kotlin files
    echo "  Processing Android Kotlin files..."
    while IFS= read -r kotlin_file; do
      if grep -qE "(VK_ID = ${OLD_VK_ID}|verifyingKeyId.*${OLD_VK_ID})" "$kotlin_file" 2>/dev/null; then
        echo "    Updating Android: $kotlin_file"
        sed_inplace "s|VK_ID = ${OLD_VK_ID}|VK_ID = ${NEW_VK_ID}|g" "$kotlin_file"
        sed_inplace "s|verifyingKeyId: ${OLD_VK_ID}|verifyingKeyId: ${NEW_VK_ID}|g" "$kotlin_file"
      fi
    done < <(find "$REPO_PATH/android" -name '*.kt' -type f 2>/dev/null)

    echo "  Done: provii-mobile"
    ;;

  #=========================================================================
  # provii-verifier (hosted path)
  #=========================================================================
  provii-verifier-hosted)
    echo "=== Propagating to provii-verifier (hosted path) ==="

    RESPONSES_FILE="$REPO_PATH/backend/src/types/responses.rs"

    OLD_VK_ID=$(detect_old_vk_id "$RESPONSES_FILE" 'verifying_key_id: [0-9]+')
    echo "  Detected old VK_ID: $OLD_VK_ID"

    echo "  Replacing verifying_key_id in responses.rs"
    sed_inplace "s|verifying_key_id: ${OLD_VK_ID}|verifying_key_id: ${NEW_VK_ID}|g" "$RESPONSES_FILE"

    echo "  Done: provii-verifier (hosted path)"
    ;;

esac

echo ""
echo "=== Propagation complete for $REPO_TYPE ==="
exit 0
