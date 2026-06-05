# Issuer Package Generator

Generate issuer identity and RedJubJub cryptographic signing keys for the Provii admin portal. Officers and client apps are managed via the admin portal GUI after import.

## Why This Tool?

RedJubJub keypair generation is computationally intensive and requires the `provii-crypto` Rust library. Cloudflare Workers have strict CPU/memory limits, making it impractical to generate keys in the admin portal. This CLI tool runs on your local machine with full access to `provii-crypto`, generating production-ready cryptographic material.

## Features

- ✅ Proper RedJubJub signature keys (not Ed25519 substitutes)
- ✅ Configurable default policies and schemas
- ✅ Interactive or non-interactive modes
- ✅ Self-verification of generated keys
- ✅ JSON export for admin portal import
- ✅ Officers and client apps managed via GUI after import

## Installation

```bash
cd tools/issuer-gen
cargo build --release
```

## Usage

### Interactive Mode (Recommended)

```bash
cargo run --release
```

The tool will guide you through:
1. **Issuer Identity**: Organization name, domain, RP ID
2. **Signing Keys**: Automatically generates RedJubJub keypair
3. **Default Policies**: Select schemas, validity periods, revocation settings

### Non-Interactive Mode (Scripting)

```bash
cargo run --release -- --non-interactive --output my-issuer.json
```

### Example Output

```json
{
  "generated_at": "2025-10-23T00:00:00Z",
  "generated_by": "issuer-gen v0.2.0",
  "issuer_kid": "australian-government-20251023",
  "organization_name": "Australian Government",
  "rp_id": "issuer.provii.app",
  "domain": "issuer.provii.app",
  "signing_keys": {
    "key_id": "australian-government-20251023-key-1729728000",
    "private_key": "aB3dF5g...",
    "public_key": "xY7wQ9r...",
    "key_type": "redjubjub"
  },
  "default_schemas": ["https://schema.org/credentials/age"],
  "max_validity_days": 365,
  "allow_revocation": true,
  "key_rotation_days": 90
}
```

## Security Warnings

⚠️ **CRITICAL SECURITY REQUIREMENTS:**

1. **DELETE THE FILE AFTER IMPORT**
   - The generated JSON contains UNENCRYPTED private signing keys
   - Only the admin portal has KEK (Key Encryption Key) to encrypt these
   - File must be deleted immediately after upload

2. **SECURE TRANSMISSION**
   - Only upload via HTTPS to admin.zerokp.id
   - Do NOT email or share the file
   - Do NOT commit to version control

3. **ADMIN ACCESS ONLY**
   - Only super_admin role can import issuers
   - Audit logs track all import operations

## Workflow

### Step 1: Generate Package

```bash
cd tools/issuer-gen
cargo run --release
```

Follow the interactive prompts to generate issuer identity and signing keys. Output: `issuer-package-YYYYMMDD-HHMMSS.json`

### Step 2: Import to Admin Portal

1. Visit https://admin.zerokp.id
2. Navigate to **Issuer Management**
3. Click **Import Issuer**
4. Upload the generated JSON file
5. Review the package details
6. Click **Import Issuer**

The admin portal will:
- ✅ Encrypt the private signing key with KEK
- ✅ Store encrypted data in Cloudflare KV
- ✅ Create issuer configuration with default policies
- ✅ Log the import operation

### Step 3: Add Officers (for in-person issuance)

1. Navigate to **Officers** tab in the admin portal
2. Click **Add Officer**
3. Enter officer name, email, and role (admin/issuer/viewer)
4. System generates HMAC secret and encrypts with KEK
5. Officer can now authenticate and issue credentials in-person

### Step 4: Add Client Apps (for API-based issuance)

1. Navigate to **Client Apps** tab in the admin portal
2. Click **Add Client App**
3. Configure app name, permissions, and API endpoints
4. System generates API credentials
5. Client app can now issue credentials via API

### Step 5: Manage via GUI

All ongoing management is handled through the admin portal:
- Key rotation and lifecycle management
- Officer permissions and HMAC secrets
- Client app credentials and permissions
- Policies and schema updates

### Step 6: Clean Up

```bash
# DELETE the source file
rm issuer-package-*.json
```

## What Gets Encrypted?

The admin portal encrypts the following before KV storage:

| Field | Encryption | Algorithm | Key |
|-------|-----------|-----------|-----|
| Private Signing Key | ✅ Yes | AES-256-GCM | KEK (from Cloudflare Secrets) |
| Officer HMAC Secrets (added via GUI) | ✅ Yes | AES-256-GCM | KEK (from Cloudflare Secrets) |
| Public Verification Key | ❌ No | N/A | Stored plaintext |
| Issuer Metadata | ❌ No | N/A | Stored plaintext |

**Encryption Format**: `nonce (12 bytes) || ciphertext || auth_tag (16 bytes)`

**KEK Management**:
- Production: `ISSUER_KEK` secret
- Sandbox: `SANDBOX_ISSUER_KEK` secret

## KV Storage Structure

After import, the following KV entries are created:

```
ISSUER_KEYS (or SANDBOX_ISSUER_KEYS):
  rj:keypair:australian-government-20251023-key-1729728000 → {
    sk: "base64url(encrypted_private_key)",
    vk: "base64url(public_key)",
    encrypted: true,
    kid: "australian-government-20251023-key-1729728000"
  }

ISSUER_CONFIG (or SANDBOX_ISSUER_CONFIG):
  issuer:config → {
    issuer_id: "did:provii:australian-government-20251023",
    rp_id: "issuer.provii.app",
    default_kid: "australian-government-20251023-key-1729728000",
    default_policy: { ... }
  }
```

Officers and client apps are added separately via the admin portal GUI and stored in their respective KV namespaces with encrypted secrets.

## Verification

The tool performs self-verification before exporting:

1. ✅ Generates RedJubJub keypair
2. ✅ Signs test credential message
3. ✅ Verifies signature with public key
4. ✅ Validates public key is on Jubjub curve
5. ✅ Exports if all checks pass

## Comparison: Manual vs Import

| Method | RedJubJub Keys | Security | Speed | Recommended |
|--------|---------------|----------|-------|-------------|
| **Import (this tool)** | ✅ Proper | ✅ Excellent | ⚡ Fast | ✅ **YES** |
| Manual (admin portal) | ❌ Ed25519 placeholder | ⚠️ Limited | 🐌 Slow | ❌ Development only |

**Production Requirement**: You MUST use this tool for production issuers. The manual creation flow in the admin portal uses Ed25519 keys which are NOT compatible with the Provii issuer's RedJubJub signature library.

## Troubleshooting

### Error: "Invalid signature bytes"
- The tool performs self-verification. If you see this error, there's a bug in key generation.
- File an issue with the full error output.

### Error: "Public key is NOT a valid Jubjub point"
- Indicates corruption in key generation.
- Try running the tool again.

### Import fails: "Missing required field"
- Ensure you're uploading the correct JSON file
- Check that all fields are present in the package

### Import fails: "KEK secret not found"
- Admin must configure `ISSUER_KEK` or `SANDBOX_ISSUER_KEK` in Cloudflare Secrets Store
- Contact infrastructure team

## Development

Build for development:
```bash
cargo build
cargo run
```

Build for release:
```bash
cargo build --release
./target/release/issuer-gen
```

Run with custom output:
```bash
cargo run -- --output ~/Desktop/my-issuer.json
```

## License

Same as provii-crypto parent project.

## Support

For issues or questions:
- File issue: https://github.com/provii/provii-crypto/issues
- Security concerns: security@provii.app
