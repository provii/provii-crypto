# tools

Operational binaries and diagnostic utilities that support the Provii crypto
workspace.

## Components

- `keygen`: Generates RedJubjub issuer key pairs, produces Cloudflare KV
  payloads, JWKS snippets, and performs a round-trip signature verification.
- `tests/test_signature.rs`: Standalone diagnostic binary that highlights
  mismatches between off-circuit and in-circuit signature computations.

## Keygen Usage

```
cargo run -p provii-keygen-tool --release
```

The binary prints the generated secret/public keys (hex and base64url), the KV
entry expected by the issuer service, and a JWKS entry ready for distribution.
It also verifies the sample credential signature before exiting.

## Signature Diagnostic Usage

The diagnostic script lives outside the Cargo workspace. Compile it directly
with `rustc` (or add a lightweight manifest if you prefer using Cargo):

```
rustc tools/tests/test_signature.rs -o target/test_signature
./target/test_signature
```

The program walks through signature creation, challenge hashing, scalar
reductions, and the verification equation. Use it to investigate mismatches
between host and circuit behaviour.
