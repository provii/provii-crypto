# crypto-commons

Shared primitives for the Provii crypto workspace. This crate defines the error
types, constants, timestamp representations, and credential/challenge data
structures that connect the signature, circuit, prover, and verifier crates.

## Highlights

- `Error` and `Result` aliases that unify error handling across crates.
- Domain-separation constants for signatures, commitments, and challenges.
- `Timestamp`, `CredMsgV2`, and `AgeSnarkProofV2` structures.
- Helper utilities such as `cred_v2_prehash_bytes` and `vec_to_array32`.

## Usage

Add the crate via the workspace dependency or through Cargo:

```rust
use provii_crypto_commons::{cred_v2_prehash_bytes, CredMsgV2, Timestamp};

let cred = CredMsgV2 {
    v: 2,
    kid: "provii:2026-05".into(),
    c: [0u8; 32],
    iat: 1_706_000_000,
    exp: 1_736_000_000,
    schema: "provii.age/0".into(),
};

let prehash = cred_v2_prehash_bytes(
    cred.v,
    &cred.kid,
    &cred.c,
    cred.iat,
    cred.exp,
    &cred.schema,
);
assert!(!prehash.is_empty());
```

## Testing

```
cargo test -p crypto-commons
```

The tests validate serialization round-trips and helper utilities. Ensure they
pass before publishing updates consumed by downstream crates.
