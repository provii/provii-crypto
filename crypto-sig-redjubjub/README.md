# crypto-sig-redjubjub

RedJubjub-inspired credential signatures tailored to the Provii age proof
system. The implementation mirrors the scalar-field behaviour of the Groth16
circuit and is **not** compatible with the Zcash RedJubjub reference.

## Capabilities

- Issuer key generation (`generate_keypair`) producing 32-byte signing and
  verification keys.
- Credential signing (`sign_cred_v2`) and verification (`verify_cred_v2`) over
  `CredMsgV2` messages from `crypto-commons`.
- Deterministic challenge computation that matches circuit field reductions.
- Error reporting via the `RedJubjubError` enum.

## Usage

```rust
use provii_crypto_sig_redjubjub::{generate_keypair, sign_cred_v2, verify_cred_v2};
use provii_crypto_commons::CredMsgV2;

let (sk, vk) = generate_keypair();
let credential = CredMsgV2 {
    v: 2,
    kid: "provii:2026-05".into(),
    c: [0u8; 32],
    iat: 1_706_000_000,
    exp: 1_736_000_000,
    schema: "provii.age/0".into(),
};

let signature = sign_cred_v2(&credential, &sk)?;
verify_cred_v2(&credential, &signature, &vk)?;
```

## Testing

```
cargo test -p crypto-sig-redjubjub
```

The test suite checks signature round-trips and the field-reduction behaviour
critical to circuit compatibility.
