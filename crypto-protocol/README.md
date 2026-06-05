# crypto-protocol

Protocol-level helpers for the Provii age-verification flow. This crate handles
nonce generation, PKCE helpers, RP challenge binding, and replay tag
computation.

## Key Modules

- `nonce`: Secure nonce generation and entropy checks shared across services.
- `lib.rs`: PKCE helpers, RP challenge binding, origin hashing, replay tag,
  issuance consent message, and length-prefixed hash helper.

## Usage

```rust
use provii_crypto_protocol::{code_challenge_s256, generate_nonce, rp_challenge, compute_replay_tag};

let nonce = generate_nonce()?;
let origin = "https://relying-party.example";
let rp_hash = rp_challenge(origin, &nonce);
let tag = compute_replay_tag(&rp_hash, &nonce);
let pkce = code_challenge_s256("verifier-string");
```

*(Error handling omitted for brevity.)*

## Testing

```
cargo test -p crypto-protocol
```

The tests cover RP challenge determinism, replay-tag construction, length
prefixing, and nonce entropy. Run them whenever any of these helpers change.
