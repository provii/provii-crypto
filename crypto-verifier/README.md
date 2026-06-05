# crypto-verifier

Groth16 verifier for Provii age proofs. The crate prepares verifying keys,
loads Groth16 proofs, and extracts canonical public inputs for downstream use.

## Highlights

- `load_vk` and `init_with_vk_bytes` helpers for preparing verifying keys at
  process start.
- `verify_age_snark` which validates a Groth16 proof and returns structured
  public inputs (`VerifyResult`).
- Extensive diagnostic logging to aid integration with host services.

## Usage

```rust
use provii_crypto_verifier::{init_with_vk_bytes, verify_age_snark};
use provii_crypto_commons::Result;

fn verify(proof: &[u8], vk_bytes: &[u8]) -> Result<()> {
    init_with_vk_bytes(vk_bytes)?;
    let result = verify_age_snark(
        proof,
        6570,
        [0u8; 32],
        [1u8; 32],
        [2u8; 32],
    )?;
    println!("Cutoff days: {}", result.cutoff_days);
    Ok(())
}
```

## Testing

```
cargo test -p crypto-verifier
```

Integration tests rely on valid proving/verifying key pairs. Ensure you have
consistent parameters when running verification tests.
