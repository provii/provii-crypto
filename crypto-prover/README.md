# crypto-prover

High-level Groth16 proof generation for Provii age credentials. The crate wraps
`bellman` to create proofs, provides extensive logging and diagnostics, and
handles canonical public-input assembly via `crypto-public-inputs`.

## Features

- `load_proving_key` for loading Groth16 parameters from bytes.
- `prove_age_snark` and `prove_age_snark_auto` convenience functions that
  orchestrate witness validation, circuit synthesis checks, and proof
  generation.
- Built-in diagnostics: logging of public inputs, constraint counts, and retry
  logic when synthesis fails.
- Shared runtime configuration (`RuntimeConfig`) with mobile-aware defaults.

## Usage

```rust
use provii_crypto_prover::{load_proving_key, prove_age_snark_auto};
use provii_crypto_circuit_age::{AgeWitness};
use provii_crypto_commons::Result;

fn prove(pk_bytes: &[u8], witness: AgeWitness, cutoff_days: u32, rp_challenge: [u8; 32]) -> Result<Vec<u8>> {
    let params = load_proving_key(pk_bytes)?;
    let proof = prove_age_snark_auto(&params, cutoff_days, rp_challenge, witness, 1)?;
    Ok(proof.proof)
}
```

*(Error handling trimmed for clarity.)*

### Proving Parameters

The crate expects Groth16 parameters generated for the age circuit in
`crypto-circuit-age`. Ensure they are generated securely and distributed to the
prover host via a trusted channel.

## Testing

```
cargo test -p crypto-prover
```

Some tests require valid proving parameters. Provide the necessary fixtures or
feature-gate such tests when running in constrained environments.
