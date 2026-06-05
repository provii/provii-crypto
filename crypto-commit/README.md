# crypto-commit

Pedersen commitment helpers that mirror the circuit implementation used by
Provii’s age credential proofs. The crate provides host-side utilities for
constructing commitments and nullifiers that remain consistent with the
Groth16 circuit in `crypto-circuit-age`.

## Features

- `pedersen_commit_dob_validated` for committing to a date of birth (days since epoch).
- `pedersen_nullifier` for deriving the credential nullifier used in
  anti-replay checks.
- `generate_commitment_randomness` for producing bit-level randomness in the
  format expected by the circuit.

## Usage

```rust
use provii_crypto_commit::{pedersen_commit_dob_validated, pedersen_nullifier, generate_commitment_randomness};
use rand::thread_rng;

let mut rng = thread_rng();
let randomness = generate_commitment_randomness(&mut rng, 192);
let commitment = pedersen_commit_dob_validated(7300, &randomness)?;

let nullifier = pedersen_nullifier(&commitment);
assert_eq!(commitment.len(), 32);
assert_eq!(nullifier.len(), 32);
```

## Testing

```
cargo test -p crypto-commit
```

The tests cover determinism and statistical properties of the randomness
utilities. Run them whenever modifying commitment semantics.
