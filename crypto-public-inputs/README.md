# crypto-public-inputs

Canonical assembly of Groth16 public inputs for the Provii age-proof circuit.
This crate ensures that off-circuit hosts and the in-circuit gadget agree on
bit ordering, field packing, and domain separation.

## Capabilities

- Little-endian bit extraction via `bits_le_from_bytes`.
- Manual and diagnostic packing routines that preserve high-order bits.
- Public-input assembly helpers (`assemble_public_inputs_canonical`,
  `assemble_public_inputs_diagnostic`, `assemble_public_inputs_manual`).
- Unit tests that lock in behaviour around edge bits (e.g. bit 254).

## Usage

```rust
use provii_crypto_public_inputs::assemble_public_inputs_canonical;

let cutoff_days = 6570; // 18 years
let rp_hash = [0u8; 32];
let issuer_vk_bytes = [1u8; 32];
let cred_nullifier = [2u8; 32];

let public_inputs = assemble_public_inputs_canonical(
    true, // direction: over-age
    cutoff_days,
    rp_hash,
    issuer_vk_bytes,
    cred_nullifier,
).expect("assembly must produce 8 elements");
assert_eq!(public_inputs.len(), 8);
```

For debugging bit-packing issues, call
`assemble_public_inputs_diagnostic` to emit warnings when the standard
multipacking routine would lose significant bits.

## Testing

```
cargo test -p crypto-public-inputs
```

The unit tests cover the edge cases that previously caused mismatches between
host and circuit representations.
