# crypto-circuit-age

Groth16 circuit implementation for Provii’s age verification credential. The
crate packages the Jubjub gadgets, Pedersen hash constants, and test harnesses
required to synthesise the circuit used by the prover and verifier crates.

## Contents

- `src/gadgets/`: Jubjub ECC primitives, Pedersen hash gadgets, and circuit
  constants sourced from Zcash Sapling tooling.
- `examples/`: Utility binaries for parameter generation, key checks, and proof
  sanity checks.
- `tests/`: Layout, parity, soundness, and constraint regression tests that
  guard circuit integrity.

## Usage

### Parameter Generation

Run the provided example to generate proving/verifying parameters:

```
cargo run -p crypto-circuit-age --example gen_params --release -- \
    --pk ./params/proving_key.bin \
    --vk ./params/verifying_key.bin
```

### Proof Sanity Check

```
cargo run -p crypto-circuit-age --example test_proof --release -- \
    --pk ./params/proving_key.bin \
    --vk ./params/verifying_key.bin
```

*(See the example sources for optional arguments and expected inputs.)*

## Testing

```
cargo test -p crypto-circuit-age
```

The tests validate circuit layout correctness and parity between in-circuit and
host-side primitives. Always run them after modifying gadgets or constants.
