<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/provii-logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="./assets/provii-logo-light.png">
    <img alt="Provii" src="./assets/provii-logo-light.png" width="200">
  </picture>
</p>

<h1 align="center">provii-crypto</h1>

<p align="center">
BLS12-381 signatures, Pedersen commitments, Groth16 zero knowledge proofs, and RedJubjub credential signing. One Rust workspace, compiled to native, WASM, mobile, and UniFFI bindings.
</p>

<p align="center">
  <a href="https://github.com/provii/provii-crypto/actions/workflows/ci.yml"><img src="https://github.com/provii/provii-crypto/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/provii-crypto-commons"><img src="https://img.shields.io/crates/v/provii-crypto-commons.svg" alt="crates.io"></a>
  <a href="https://docs.rs/provii-crypto-commons"><img src="https://img.shields.io/docsrs/provii-crypto-commons" alt="docs.rs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-blue" alt="Licence"></a>
  <img src="https://img.shields.io/badge/MSRV-1.85-orange" alt="MSRV 1.85">
</p>

## Crates

Eight library crates, one integration test crate, and two CLI tools. All share a single version (`0.1.0`), edition, MSRV, and licence through the workspace `Cargo.toml`.

| Crate | Purpose |
| --- | --- |
| `provii-crypto-commons` | Shared error types, domain separation constants, credential message structures, and serialisation helpers. Supports `no_std` via the `std` feature gate. |
| `provii-crypto-commit` | Pedersen commitments over the Jubjub curve using Sapling generators. Provides `pedersen_commit_dob_validated` for date of birth binding and `pedersen_nullifier` for deterministic credential identifiers. |
| `provii-crypto-sig-redjubjub` | Custom RedJubjub signature scheme on the Jubjub prime order subgroup. Signs credential prehashes with BLAKE2s domain separation. Not Zcash compatible. |
| `provii-crypto-circuit-age` | Groth16 arithmetic circuit (BLS12-381) that proves age eligibility without revealing date of birth. Encodes Pedersen commitment opening, RedJubjub signature verification, nullifier derivation, and relying party binding as R1CS constraints. |
| `provii-crypto-public-inputs` | Canonical bit packing of the 8 BLS12-381 scalar field elements the circuit exposes: direction, cutoff, RP hash, issuer verification key, credential nullifier. |
| `provii-crypto-prover` | High level Groth16 proof generation. Loads proving parameters, synthesises the age circuit, serialises the output, and returns it as bytes. Multicore on desktop, single threaded on WASM and mobile. |
| `provii-crypto-verifier` | Groth16 proof verification against a prepared verifying key registry. Assembles public inputs canonically and delegates to Bellman. |
| `provii-crypto-protocol` | PKCE S256 challenges, nonce generation (platform aware for WASM via `getrandom`), relying party challenge binding with SHA-256, and origin hashing. |
| `provii-crypto-e2e-tests` | Cross crate integration tests exercising the full issuance and verification pipeline. Not published. |
| `provii-keygen-tool` | CLI for generating RedJubjub issuer key pairs. Located in `tools/keygen`. |
| `issuer-gen` | Interactive CLI for provisioning issuer credentials with metadata. Located in `tools/issuer-gen`. |

API documentation for each published crate is on [docs.rs](https://docs.rs/provii-crypto-commons).

## Usage

Add the crates you need to your `Cargo.toml`. Most consumers want the prover, verifier, protocol, or signature crate.

```toml
[dependencies]
provii-crypto-commons = "0.1"
provii-crypto-commit = "0.1"
provii-crypto-sig-redjubjub = "0.1"
provii-crypto-prover = "0.1"
provii-crypto-verifier = "0.1"
provii-crypto-protocol = "0.1"
```

Generating a Pedersen commitment and its nullifier:

```rust
use provii_crypto_commit::{
    generate_commitment_randomness, pedersen_commit_dob_validated, pedersen_nullifier,
};
use rand::rngs::OsRng;

fn main() -> Result<(), provii_crypto_commons::Error> {
    let dob_days: i32 = 7300; // ~20 years from epoch
    let r_bits = generate_commitment_randomness(&mut OsRng, 192);

    let commitment = pedersen_commit_dob_validated(dob_days, &r_bits)?;
    let nullifier = pedersen_nullifier(&commitment);

    assert_eq!(commitment.len(), 32);
    assert_eq!(nullifier.len(), 32);
    Ok(())
}
```

## Compiling for other targets

### WASM

Several crates compile to `wasm32-unknown-unknown` for use in Cloudflare Workers. The workspace includes a `[profile.worker]` optimised for minimal binary size (`opt-level = "z"`, fat LTO, panic abort, single codegen unit).

```sh
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --profile worker -p provii-crypto-protocol
```

On WASM targets, `provii-crypto-protocol` uses `getrandom` with the `js` feature for nonce generation, and `provii-crypto-prover` disables Bellman's `multicore` feature to avoid thread dependencies. These switches are automatic via `cfg(target_arch = "wasm32")` in each crate's `Cargo.toml`.

### Mobile (iOS and Android)

The workspace includes a `[profile.mobile]` with thin LTO and `opt-level = 2` for a balance of proof generation speed and binary size. The `provii-mobile-sdk` repository wraps these crates through UniFFI to produce Swift and Kotlin bindings. This repository does not contain UniFFI definitions itself.

```sh
# iOS (aarch64)
cargo build --target aarch64-apple-ios --profile mobile --workspace

# Android (aarch64)
cargo build --target aarch64-linux-android --profile mobile --workspace
```

On Android and iOS targets, Bellman's `multicore` feature is disabled automatically via conditional dependencies in `provii-crypto-prover` and `provii-crypto-circuit-age`.

## Security

Secret data never touches a comparison operator. All equality checks on secret material go through `subtle::ConstantTimeEq::ct_eq()`, and the signing and proving paths contain no branches or array indexing driven by secret values.

Key material is zeroed on drop. Witness and circuit types (`AgeWitness`, `AgeCircuit`) along with credential attestation structures derive both `Zeroize` and `ZeroizeOnDrop`. `SigningKey` in the RedJubjub crate implements `Zeroize` with a manual `Drop` that calls `zeroize()`. Signing nonces are zeroed via volatile writes after use.

`#[deny(unsafe_code)]` is set at the workspace level. Every library crate goes further with `#![forbid(unsafe_code)]` at the crate root. One exception exists: `provii-crypto-sig-redjubjub` uses `#![deny(unsafe_code)]` instead, because two `#[allow(unsafe_code)]` blocks perform `from_raw_parts_mut` volatile writes to zeroize `JubjubScalar` fields. The upstream `jubjub` crate does not implement `Zeroize` on its scalar type, so we do it ourselves. Both blocks carry written safety invariants explaining why.

Clippy denies `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, and `cast_possible_truncation` among other lints across the entire workspace. Library functions return `Result`.

The `fuzz/` directory contains libFuzzer targets for the cryptographic crates.

## Minimum supported Rust version

The MSRV is **1.85**, enforced by `rust-version = "1.85"` in the workspace `Cargo.toml`. Bumping the MSRV is a semver minor change and will be noted in `CHANGELOG.md`.

## Licence

Licensed under [Apache-2.0](LICENSE).
