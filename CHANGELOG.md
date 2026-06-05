# Changelog

All notable changes to provii-crypto will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses 0ver (0.x.y). Breaking changes are expected until 1.0.

## [v0.1.0] - unreleased

Initial Provii release. Zero knowledge proof circuits, commitment schemes, signature primitives, and protocol helpers for privacy-preserving age verification.

### Added
- Groth16 age verification circuit with direction mux (crypto-circuit-age)
- RedJubjub signature scheme on Jubjub prime order subgroup (crypto-sig-redjubjub)
- Pedersen commitments and nullifiers (crypto-commit)
- PKCE S256 challenges, nonce generation, RP challenge binding (crypto-protocol)
- Canonical public input bit packing (crypto-public-inputs)
- Common error types, domain separation constants, credential structures (crypto-commons)
- Zero knowledge proof generation and verification (crypto-prover, crypto-verifier)
- CLI tools for key generation and issuer provisioning (tools/)
- 23 fuzz targets covering all critical paths
