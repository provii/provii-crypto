# provii-crypto Architecture

This document describes the architecture of the provii-crypto library, including its crate structure, key design decisions, and data flow patterns.

## Overview

provii-crypto is a Rust workspace containing cryptographic primitives for privacy-preserving identity verification. The core functionality enables zero-knowledge proofs for age verification without revealing the actual birthdate.

## Crate Structure

```
provii-crypto/
├── crypto-commons/          # Shared types, utilities, and constants
├── crypto-sig-redjubjub/    # RedJubjub signature implementation
├── crypto-commit/           # Commitment schemes (Pedersen)
├── crypto-circuit-age/      # Age verification circuit (Bellman/Groth16)
├── crypto-prover/           # Zero-knowledge proof generation
├── crypto-verifier/         # Zero-knowledge proof verification
├── crypto-protocol/         # Protocol message types and serialisation
├── crypto-public-inputs/    # Public input assembly and handling
├── crypto-e2e-tests/        # End-to-end integration tests
└── tools/                   # CLI utilities
    ├── keygen/              # Key generation tool
    └── issuer-gen/          # Issuer key generation
```

## Dependency Graph

```
                    ┌─────────────────┐
                    │  crypto-commons │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
┌────────────────┐  ┌────────────────┐  ┌────────────────┐
│crypto-sig-     │  │ crypto-commit  │  │ crypto-public  │
│redjubjub       │  │                │  │ -inputs        │
└────────────────┘  └────────┬───────┘  └────────┬───────┘
                             │                   │
                             ▼                   │
                    ┌────────────────┐           │
                    │crypto-circuit- │◄──────────┘
                    │age             │
                    └────────┬───────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
     ┌────────────┐  ┌────────────┐  ┌────────────────┐
     │crypto-     │  │crypto-     │  │crypto-protocol │
     │prover      │  │verifier    │  │                │
     └────────────┘  └────────────┘  └────────────────┘
```

## Core Components

### crypto-commons

Shared foundational types used across the workspace:

- **Credential types**: `Credential`, `CredentialPrehash`
- **Scalar utilities**: Field element operations
- **Hashing**: Blake2s wrappers for credential hashing
- **Serialisation**: Common serialisation helpers

### crypto-sig-redjubjub

Implementation of the RedJubjub signature scheme over the Jubjub curve:

- **Key types**: `SigningKey`, `VerificationKey`
- **Signatures**: Schnorr-style signatures
- **Rerandomization**: Support for rerandomizable signatures

### crypto-commit

Pedersen commitment scheme implementation:

- **Commitments**: Binding and hiding commitments
- **Nullifiers**: Unique identifiers derived from secrets
- **Opening proofs**: Commitment opening verification

### crypto-circuit-age

Bellman/Groth16 circuit for age verification:

- **Circuit definition**: R1CS constraints for age check
- **Witness generation**: Private input preparation
- **Public inputs**: Age threshold, current date, commitment

### crypto-prover

Zero-knowledge proof generation:

- **Proof generation**: Groth16 proof creation
- **Proving key management**: PK loading and caching
- **Batch proving**: Multiple proofs in parallel (via rayon)

### crypto-verifier

Zero-knowledge proof verification:

- **Proof verification**: Groth16 proof checking
- **Verification key management**: VK loading
- **Batch verification**: Multiple proofs efficiently

### crypto-protocol

Protocol message types for network communication:

- **Request types**: Verification request structures
- **Response types**: Verification response structures
- **Serialisation**: Borsh and JSON encoding

### crypto-public-inputs

Public input handling for ZK proofs:

- **Input assembly**: Combining public values
- **Bit representation**: Field element to bits conversion
- **Validation**: Input bounds checking

## Data Flow

### Proof Generation Flow

```
1. User has: Credential (DOB, secret)
                    │
                    ▼
2. Create commitment: C = Commit(DOB, secret)
                    │
                    ▼
3. Generate witness: (DOB, secret, threshold, current_date)
                    │
                    ▼
4. Prove in circuit: age >= threshold
                    │
                    ▼
5. Output: Proof π, Public inputs (C, threshold, date)
```

### Verification Flow

```
1. Verifier receives: Proof π, Public inputs
                    │
                    ▼
2. Load verification key
                    │
                    ▼
3. Verify: Groth16.verify(VK, π, public_inputs)
                    │
                    ▼
4. Output: Accept/Reject
```

## Security Properties

### Cryptographic Guarantees

1. **Zero-Knowledge**: Verifier learns nothing beyond age >= threshold
2. **Soundness**: Cannot prove false age claim
3. **Commitment Binding**: Cannot change committed DOB
4. **Commitment Hiding**: DOB remains hidden

### Implementation Security

1. **Constant-time operations**: Via `subtle` crate
2. **Memory zeroization**: Via `zeroize` crate
3. **No panics**: All errors return `Result`
4. **Fuzz testing**: 23 fuzz targets

## Build Profiles

| Profile | Use Case | Optimisation |
|---------|----------|--------------|
| `release` | Production server | Max speed, LTO |
| `worker` | Cloudflare Workers/WASM | Min size, fat LTO |
| `mobile` | iOS/Android | Balanced size/speed |

## Testing Strategy

1. **Unit tests**: Per-crate functionality
2. **Integration tests**: Cross-crate flows (`crypto-e2e-tests`)
3. **Property tests**: Via `proptest` and `quickcheck`
4. **Fuzz testing**: 25 targets via `cargo-fuzz`
5. **Miri**: Undefined behavior detection

## Dependencies

### Core Cryptography
- `bellman`: Groth16 proving system
- `bls12_381`: BLS12-381 curve operations
- `jubjub`: Jubjub curve for signatures
- `redjubjub`: RedJubjub signature scheme

### Security
- `subtle`: Constant-time operations
- `zeroize`: Secure memory cleanup
- `rand_core`: Secure randomness

### Serialisation
- `serde`: General serialisation
- `borsh`: Binary encoding
- `base64`: Base64 encoding

## Related Documents

- [ADR Index](./adr/) - Architecture Decision Records
- [SECURITY.md](../SECURITY.md) - Security policy and practices
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development guidelines
