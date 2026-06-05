# ADR 0003: Workspace Crate Structure

## Status

Accepted

## Context

provii-crypto contains multiple related but distinct pieces of functionality:

- Signature schemes
- Commitment schemes
- ZK circuits
- Proof generation/verification
- Protocol messages

We need to decide how to organize this code. Options:

1. **Monolithic crate**: All code in one crate
2. **Workspace with many crates**: Separate crate per concern
3. **Feature flags**: Single crate with features

## Decision

We will use a Cargo workspace with focused crates because:

1. **Compilation speed**: Only rebuild changed crates
2. **Clear boundaries**: Each crate has single responsibility
3. **Selective dependencies**: Consumers import only what they need
4. **Testing isolation**: Each crate tests independently
5. **Platform targeting**: Different crates for different platforms

### Crate Responsibilities

| Crate | Responsibility | Consumers |
|-------|----------------|-----------|
| `crypto-commons` | Shared types, error enum, constants | All crates |
| `crypto-sig-redjubjub` | RedJubjub signing and verification | Circuit, prover |
| `crypto-commit` | Pedersen commitments, nullifiers | Circuit, prover |
| `crypto-circuit-age` | Groth16 age verification circuit | Prover |
| `crypto-public-inputs` | Canonical public input assembly | Prover, verifier |
| `crypto-prover` | Proof generation | Mobile apps, CLI |
| `crypto-verifier` | Proof verification | Servers |
| `crypto-protocol` | PKCE, nonces, RP challenge binding | All consumers |

## Consequences

### Positive

- Mobile apps only need `crypto-prover` (no verification code)
- Servers only need `crypto-verifier` (no proving code)
- Faster CI with incremental builds
- Clear API boundaries between concerns
- Easier security auditing per crate

### Negative

- More Cargo.toml files to maintain
- Dependency versions must be coordinated
- Cross-crate changes require multiple updates
- Learning curve for new contributors

### Neutral

- Uses workspace inheritance for common settings
- All crates share same version number

## References

- [Cargo Workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html)
- [Workspace Inheritance](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#inheriting-a-dependency-from-a-workspace)
