# ADR 0002: Use Groth16 Proving System

## Status

Accepted

## Context

provii-crypto needs a zero-knowledge proving system for age verification. The key requirements are:

1. **Proof size**: Must be small for mobile/web transmission
2. **Verification speed**: Must verify quickly (< 50ms)
3. **Security**: Must be well-audited and battle-tested
4. **Tooling**: Must have Rust support

Options considered:

| System | Proof Size | Verify Time | Trust Setup | Maturity |
|--------|------------|-------------|-------------|----------|
| Groth16 | ~200 bytes | ~10ms | Trusted | High |
| PLONK | ~500 bytes | ~20ms | Universal | Medium |
| STARK | ~100 KB | ~50ms | None | Medium |
| Bulletproofs | ~700 bytes | ~50ms | None | High |

## Decision

We will use Groth16 via the `bellman` crate because:

1. **Smallest proofs**: ~200 bytes is ideal for mobile/QR codes
2. **Fastest verification**: Critical for server-side batch verification
3. **Mature implementation**: bellman is used in Zcash production
4. **BLS12-381 curve**: Strong security, well-studied

The trusted setup requirement is acceptable because:
- Age verification is a single-purpose circuit
- Setup can be performed once with MPC ceremony
- Setup parameters can be audited and distributed

## Consequences

### Positive

- Smallest possible proof size
- Sub-10ms verification enables high throughput
- Proven security from Zcash deployment
- Excellent Rust tooling via bellman

### Negative

- Trusted setup required (mitigated by MPC)
- Circuit changes require new setup
- Higher proving time than some alternatives (~2-5 seconds)

### Neutral

- Requires BLS12-381 curve infrastructure
- R1CS constraint system (different from AIR/Plonkish)

## References

- [Groth16 Paper](https://eprint.iacr.org/2016/260)
- [bellman crate](https://github.com/zkcrypto/bellman)
- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
