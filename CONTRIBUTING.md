# Contributing to provii-crypto

Thank you for your interest in contributing to provii-crypto!

This is a cryptographic library implementing zero-knowledge proofs, digital signatures, and commitment schemes. Contributions to cryptographic code require extra care and review.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your changes

## Development Setup

```bash
# Clone the repository
git clone https://github.com/provii/provii-crypto.git
cd provii-crypto

# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Check formatting
cargo fmt --all --check

# Run clippy lints
cargo clippy --workspace --all-features -- -D warnings

# Build documentation
cargo doc --workspace --no-deps
```

### Minimum Supported Rust Version (MSRV)

This project requires Rust 1.85 or later. Ensure your changes work with the MSRV:

```bash
rustup install 1.85
cargo +1.85 test --workspace --locked
```

## Code Standards

### Formatting

All code must be formatted with `rustfmt`:

```bash
cargo fmt --all
```

### Linting

All code must pass clippy with no warnings:

```bash
cargo clippy --workspace --all-features -- -D warnings
```

### Testing

All new code must include tests. Run the test suite with:

```bash
cargo test --workspace --all-features
```

We maintain a 90% test coverage threshold for cryptographic crates.

### Documentation

Public APIs must be documented. Build docs with:

```bash
cargo doc --workspace --no-deps
```

## Cryptographic Code Guidelines

When modifying cryptographic code, additional requirements apply:

### Security Requirements

1. **No unsafe code** without explicit justification and review by `@provii/security-team`

2. **Constant-time operations** for all secret-dependent computations:
   - Use `subtle` crate for conditional selection
   - No secret-dependent branches or array indexing
   - Verify with timing analysis tools when possible

3. **Zeroization** of sensitive data:
   - Use the `zeroize` crate for all secret keys and intermediate values
   - Implement `Zeroize` and `ZeroizeOnDrop` for types containing secrets
   - Never clone or copy secret values unnecessarily

4. **No panics** in library code:
   - Use `Result` types for fallible operations
   - Handle all error cases explicitly
   - Panics in crypto code may leak secrets via stack traces

5. **Input validation**:
   - Validate all curve points are on the curve
   - Check scalar ranges before operations
   - Reject invalid encodings early

6. **Thorough testing**:
   - Include edge cases and boundary conditions
   - Use known test vectors from standards
   - Add property-based tests with `proptest`
   - Consider adding fuzz targets for new functionality

### Review Requirements

Changes to cryptographic code require approval from both:
- `@provii/core-team` (code quality, style, tests)
- `@provii/security-team` (cryptographic correctness, security)

### Crate-Specific Guidelines

| Crate | Special Considerations |
|-------|----------------------|
| `crypto-sig-redjubjub` | All signature operations must be constant-time; must match field-reduction behaviour of the circuit |
| `crypto-commit` | Pedersen commitments must be perfectly hiding |
| `crypto-prover` | Proof generation must not leak witness |
| `crypto-verifier` | Must reject malformed proofs without panicking |
| `crypto-circuit-age` | Circuit constraints must be complete and sound |
| `crypto-protocol` | Protocol must handle all error cases gracefully |

## Dependencies

### Adding New Dependencies

New dependencies require justification and security review:

1. Check for known vulnerabilities: `cargo audit`
2. Review the dependency's security posture
3. Prefer well-maintained, audited crates
4. Document why the dependency is needed

### Cryptographic Dependencies

For cryptographic dependencies specifically:
- Only use crates with established security track records
- Prefer crates that have undergone third-party audits
- Document any deviations from upstream recommendations

### Prohibited

- No wildcard version specifications (`*`)
- No git dependencies in release builds
- No dependencies with known vulnerabilities

## Pull Request Process

### Before Submitting

1. Ensure all CI checks pass locally:
   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-features -- -D warnings
   cargo test --workspace --locked
   cargo doc --workspace --no-deps
   ```

2. Update documentation if needed

3. Add tests for new functionality

4. Run security checks:
   ```bash
   cargo audit
   ```

### PR Requirements

- Clear description of changes and motivation
- Reference any related issues
- Include test plan for cryptographic changes
- Document any security considerations

### Review Process

1. Automated CI must pass
2. At least one approval from `@provii/core-team`
3. For crypto changes: additional approval from `@provii/security-team`
4. No unresolved review comments

## Commit Messages

Use clear, descriptive commit messages following conventional commits:

```
feat: add support for batch verification
fix: handle edge case in commitment scheme
docs: update API documentation for prover
test: add test vectors for RedJubjub signatures
security: fix constant-time comparison in signature verification
refactor: simplify proof serialization logic
```

For security-related fixes, include impact assessment in the commit body.

## Fuzzing

We maintain fuzz targets for security-critical code. To run fuzzing locally:

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a specific fuzz target
cd fuzz
cargo +nightly fuzz run <target>
```

When adding new functionality, consider adding fuzz targets for:
- Serialization/deserialization
- Signature verification
- Proof verification
- Any parsing of untrusted input

## Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

Please see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Questions?

- Open an issue for questions or discussions about potential contributions
- For security-sensitive discussions, email security@provii.app
