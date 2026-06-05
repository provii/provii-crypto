# crypto-e2e-tests

End-to-end integration tests for the Provii crypto workspace. These tests stitch
together signature verification, challenge handling, proving, and verification
into executable scenarios that mirror production workflows.

## Structure

- `tests/age_verification.rs`: High-level age verification scenario covering the
  entire credential issuance and proof verification pipeline.
- `tests/public_input_debugging.rs`: Utilities for troubleshooting public-input
  mismatches between host and circuit representations.
- `tests/test_native_verify.rs`: Native verification checks for Groth16 proofs.

## Running the Tests

```
cargo test -p crypto-e2e-tests
```

These tests may require proving/verifying keys and JWKS fixtures. Review the
individual test files for required environment variables or sample data.

## When to Run

- After modifying the circuit (`crypto-circuit-age`) or proving logic.
- After updating credential signing or challenge verification flow.
- Before releases that impact the end-user age verification experience.
