//! Boundary tests for `DobAttestation::verify_with_timestamp`.
//!
//! These tests target the exact boundary values of the clock skew tolerance
//! (60s) and max age (3600s) checks. They kill mutants where `>` is replaced
//! with `>=` on both conditionals.

#![allow(clippy::expect_used)]

use ed25519_dalek::SigningKey;
use provii_crypto_commons::attestation::{DobAttestation, ATTESTATION_MAX_AGE_SECONDS};
use provii_crypto_commons::constants::ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS;
use provii_crypto_commons::Error;

fn generate_test_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
    let signing_key = SigningKey::from_bytes(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ]);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Attestation timestamp is exactly at clock skew tolerance boundary.
/// timestamp = current_time + 60 means the difference is exactly the tolerance.
/// The condition is `self.timestamp > current_time + tolerance`, so at exactly
/// the boundary (timestamp == current_time + tolerance) it should NOT trigger
/// the error. This kills `> → >=`.
#[test]
fn clock_skew_exactly_at_tolerance_should_pass() {
    let (signing_key, verifying_key) = generate_test_keypair();
    let current_time = 1_704_067_200u64;

    let attestation = DobAttestation::create(
        7300,
        "dmv.ca.gov",
        current_time + ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS,
        [0x42u8; 32],
        &signing_key,
    )
    .expect("create attestation");

    let result = attestation.verify_with_timestamp(&verifying_key, current_time);
    assert!(
        result.is_ok(),
        "timestamp exactly at clock skew tolerance should pass, got: {result:?}"
    );
}

/// Attestation timestamp is one second beyond the clock skew tolerance.
/// timestamp = current_time + 61 means `self.timestamp > current_time + 60`
/// is true, so it should fail with InvalidInput.
#[test]
fn clock_skew_one_past_tolerance_should_fail() {
    let (signing_key, verifying_key) = generate_test_keypair();
    let current_time = 1_704_067_200u64;

    let attestation = DobAttestation::create(
        7300,
        "dmv.ca.gov",
        current_time + ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS + 1,
        [0x42u8; 32],
        &signing_key,
    )
    .expect("create attestation");

    let result = attestation.verify_with_timestamp(&verifying_key, current_time);
    assert_eq!(
        result,
        Err(Error::InvalidInput),
        "timestamp one second past clock skew tolerance should fail"
    );
}

/// Attestation age is exactly at max age boundary.
/// current_time - timestamp = 3600 exactly.
/// The condition is `current_time - timestamp > 3600`, so at exactly 3600 it
/// should NOT trigger. This kills `> → >=`.
#[test]
fn max_age_exactly_at_boundary_should_pass() {
    let (signing_key, verifying_key) = generate_test_keypair();
    let current_time = 1_704_067_200u64;

    let attestation = DobAttestation::create(
        7300,
        "dmv.ca.gov",
        current_time - ATTESTATION_MAX_AGE_SECONDS,
        [0x42u8; 32],
        &signing_key,
    )
    .expect("create attestation");

    let result = attestation.verify_with_timestamp(&verifying_key, current_time);
    assert!(
        result.is_ok(),
        "attestation exactly at max age should pass, got: {result:?}"
    );
}

/// Attestation age is one second beyond max age.
/// current_time - timestamp = 3601, which is > 3600, so it should fail.
#[test]
fn max_age_one_past_boundary_should_fail() {
    let (signing_key, verifying_key) = generate_test_keypair();
    let current_time = 1_704_067_200u64;

    let attestation = DobAttestation::create(
        7300,
        "dmv.ca.gov",
        current_time - ATTESTATION_MAX_AGE_SECONDS - 1,
        [0x42u8; 32],
        &signing_key,
    )
    .expect("create attestation");

    let result = attestation.verify_with_timestamp(&verifying_key, current_time);
    assert_eq!(
        result,
        Err(Error::Expired),
        "attestation one second past max age should fail"
    );
}

/// Timestamp slightly in the future (within tolerance) should pass.
/// Exercises the saturating_sub path: when timestamp > current_time, the
/// saturating_sub yields 0 which is <= max_age, so only the clock skew
/// check matters.
#[test]
fn clock_skew_within_tolerance_should_pass() {
    let (signing_key, verifying_key) = generate_test_keypair();
    let current_time = 1_704_067_200u64;

    let attestation = DobAttestation::create(
        7300,
        "dmv.ca.gov",
        current_time + ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS - 1,
        [0x42u8; 32],
        &signing_key,
    )
    .expect("create attestation");

    let result = attestation.verify_with_timestamp(&verifying_key, current_time);
    assert!(
        result.is_ok(),
        "timestamp 59s in the future (within tolerance) should pass, got: {result:?}"
    );
}
