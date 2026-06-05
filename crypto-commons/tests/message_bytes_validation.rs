//! Mutation-killing tests for `compute_message_bytes` and `cred_v2_prehash_bytes`.
//!
//! These tests target 6 surviving mutants:
//! - `||` to `&&` on the session_id/client_id branch condition
//! - `>` to `==` and `>` to `>=` on session_id length check (255 boundary)
//! - `>` to `==` and `>` to `>=` on client_id length check (255 boundary)
//! - `||` to `&&` on the kid/schema length check in `cred_v2_prehash_bytes`

#![allow(clippy::expect_used)]

use provii_crypto_commons::attestation::DobAttestation;
use provii_crypto_commons::{cred_v2_prehash_bytes, Error};

const DOB_DAYS: i32 = 7300;
const ISSUER_ID: &str = "test-issuer";
const TIMESTAMP: u64 = 1_700_000_000;
const NONCE: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// compute_message_bytes: || → && mutant killer
//
// When only session_id is Some (client_id is None), the branch must still be
// entered. The && mutant would skip it, producing the same hash as (None, None).
// ---------------------------------------------------------------------------

#[test]
fn session_only_differs_from_both_none() {
    let hash_none_none =
        DobAttestation::compute_message_bytes(DOB_DAYS, ISSUER_ID, TIMESTAMP, &NONCE, None, None)
            .expect("should succeed with no optional fields");

    let hash_session_only = DobAttestation::compute_message_bytes(
        DOB_DAYS,
        ISSUER_ID,
        TIMESTAMP,
        &NONCE,
        Some("session-abc"),
        None,
    )
    .expect("should succeed with session_id only");

    // The branch must have been entered, producing different bytes.
    assert_ne!(
        hash_none_none, hash_session_only,
        "session_id = Some must alter the hash (kills || -> && mutant)"
    );
}

#[test]
fn client_only_differs_from_both_none() {
    let hash_none_none =
        DobAttestation::compute_message_bytes(DOB_DAYS, ISSUER_ID, TIMESTAMP, &NONCE, None, None)
            .expect("should succeed with no optional fields");

    let hash_client_only = DobAttestation::compute_message_bytes(
        DOB_DAYS,
        ISSUER_ID,
        TIMESTAMP,
        &NONCE,
        None,
        Some("client-xyz"),
    )
    .expect("should succeed with client_id only");

    assert_ne!(
        hash_none_none, hash_client_only,
        "client_id = Some must alter the hash (kills || -> && mutant)"
    );
}

// ---------------------------------------------------------------------------
// compute_message_bytes: session_id length boundary (255/256/257)
//
// - 255 bytes: valid (kills > → >= which would reject 255)
// - 256 bytes: rejected (kills > → == partially, since 256 == 255 is false
//   under the == mutant BUT the u8::try_from fallback catches it; 257 is the
//   definitive == killer)
// - 257 bytes: rejected (kills > → == fully, since 257 != 255)
// ---------------------------------------------------------------------------

#[test]
fn session_id_255_bytes_succeeds() {
    let sid = "a".repeat(255);
    let result = DobAttestation::compute_message_bytes(
        DOB_DAYS,
        ISSUER_ID,
        TIMESTAMP,
        &NONCE,
        Some(&sid),
        None,
    );
    assert!(
        result.is_ok(),
        "session_id of exactly 255 bytes must succeed (kills > -> >= mutant)"
    );
}

#[test]
fn session_id_256_bytes_fails() {
    let sid = "b".repeat(256);
    let result = DobAttestation::compute_message_bytes(
        DOB_DAYS,
        ISSUER_ID,
        TIMESTAMP,
        &NONCE,
        Some(&sid),
        None,
    );
    assert_eq!(
        result,
        Err(Error::FieldTooLong),
        "session_id of 256 bytes must be rejected"
    );
}

#[test]
fn session_id_257_bytes_fails() {
    let sid = "c".repeat(257);
    let result = DobAttestation::compute_message_bytes(
        DOB_DAYS,
        ISSUER_ID,
        TIMESTAMP,
        &NONCE,
        Some(&sid),
        None,
    );
    assert_eq!(
        result,
        Err(Error::FieldTooLong),
        "session_id of 257 bytes must be rejected (kills > -> == mutant)"
    );
}

// ---------------------------------------------------------------------------
// compute_message_bytes: client_id length boundary (255/256/257)
// ---------------------------------------------------------------------------

#[test]
fn client_id_255_bytes_succeeds() {
    let cid = "d".repeat(255);
    let result = DobAttestation::compute_message_bytes(
        DOB_DAYS,
        ISSUER_ID,
        TIMESTAMP,
        &NONCE,
        None,
        Some(&cid),
    );
    assert!(
        result.is_ok(),
        "client_id of exactly 255 bytes must succeed (kills > -> >= mutant)"
    );
}

#[test]
fn client_id_256_bytes_fails() {
    let cid = "e".repeat(256);
    let result = DobAttestation::compute_message_bytes(
        DOB_DAYS,
        ISSUER_ID,
        TIMESTAMP,
        &NONCE,
        None,
        Some(&cid),
    );
    assert_eq!(
        result,
        Err(Error::FieldTooLong),
        "client_id of 256 bytes must be rejected"
    );
}

#[test]
fn client_id_257_bytes_fails() {
    let cid = "f".repeat(257);
    let result = DobAttestation::compute_message_bytes(
        DOB_DAYS,
        ISSUER_ID,
        TIMESTAMP,
        &NONCE,
        None,
        Some(&cid),
    );
    assert_eq!(
        result,
        Err(Error::FieldTooLong),
        "client_id of 257 bytes must be rejected (kills > -> == mutant)"
    );
}

// ---------------------------------------------------------------------------
// cred_v2_prehash_bytes: || → && mutant killer
//
// When kid exceeds 255 but schema is fine, the function must still reject.
// The && mutant would only reject when BOTH exceed 255.
// ---------------------------------------------------------------------------

#[test]
fn cred_v2_prehash_rejects_long_kid_alone() {
    let long_kid = "k".repeat(256);
    let c = [0u8; 32];
    let result = cred_v2_prehash_bytes(1, &long_kid, &c, 1000, 2000, "age.v1");
    assert_eq!(
        result,
        Err(Error::FieldTooLong),
        "kid alone exceeding 255 must be rejected (kills || -> && mutant)"
    );
}

#[test]
fn cred_v2_prehash_rejects_long_schema_alone() {
    let long_schema = "s".repeat(256);
    let c = [0u8; 32];
    let result = cred_v2_prehash_bytes(1, "valid-kid", &c, 1000, 2000, &long_schema);
    assert_eq!(
        result,
        Err(Error::FieldTooLong),
        "schema alone exceeding 255 must be rejected (kills || -> && mutant)"
    );
}
