//! Shared types, constants, and serialization helpers for the Provii crypto crates.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::{string::String, vec::Vec};

pub mod attestation;
pub mod constants;

use serde::{Deserialize, Serialize};

// Re-export shared constants for downstream consumers.
pub use constants::*;

/// Direction of proof: whether the age check proves "over" or "under" a threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofDirection {
    /// User meets or exceeds the minimum age threshold.
    OverAge,
    /// User is at or below the maximum age threshold.
    UnderAge,
}

/// Errors shared across Provii cryptographic components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Serialised data (proof bytes, VK bytes, etc.) could not be parsed.
    InvalidFormat,
    /// The zero knowledge proof failed verification.
    InvalidProof,
    /// Signature or proof verification did not pass.
    VerificationFailed,
    /// A function argument violated its documented constraints.
    InvalidInput,
    /// A cryptographic signature was malformed or did not verify.
    InvalidSignature,
    /// The origin hash supplied by the relying party was invalid.
    InvalidOriginHash,
    /// A required timestamp field (e.g. `issued_at`) was missing or invalid.
    MissingTimestamp,
    /// The supplied timestamp is in the future, beyond clock skew tolerance.
    FutureTimestamp,
    /// The credential has been revoked via the ban list.
    CredentialBanned,
    /// Writing to or reading from the nullifier store failed.
    NullifierStoreFailure,
    /// A time-bounded value (challenge, credential, attestation) has expired.
    Expired,
    /// The requested resource was not found in the store.
    NotFound,
    /// The caller exceeded the configured rate limit.
    RateLimitExceeded,
    /// Groth16 proof generation failed (synthesis or randomisation error).
    ProverFailed,
    /// The verifier was called before a verifying key was loaded.
    VerifierNotInitialized,
    /// Attempted to initialise a singleton resource that was already set.
    AlreadyInitialized,
    /// An unexpected internal error (I/O, lock poisoning, etc.).
    Internal,
    /// A length-prefixed string field exceeds 255 bytes.
    FieldTooLong,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidFormat => write!(
                f,
                "serialised data could not be parsed; check that the payload matches the expected wire format"
            ),
            Self::InvalidProof => write!(
                f,
                "zero knowledge proof failed verification; regenerate the proof with the current proving key"
            ),
            Self::VerificationFailed => write!(
                f,
                "signature or proof verification did not pass; ensure the correct verifying key is loaded"
            ),
            Self::InvalidInput => write!(
                f,
                "a function argument violated its documented constraints; review parameter bounds"
            ),
            Self::InvalidSignature => write!(
                f,
                "cryptographic signature was malformed or did not verify; confirm the signing key matches"
            ),
            Self::InvalidOriginHash => write!(
                f,
                "origin hash from the relying party is invalid; verify the RP domain and challenge"
            ),
            Self::MissingTimestamp => write!(
                f,
                "required timestamp field is missing or invalid; supply a valid issued_at value"
            ),
            Self::FutureTimestamp => write!(
                f,
                "timestamp is in the future beyond clock skew tolerance; synchronise system clock via NTP"
            ),
            Self::CredentialBanned => write!(
                f,
                "credential has been revoked via the ban list; request a new credential from the issuer"
            ),
            Self::NullifierStoreFailure => write!(
                f,
                "nullifier store read/write failed; check storage backend connectivity"
            ),
            Self::Expired => write!(
                f,
                "time-bounded value has expired; obtain a fresh challenge or credential"
            ),
            Self::NotFound => write!(
                f,
                "requested resource was not found in the store; verify the identifier is correct"
            ),
            Self::RateLimitExceeded => write!(
                f,
                "rate limit exceeded; retry after the cooldown period"
            ),
            Self::ProverFailed => write!(
                f,
                "Groth16 proof generation failed; ensure the witness satisfies all circuit constraints"
            ),
            Self::VerifierNotInitialized => write!(
                f,
                "verifier was called before a verifying key was loaded; call init() first"
            ),
            Self::AlreadyInitialized => write!(
                f,
                "singleton resource was already initialised; init() must be called exactly once"
            ),
            Self::Internal => write!(
                f,
                "unexpected internal error (I/O, lock poisoning); check logs for root cause"
            ),
            Self::FieldTooLong => write!(
                f,
                "length-prefixed string field exceeds 255 bytes; shorten the kid or schema value"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Convenience alias for `core::result::Result<T, Error>` used across the crypto crates.
pub type Result<T> = core::result::Result<T, Error>;

/// Timestamp (seconds and nanoseconds since the Unix epoch).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Timestamp {
    /// Whole seconds since 1970-01-01 00:00:00 UTC. Negative for pre-epoch.
    pub seconds: i64,
    /// Sub-second nanoseconds (0..999_999_999).
    pub nanos: i32,
}

impl Timestamp {
    pub fn new(seconds: i64, nanos: i32) -> Result<Self> {
        if !(0..1_000_000_000).contains(&nanos) {
            return Err(Error::InvalidInput);
        }
        Ok(Self { seconds, nanos })
    }
}

impl core::fmt::Display for Timestamp {
    #[allow(
        clippy::arithmetic_side_effects,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let total_secs = self.seconds;
        let nanos = self.nanos as u64;

        let mut days = total_secs.div_euclid(86400);
        let mut day_secs = total_secs.rem_euclid(86400) as u64;

        let hours = day_secs / 3600;
        day_secs %= 3600;
        let minutes = day_secs / 60;
        let seconds = day_secs % 60;

        // civil_from_days algorithm (Howard Hinnant)
        days += 719_468;
        let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
        let doe = (days - era * 146_097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = (yoe as i64) + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = if m <= 2 { y + 1 } else { y };

        write!(
            f,
            "{year:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}.{nanos:09}Z"
        )
    }
}

/// Credential message v2 as signed by the issuer.
///
/// # Zeroization note
///
/// The `c` field contains the Pedersen commitment bytes. These are public
/// data once the credential is issued (they appear in signed credentials
/// and are transmitted to verifiers). No zeroization is required.
/// Clone and Debug are intentionally derived for protocol handling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredMsgV2 {
    pub v: u8,
    pub kid: String,
    pub c: [u8; 32],
    pub iat: u64,
    pub exp: u64,
    pub schema: String,
}

/// SNARK proof bundle for the credential v2 circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgeSnarkProofV2 {
    /// Format version for the proof payload.
    pub v: u8,
    /// Versioned identifier of the issuer verifying key. `u32` to accommodate
    /// manifest-level vk_ids derived from Blake2s truncation (e.g. 2_031_517_468
    /// is outside u16). Matches `AgeSnarkProofV2Extended.vk` in crypto-prover.
    pub vk: u32,
    /// Blake2s hash of the relying party challenge.
    pub rp: [u8; 32],
    /// Age cutoff expressed in days (negative for pre-1970 dates).
    pub cutoff: i32,
    /// Serialized Groth16 proof bytes.
    pub proof: Vec<u8>,
}

pub const GROTH16_BLS12_381_PROOF_SIZE: usize = 192;

impl AgeSnarkProofV2 {
    pub fn validate_proof_size(&self) -> Result<()> {
        if self.proof.len() != GROTH16_BLS12_381_PROOF_SIZE {
            return Err(Error::InvalidFormat);
        }
        Ok(())
    }
}

/// Assemble the credential v2 prehash with domain separation.
///
/// Returns `Err(Error::FieldTooLong)` if `kid` or `schema` exceeds 255 bytes,
/// since their lengths are encoded as a single `u8`.
pub fn cred_v2_prehash_bytes(
    v: u8,
    kid: &str,
    c: &[u8; 32],
    iat: u64,
    exp: u64,
    schema: &str,
) -> Result<Vec<u8>> {
    use byteorder::{BigEndian, WriteBytesExt};
    let kid_b = kid.as_bytes();
    let sch_b = schema.as_bytes();

    if kid_b.len() > 255 || sch_b.len() > 255 {
        return Err(Error::FieldTooLong);
    }

    // 1 (v) + 1 (kid_len) + kid + 32 (c) + 8 (iat) + 8 (exp) + 1 (sch_len) + sch + DST
    let capacity = 51usize
        .saturating_add(kid_b.len())
        .saturating_add(sch_b.len())
        .saturating_add(CRED_DST.len());
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(CRED_DST);
    out.push(v);

    out.push(u8::try_from(kid_b.len()).map_err(|_| Error::FieldTooLong)?);
    out.extend_from_slice(kid_b);

    out.extend_from_slice(c);

    out.write_u64::<BigEndian>(iat)
        .map_err(|_| Error::Internal)?;
    out.write_u64::<BigEndian>(exp)
        .map_err(|_| Error::Internal)?;

    out.push(u8::try_from(sch_b.len()).map_err(|_| Error::FieldTooLong)?);
    out.extend_from_slice(sch_b);
    Ok(out)
}

/// Convert a slice into a 32-byte array, enforcing the expected length.
pub fn vec_to_array32(v: &[u8]) -> Result<[u8; 32]> {
    if v.len() != 32 {
        return Err(Error::InvalidFormat);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(v);
    Ok(arr)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    /* ========================================================================== */
    /*                    vec_to_array32 TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_vec_to_array32_valid_input() -> Result<()> {
        let input = vec![42u8; 32];
        let result = vec_to_array32(&input)?;
        assert_eq!(result, [42u8; 32]);
        Ok(())
    }

    #[test]
    fn test_vec_to_array32_all_zeros() -> Result<()> {
        let input = vec![0u8; 32];
        let result = vec_to_array32(&input)?;
        assert_eq!(result, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn test_vec_to_array32_all_ones() -> Result<()> {
        let input = vec![0xFFu8; 32];
        let result = vec_to_array32(&input)?;
        assert_eq!(result, [0xFFu8; 32]);
        Ok(())
    }

    #[test]
    fn test_vec_to_array32_sequence() -> Result<()> {
        let input: Vec<u8> = (0..32).collect();
        let arr = vec_to_array32(&input)?;
        for (i, &val) in arr.iter().enumerate() {
            assert_eq!(val, i as u8);
        }
        Ok(())
    }

    #[test]
    fn test_vec_to_array32_empty_input() {
        let input: Vec<u8> = vec![];
        let result = vec_to_array32(&input);
        assert!(result.is_err());
        assert_eq!(result, Err(Error::InvalidFormat));
    }

    #[test]
    fn test_vec_to_array32_too_short() {
        let input = vec![1u8; 31];
        let result = vec_to_array32(&input);
        assert!(result.is_err());
        assert_eq!(result, Err(Error::InvalidFormat));
    }

    #[test]
    fn test_vec_to_array32_too_long() {
        let input = vec![1u8; 33];
        let result = vec_to_array32(&input);
        assert!(result.is_err());
        assert_eq!(result, Err(Error::InvalidFormat));
    }

    #[test]
    fn test_vec_to_array32_way_too_short() {
        let input = vec![1u8; 1];
        let result = vec_to_array32(&input);
        assert!(result.is_err());
        assert_eq!(result, Err(Error::InvalidFormat));
    }

    #[test]
    fn test_vec_to_array32_way_too_long() {
        let input = vec![1u8; 100];
        let result = vec_to_array32(&input);
        assert!(result.is_err());
        assert_eq!(result, Err(Error::InvalidFormat));
    }

    /* ========================================================================== */
    /*                    cred_v2_prehash_bytes TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_cred_v2_prehash_basic() -> Result<()> {
        let v = 2u8;
        let kid = "test-key-123";
        let c = [0x42u8; 32];
        let iat = 1609459200u64; // 2021-01-01 00:00:00 UTC
        let exp = 1640995200u64; // 2022-01-01 00:00:00 UTC
        let schema = "provii.age.v0";

        let result = cred_v2_prehash_bytes(v, kid, &c, iat, exp, schema)?;

        // Verify domain separation tag is present
        assert!(result.starts_with(CRED_DST));

        // Verify version byte
        assert_eq!(result[CRED_DST.len()], v);

        // Verify output is non-empty
        assert!(!result.is_empty());
        Ok(())
    }

    #[test]
    fn test_cred_v2_prehash_empty_kid() -> Result<()> {
        let v = 2u8;
        let kid = "";
        let c = [0u8; 32];
        let iat = 0u64;
        let exp = 0u64;
        let schema = "test";

        let result = cred_v2_prehash_bytes(v, kid, &c, iat, exp, schema)?;

        // Should still work with empty kid
        assert!(result.starts_with(CRED_DST));
        // kid length byte should be 0
        assert_eq!(result[CRED_DST.len() + 1], 0);
        Ok(())
    }

    #[test]
    fn test_cred_v2_prehash_empty_schema() -> Result<()> {
        let v = 2u8;
        let kid = "key";
        let c = [0u8; 32];
        let iat = 0u64;
        let exp = 0u64;
        let schema = "";

        let result = cred_v2_prehash_bytes(v, kid, &c, iat, exp, schema)?;

        // Should still work with empty schema
        assert!(result.starts_with(CRED_DST));
        assert!(!result.is_empty());
        Ok(())
    }

    #[test]
    fn test_cred_v2_prehash_deterministic() -> Result<()> {
        let v = 2u8;
        let kid = "test-key";
        let c = [0xAAu8; 32];
        let iat = 1000u64;
        let exp = 2000u64;
        let schema = "schema.v1";

        let result1 = cred_v2_prehash_bytes(v, kid, &c, iat, exp, schema)?;
        let result2 = cred_v2_prehash_bytes(v, kid, &c, iat, exp, schema)?;

        // Same inputs should produce same output
        assert_eq!(result1, result2);
        Ok(())
    }

    #[test]
    fn test_cred_v2_prehash_different_inputs() -> Result<()> {
        let v = 2u8;
        let kid = "test-key";
        let c = [0xAAu8; 32];
        let iat = 1000u64;
        let exp = 2000u64;
        let schema = "schema.v1";

        let result1 = cred_v2_prehash_bytes(v, kid, &c, iat, exp, schema)?;

        // Change kid
        let result2 = cred_v2_prehash_bytes(v, "different-key", &c, iat, exp, schema)?;
        assert_ne!(result1, result2);

        // Change commitment
        let c2 = [0xBBu8; 32];
        let result3 = cred_v2_prehash_bytes(v, kid, &c2, iat, exp, schema)?;
        assert_ne!(result1, result3);

        // Change iat
        let result4 = cred_v2_prehash_bytes(v, kid, &c, 9999u64, exp, schema)?;
        assert_ne!(result1, result4);

        // Change exp
        let result5 = cred_v2_prehash_bytes(v, kid, &c, iat, 9999u64, schema)?;
        assert_ne!(result1, result5);

        // Change schema
        let result6 = cred_v2_prehash_bytes(v, kid, &c, iat, exp, "different.schema")?;
        assert_ne!(result1, result6);
        Ok(())
    }

    #[test]
    fn test_cred_v2_prehash_length_prefixes() -> Result<()> {
        let v = 2u8;
        let kid = "ABC"; // 3 bytes
        let c = [0u8; 32];
        let iat = 0u64;
        let exp = 0u64;
        let schema = "XY"; // 2 bytes

        let result = cred_v2_prehash_bytes(v, kid, &c, iat, exp, schema)?;

        // Check kid length prefix
        let kid_len_pos = CRED_DST.len() + 1; // after DST and version
        assert_eq!(result[kid_len_pos], 3);

        // Calculate position of schema length
        // DST + v (1) + kid_len (1) + kid (3) + c (32) + iat (8) + exp (8)
        let schema_len_pos = CRED_DST.len() + 1 + 1 + 3 + 32 + 8 + 8;
        assert_eq!(result[schema_len_pos], 2);
        Ok(())
    }

    #[test]
    fn test_cred_v2_prehash_kid_too_long() {
        let kid = &"x".repeat(256);
        let result = cred_v2_prehash_bytes(2, kid, &[0u8; 32], 0, 0, "s");
        assert_eq!(result, Err(Error::FieldTooLong));
    }

    #[test]
    fn test_cred_v2_prehash_schema_too_long() {
        let schema = &"y".repeat(256);
        let result = cred_v2_prehash_bytes(2, "k", &[0u8; 32], 0, 0, schema);
        assert_eq!(result, Err(Error::FieldTooLong));
    }

    #[test]
    fn test_cred_v2_prehash_255_bytes_ok() -> Result<()> {
        let kid = &"k".repeat(255);
        let schema = &"s".repeat(255);
        let bytes = cred_v2_prehash_bytes(2, kid, &[0u8; 32], 0, 0, schema)?;
        // Verify DST prefix is present
        assert!(bytes.starts_with(CRED_DST));
        // Verify version byte follows DST
        assert_eq!(bytes[CRED_DST.len()], 2);
        // Verify kid length byte is 255
        assert_eq!(bytes[CRED_DST.len() + 1], 255);
        // Verify total expected length: DST + v(1) + kid_len(1) + kid(255) + c(32) + iat(8) + exp(8) + sch_len(1) + sch(255)
        let expected_len = CRED_DST.len() + 1 + 1 + 255 + 32 + 8 + 8 + 1 + 255;
        assert_eq!(bytes.len(), expected_len);
        Ok(())
    }

    /* ========================================================================== */
    /*                    PC-125: 256-BYTE BOUNDARY TESTS                       */
    /* ========================================================================== */

    #[test]
    fn test_cred_v2_prehash_kid_exactly_255_bytes_succeeds() -> Result<()> {
        // PC-125: kid at exactly 255 bytes (max valid) should succeed
        let kid = &"k".repeat(255);
        let result = cred_v2_prehash_bytes(2, kid, &[0u8; 32], 1000, 2000, "s");
        assert!(result.is_ok(), "kid at 255 bytes must succeed");
        Ok(())
    }

    #[test]
    fn test_cred_v2_prehash_kid_exactly_256_bytes_fails() {
        // PC-125: kid at exactly 256 bytes (one over max) should fail
        let kid = &"k".repeat(256);
        let result = cred_v2_prehash_bytes(2, kid, &[0u8; 32], 1000, 2000, "s");
        assert_eq!(result, Err(Error::FieldTooLong));
    }

    #[test]
    fn test_cred_v2_prehash_schema_exactly_255_bytes_succeeds() -> Result<()> {
        // PC-125: schema at exactly 255 bytes (max valid) should succeed
        let schema = &"s".repeat(255);
        let result = cred_v2_prehash_bytes(2, "k", &[0u8; 32], 1000, 2000, schema);
        assert!(result.is_ok(), "schema at 255 bytes must succeed");
        Ok(())
    }

    #[test]
    fn test_cred_v2_prehash_schema_exactly_256_bytes_fails() {
        // PC-125: schema at exactly 256 bytes (one over max) should fail
        let schema = &"s".repeat(256);
        let result = cred_v2_prehash_bytes(2, "k", &[0u8; 32], 1000, 2000, schema);
        assert_eq!(result, Err(Error::FieldTooLong));
    }

    #[test]
    fn test_cred_v2_prehash_both_fields_at_boundary() -> Result<()> {
        // PC-125: both kid and schema at 255 bytes simultaneously
        let kid = &"k".repeat(255);
        let schema = &"s".repeat(255);
        let result = cred_v2_prehash_bytes(2, kid, &[0u8; 32], 1000, 2000, schema);
        assert!(result.is_ok(), "both fields at 255 bytes must succeed");

        // But if either goes to 256, it fails
        let kid_long = &"k".repeat(256);
        let result2 = cred_v2_prehash_bytes(2, kid_long, &[0u8; 32], 1000, 2000, schema);
        assert_eq!(result2, Err(Error::FieldTooLong));
        Ok(())
    }

    /* ========================================================================== */
    /*                    PC-187: CredMsgV2 CONSTRUCTION TESTS                   */
    /* ========================================================================== */

    #[test]
    fn test_cred_msg_v2_direct_construction() {
        // PC-187: CredMsgV2 is a plain struct with no new() constructor.
        // Test direct field construction and access.
        let cred = CredMsgV2 {
            v: 2,
            kid: String::from("test-issuer-key"),
            c: [0xABu8; 32],
            iat: 1704067200,
            exp: 1735689600,
            schema: String::from("provii.age/0"),
        };
        assert_eq!(cred.v, 2);
        assert_eq!(cred.kid, "test-issuer-key");
        assert_eq!(cred.c, [0xABu8; 32]);
        assert_eq!(cred.iat, 1704067200);
        assert_eq!(cred.exp, 1735689600);
        assert_eq!(cred.schema, "provii.age/0");
    }

    #[test]
    fn test_cred_msg_v2_clone_independence() {
        // PC-187: Cloned CredMsgV2 should be independent of the original
        let cred = CredMsgV2 {
            v: 2,
            kid: String::from("original"),
            c: [0x11u8; 32],
            iat: 1000,
            exp: 2000,
            schema: String::from("schema.v1"),
        };
        let mut cloned = cred.clone();
        cloned.kid = String::from("modified");
        cloned.c = [0x22u8; 32];

        // Original remains unchanged
        assert_eq!(cred.kid, "original");
        assert_eq!(cred.c, [0x11u8; 32]);
        assert_eq!(cloned.kid, "modified");
        assert_eq!(cloned.c, [0x22u8; 32]);
    }

    #[test]
    fn test_cred_msg_v2_with_prehash() -> Result<()> {
        // PC-187: CredMsgV2 fields feed directly into cred_v2_prehash_bytes
        let cred = CredMsgV2 {
            v: 2,
            kid: String::from("provii:2026-05"),
            c: [0xFFu8; 32],
            iat: 1704067200,
            exp: 1735689600,
            schema: String::from("provii.age/0"),
        };
        let prehash =
            cred_v2_prehash_bytes(cred.v, &cred.kid, &cred.c, cred.iat, cred.exp, &cred.schema)?;
        assert!(!prehash.is_empty());
        assert!(prehash.starts_with(CRED_DST));
        Ok(())
    }

    /* ========================================================================== */
    /*                    STRUCT SERIALIZATION TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_timestamp_serialization() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let ts = Timestamp {
            seconds: 1609459200,
            nanos: 123456789,
        };

        let json = serde_json::to_string(&ts)?;
        let deserialized: Timestamp = serde_json::from_str(&json)?;

        assert_eq!(deserialized.seconds, ts.seconds);
        assert_eq!(deserialized.nanos, ts.nanos);
        Ok(())
    }

    #[test]
    fn test_timestamp_negative_seconds() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let ts = Timestamp {
            seconds: -1000,
            nanos: 0,
        };

        let json = serde_json::to_string(&ts)?;
        let deserialized: Timestamp = serde_json::from_str(&json)?;

        assert_eq!(deserialized.seconds, -1000);
        Ok(())
    }

    #[test]
    fn test_cred_msg_v2_serialization() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let cred = CredMsgV2 {
            v: 2,
            kid: String::from("issuer-key-v1"),
            c: [0xAAu8; 32],
            iat: 1609459200,
            exp: 1640995200,
            schema: String::from("provii.age.v0"),
        };

        let json = serde_json::to_string(&cred)?;
        let deserialized: CredMsgV2 = serde_json::from_str(&json)?;

        assert_eq!(deserialized.v, cred.v);
        assert_eq!(deserialized.kid, cred.kid);
        assert_eq!(deserialized.c, cred.c);
        assert_eq!(deserialized.iat, cred.iat);
        assert_eq!(deserialized.exp, cred.exp);
        assert_eq!(deserialized.schema, cred.schema);
        Ok(())
    }

    #[test]
    fn test_age_snark_proof_v2_serialization() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let proof = AgeSnarkProofV2 {
            v: 2,
            vk: 1,
            rp: [0xBBu8; 32],
            cutoff: 6570,           // 18 years in days
            proof: vec![0xCC; 192], // Typical Groth16 proof size
        };

        let json = serde_json::to_string(&proof)?;
        let deserialized: AgeSnarkProofV2 = serde_json::from_str(&json)?;

        assert_eq!(deserialized.v, proof.v);
        assert_eq!(deserialized.vk, proof.vk);
        assert_eq!(deserialized.rp, proof.rp);
        assert_eq!(deserialized.cutoff, proof.cutoff);
        assert_eq!(deserialized.proof, proof.proof);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ERROR ENUM TESTS                                       */
    /* ========================================================================== */

    #[test]
    fn test_error_enum_equality() {
        assert_eq!(Error::InvalidFormat, Error::InvalidFormat);
        assert_ne!(Error::InvalidFormat, Error::InvalidProof);
    }

    #[test]
    fn test_error_enum_clone() {
        let err1 = Error::VerificationFailed;
        let err2 = err1.clone();
        assert_eq!(err1, err2);
    }

    /* ========================================================================== */
    /*                    CONSTANTS TESTS                                        */
    /* ========================================================================== */

    #[test]
    #[allow(clippy::const_is_empty)]
    fn test_domain_separation_tags_non_empty() {
        assert!(!CRED_DST.is_empty());
        assert!(!CHALLENGE_DST.is_empty());
        assert!(!NULLIFIER_DST.is_empty());
        assert!(!CHALLENGE_SIG_DST.is_empty());
        assert!(!CHALLENGE_ID_DST.is_empty());
    }

    #[test]
    fn test_domain_separation_tags_unique() {
        use crate::attestation::DOB_ATTESTATION_DST;

        let all_tags: &[(&str, &[u8])] = &[
            ("CRED_DST", CRED_DST),
            ("CHALLENGE_DST", CHALLENGE_DST),
            ("NULLIFIER_DST", NULLIFIER_DST),
            ("DOB_ATTESTATION_DST", DOB_ATTESTATION_DST),
            ("CHALLENGE_SIG_DST", CHALLENGE_SIG_DST),
            ("CHALLENGE_ID_DST", CHALLENGE_ID_DST),
            ("REDJUBJUB_PERSONALIZATION", REDJUBJUB_PERSONALIZATION),
            ("REDJUBJUB_NONCE_TAG", REDJUBJUB_NONCE_TAG),
            ("ISSUANCE_CONSENT_DST", ISSUANCE_CONSENT_DST),
        ];

        // Check all tags are unique
        for i in 0..all_tags.len() {
            for j in (i + 1)..all_tags.len() {
                assert_ne!(
                    all_tags[i].1, all_tags[j].1,
                    "Domain separation tag collision: {} vs {}",
                    all_tags[i].0, all_tags[j].0
                );
            }
        }

        // Prefix safety for hash-domain DSTs (REDJUBJUB_PERSONALIZATION is a
        // blake2s personalization parameter, not a hash-input prefix, so the
        // prefix relationship with REDJUBJUB_NONCE_TAG is safe by design)
        let hash_dsts: &[(&str, &[u8])] = &[
            ("CRED_DST", CRED_DST),
            ("CHALLENGE_DST", CHALLENGE_DST),
            ("NULLIFIER_DST", NULLIFIER_DST),
            ("DOB_ATTESTATION_DST", DOB_ATTESTATION_DST),
            ("CHALLENGE_SIG_DST", CHALLENGE_SIG_DST),
            ("CHALLENGE_ID_DST", CHALLENGE_ID_DST),
            ("ISSUANCE_CONSENT_DST", ISSUANCE_CONSENT_DST),
        ];
        for i in 0..hash_dsts.len() {
            for j in 0..hash_dsts.len() {
                if i != j {
                    assert!(
                        !hash_dsts[j].1.starts_with(hash_dsts[i].1),
                        "{} is a prefix of {}",
                        hash_dsts[i].0,
                        hash_dsts[j].0
                    );
                }
            }
        }
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_size_constants_reasonable() {
        assert_eq!(CREDENTIAL_ID_SIZE, 32);
        assert!(MAX_CREDENTIAL_SIZE > 0);
        assert!(MAX_CREDENTIAL_SIZE <= 10_000); // Reasonable upper bound
        assert!(MAX_RANGE_PROOF_SIZE > 0);
        assert!(MAX_CREDENTIAL_SIGNATURE_SIZE > 0);
        assert!(MAX_WALLET_SIGNATURE_SIZE > 0);
        assert_eq!(NONCE_SIZE, 32);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_time_constants_reasonable() {
        assert_eq!(CHALLENGE_EXPIRY_SECONDS, 300); // 5 minutes
        assert_eq!(CLOCK_SKEW_TOLERANCE_SECONDS, 30); // 30 seconds
        assert_eq!(SESSION_TIMEOUT_MS, 120_000); // 2 minutes

        // Verify time relationships make sense
        assert!(CHALLENGE_EXPIRY_SECONDS > CLOCK_SKEW_TOLERANCE_SECONDS);
    }

    /// PC-043: Pin constants hash test.
    /// Computes a Blake2s-256 hash over all DST constant values concatenated
    /// together and asserts the hash matches a pinned value. This catches
    /// accidental constant changes that would break cross-crate compatibility.
    #[test]
    fn test_constants_pin_hash() {
        use crate::attestation::DOB_ATTESTATION_DST;
        use blake2::Digest;

        let mut hasher = blake2::Blake2s256::new();
        hasher.update(CRED_DST);
        hasher.update(CHALLENGE_DST);
        hasher.update(NULLIFIER_DST);
        hasher.update(CHALLENGE_SIG_DST);
        hasher.update(CHALLENGE_ID_DST);
        hasher.update(REDJUBJUB_PERSONALIZATION);
        hasher.update(REDJUBJUB_NONCE_TAG);
        hasher.update(DOB_ATTESTATION_DST);
        hasher.update(ISSUANCE_CONSENT_DST);
        let hash = hasher.finalize();

        let actual = hex::encode(hash.as_slice());
        // Pinned value: if any DST constant changes, this test fails.
        assert_eq!(
            actual, "3df66d2e9e2ebd4ff94327ffbf148c633889ba7fd831aac25433bd03fa724c70",
            "DST constants changed unexpectedly; update this pin only if the change is intentional"
        );
    }

    /* ========================================================================== */
    /*                    TIMESTAMP DISPLAY TESTS                                */
    /* ========================================================================== */

    #[test]
    fn test_timestamp_display_epoch() {
        let ts = Timestamp::new(0, 0).unwrap();
        assert_eq!(alloc::format!("{ts}"), "1970-01-01T00:00:00.000000000Z");
    }

    #[test]
    fn test_timestamp_display_known_date() {
        // 2026-01-15T12:30:00.000000000Z = 1768480200 seconds
        let ts = Timestamp::new(1768480200, 0).unwrap();
        assert_eq!(alloc::format!("{ts}"), "2026-01-15T12:30:00.000000000Z");
    }

    #[test]
    fn test_timestamp_display_with_nanos() {
        let ts = Timestamp::new(1768480200, 123456789).unwrap();
        assert_eq!(alloc::format!("{ts}"), "2026-01-15T12:30:00.123456789Z");
    }

    #[test]
    fn test_timestamp_display_y2k() {
        // 2000-01-01T00:00:00Z = 946684800 seconds
        let ts = Timestamp::new(946684800, 0).unwrap();
        assert_eq!(alloc::format!("{ts}"), "2000-01-01T00:00:00.000000000Z");
    }

    /* ========================================================================== */
    /*                    CREDMSGV2 EQUALITY TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_cred_msg_v2_eq_same() {
        let cred = CredMsgV2 {
            v: 2,
            kid: alloc::string::String::from("kid-1"),
            c: [0xAA; 32],
            iat: 1000,
            exp: 2000,
            schema: alloc::string::String::from("age"),
        };
        let cred2 = cred.clone();
        assert_eq!(cred, cred2);
    }

    #[test]
    fn test_cred_msg_v2_ne_different_kid() {
        let cred1 = CredMsgV2 {
            v: 2,
            kid: alloc::string::String::from("kid-1"),
            c: [0xAA; 32],
            iat: 1000,
            exp: 2000,
            schema: alloc::string::String::from("age"),
        };
        let cred2 = CredMsgV2 {
            v: 2,
            kid: alloc::string::String::from("kid-2"),
            c: [0xAA; 32],
            iat: 1000,
            exp: 2000,
            schema: alloc::string::String::from("age"),
        };
        assert_ne!(cred1, cred2);
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    use proptest::prelude::*;

    /// Helper to convert crate errors into proptest failures.
    fn fail<E: core::fmt::Debug>(e: E) -> TestCaseError {
        TestCaseError::fail(alloc::format!("{e:?}"))
    }

    proptest! {
        /// Property: cred_v2_prehash_bytes is deterministic
        #[test]
        fn prop_cred_v2_prehash_deterministic(
            v in any::<u8>(),
            kid in "\\PC{0,20}",
            c in any::<[u8; 32]>(),
            iat in any::<u64>(),
            exp in any::<u64>(),
            schema in "\\PC{0,30}"
        ) {
            let result1 = cred_v2_prehash_bytes(v, &kid, &c, iat, exp, &schema).map_err(fail)?;
            let result2 = cred_v2_prehash_bytes(v, &kid, &c, iat, exp, &schema).map_err(fail)?;
            prop_assert_eq!(&result1, &result2, "cred_v2_prehash_bytes must be deterministic");
        }

        /// Property: different v values produce different outputs
        #[test]
        fn prop_cred_v2_prehash_different_v(
            v1 in any::<u8>(),
            v2 in any::<u8>(),
            kid in "\\PC{1,10}",
            c in any::<[u8; 32]>(),
            iat in any::<u64>(),
            exp in any::<u64>(),
            schema in "\\PC{1,10}"
        ) {
            prop_assume!(v1 != v2);
            let result1 = cred_v2_prehash_bytes(v1, &kid, &c, iat, exp, &schema).map_err(fail)?;
            let result2 = cred_v2_prehash_bytes(v2, &kid, &c, iat, exp, &schema).map_err(fail)?;
            prop_assert_ne!(&result1, &result2, "Different v values must produce different outputs");
        }

        /// Property: different commitments produce different outputs
        #[test]
        fn prop_cred_v2_prehash_different_commitment(
            v in any::<u8>(),
            kid in "\\PC{0,10}",
            c1 in any::<[u8; 32]>(),
            c2 in any::<[u8; 32]>(),
            iat in any::<u64>(),
            exp in any::<u64>(),
            schema in "\\PC{0,10}"
        ) {
            prop_assume!(c1 != c2);
            let result1 = cred_v2_prehash_bytes(v, &kid, &c1, iat, exp, &schema).map_err(fail)?;
            let result2 = cred_v2_prehash_bytes(v, &kid, &c2, iat, exp, &schema).map_err(fail)?;
            prop_assert_ne!(&result1, &result2);
        }

        /// Property: vec_to_array32 succeeds for valid 32-byte inputs
        #[test]
        fn prop_vec_to_array32_valid_input(bytes in any::<[u8; 32]>()) {
            let vec = bytes.to_vec();
            let result = vec_to_array32(&vec).map_err(fail)?;
            prop_assert_eq!(result, bytes);
        }

        /// Property: vec_to_array32 fails for non-32-byte inputs
        #[test]
        fn prop_vec_to_array32_invalid_length(len in 0usize..256) {
            prop_assume!(len != 32);
            let vec = vec![0u8; len];
            let result = vec_to_array32(&vec);
            prop_assert!(result.is_err());
            let err = result.err().ok_or_else(|| TestCaseError::fail("expected error"))?;
            prop_assert_eq!(err, Error::InvalidFormat);
        }

        /// Property: Timestamp serialization round-trip
        #[test]
        fn prop_timestamp_serialization_round_trip(
            seconds in any::<i64>(),
            nanos in any::<i32>()
        ) {
            let ts = Timestamp { seconds, nanos };
            let json = serde_json::to_string(&ts).map_err(fail)?;
            let ts2: Timestamp = serde_json::from_str(&json).map_err(fail)?;
            prop_assert_eq!(ts2.seconds, seconds);
            prop_assert_eq!(ts2.nanos, nanos);
        }

        /// Property: CredMsgV2 serialization round-trip
        #[test]
        fn prop_cred_msg_v2_serialization_round_trip(
            v in any::<u8>(),
            kid in "\\PC{0,30}",
            c in any::<[u8; 32]>(),
            iat in any::<u64>(),
            exp in any::<u64>(),
            schema in "\\PC{0,30}"
        ) {
            let cred = CredMsgV2 { v, kid, c, iat, exp, schema };
            let json = serde_json::to_string(&cred).map_err(fail)?;
            let cred2: CredMsgV2 = serde_json::from_str(&json).map_err(fail)?;
            prop_assert_eq!(cred2.v, cred.v);
            prop_assert_eq!(&cred2.kid, &cred.kid);
            prop_assert_eq!(cred2.c, cred.c);
            prop_assert_eq!(cred2.iat, cred.iat);
            prop_assert_eq!(cred2.exp, cred.exp);
            prop_assert_eq!(&cred2.schema, &cred.schema);
        }

        /// Property: AgeSnarkProofV2 serialization round-trip
        #[test]
        fn prop_age_snark_proof_v2_serialization(
            v in any::<u8>(),
            vk in any::<u32>(),
            rp in any::<[u8; 32]>(),
            cutoff in any::<i32>(),
            proof in prop::collection::vec(any::<u8>(), 0..500)
        ) {
            let proof_obj = AgeSnarkProofV2 { v, vk, rp, cutoff, proof };
            let json = serde_json::to_string(&proof_obj).map_err(fail)?;
            let proof2: AgeSnarkProofV2 = serde_json::from_str(&json).map_err(fail)?;
            prop_assert_eq!(proof2.v, proof_obj.v);
            prop_assert_eq!(proof2.vk, proof_obj.vk);
            prop_assert_eq!(proof2.rp, proof_obj.rp);
            prop_assert_eq!(proof2.cutoff, proof_obj.cutoff);
            prop_assert_eq!(proof2.proof, proof_obj.proof);
        }
    }
}
