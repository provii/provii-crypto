//! Ed25519 attestation types for blind credential issuance.
//!
//! This module provides the `DobAttestation` struct which represents a signed
//! attestation of a date of birth from a trusted issuer. The attestation is
//! used in the blind issuance protocol where:
//!
//! 1. Issuer verifies user identity and creates Ed25519-signed attestation
//! 2. User generates commitment randomness locally
//! 3. User sends attestation + randomness to Provii
//! 4. Provii verifies attestation and computes commitment server-side
//!
//! This ensures the issuer never sees the commitment (privacy) while
//! preventing the user from lying about their DOB (security).
//!
//! # Security Considerations (ASVS 5.0 / MASVS 2.0)
//!
//! - `SigningKey` is zeroized on drop (ed25519-dalek uses zeroize internally)
//! - Signature verification uses constant-time comparison (ed25519-dalek)
//! - Nonces must be unique per attestation (caller responsibility)
//! - Timestamp validation prevents replay attacks
//! - Blake2s256 provides 128-bit collision resistance
//!
//! # Canonical Message Bytes (v1 field order)
//!
//! The Blake2s-256 input is the concatenation of the fields below in
//! exactly this order. Field order is part of the wire contract; do not
//! reorder without a DST bump.
//!
//! 1. `DOB_ATTESTATION_DST`. 25 bytes, fixed.
//! 2. `dob_days` (i32, little-endian). 4 bytes.
//! 3. `issuer_id_len` (u8). 1 byte.
//! 4. `issuer_id` (UTF-8). `issuer_id_len` bytes.
//! 5. `timestamp` (u64, little-endian, seconds). 8 bytes.
//! 6. `nonce` (random). 32 bytes.
//! 7. `session_id_len` (u8), `session_id` (UTF-8). New v1.1, optional.
//! 8. `client_id_len` (u8), `client_id` (UTF-8). New v1.1, optional.
//!
//! When both `session_id` and `client_id` are `None`, sections 7 and 8 are
//! omitted entirely (no length prefix emitted) so the canonical bytes are
//! byte-identical to pre-v1.1 attestations. When either is `Some`, both
//! sections are emitted (a missing field encodes as a single zero length
//! byte with no payload). This matters so that the TS gateway and Rust
//! verifier produce identical hashes for sandbox attestations.

use alloc::string::String;
use blake2::{Blake2s256, Digest};
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{constants::ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS, Error, Result};

/// Domain separation tag for DOB attestation signatures.
pub const DOB_ATTESTATION_DST: &[u8] = b"provii.attestation.dob.v0";

/// Maximum age of attestation in seconds (1 hour).
pub const ATTESTATION_MAX_AGE_SECONDS: u64 = 3600;

/// A signed attestation of date of birth from a trusted issuer.
///
/// The attestation contains:
/// - `dob_days`: Days since Unix epoch representing date of birth (negative for pre-1970)
/// - `issuer_id`: Identifier for the issuing authority (e.g., "dmv.ca.gov")
/// - `timestamp`: Unix timestamp when attestation was created
/// - `nonce`: Random 32-byte value for replay prevention
/// - `session_id`: (v1.1) opaque docs-sandbox gateway session identifier
/// - `client_id`: (v1.1) `docs-sbx-*` / `mwallet-sbx-*` client identifier
/// - `signature`: Ed25519 signature over the message
///
/// When `session_id` and `client_id` are both `None`, the canonical
/// message bytes are byte-identical to the pre-v1.1 layout. See the
/// module-level docs for the full field order.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct DobAttestation {
    /// Days since Unix epoch (1970-01-01) representing date of birth.
    /// Negative values represent dates before the epoch.
    /// SECRET: this field holds the user's actual date of birth.
    pub dob_days: i32,
    /// Identifier for the issuing authority.
    #[zeroize(skip)]
    pub issuer_id: String,
    /// Unix timestamp (seconds) when the attestation was created.
    #[zeroize(skip)]
    pub timestamp: u64,
    /// Random nonce for replay prevention (hex encoded in JSON).
    #[serde(with = "hex_bytes_32")]
    #[zeroize(skip)]
    pub nonce: [u8; 32],
    /// Opaque docs-sandbox gateway session identifier (32 hex chars).
    /// Included in canonical bytes when `Some`; omitted when `None`.
    /// Non-sandbox issuance leaves this `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub session_id: Option<String>,
    /// `docs-sbx-*` or `mwallet-sbx-*` client identifier bound to this
    /// attestation. Included in canonical bytes when `Some`; omitted when
    /// `None`. Non-sandbox issuance leaves this `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub client_id: Option<String>,
    /// Ed25519 signature over the message bytes (hex encoded in JSON).
    #[serde(with = "hex_bytes_64")]
    #[zeroize(skip)]
    pub signature: [u8; 64],
}

impl fmt::Debug for DobAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DobAttestation")
            .field("dob_days", &"[REDACTED]")
            .field("issuer_id", &self.issuer_id)
            .field("timestamp", &self.timestamp)
            .field("nonce", &hex::encode(self.nonce))
            .field("session_id", &self.session_id)
            .field("client_id", &self.client_id)
            .field("signature", &hex::encode(self.signature))
            .finish()
    }
}

// Custom serde module for [u8; 32] hex encoding
mod hex_bytes_32 {
    use alloc::string::String;
    use alloc::vec::Vec;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes: Vec<u8> = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

// Custom serde module for [u8; 64] hex encoding
mod hex_bytes_64 {
    use alloc::string::String;
    use alloc::vec::Vec;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes: Vec<u8> = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

impl DobAttestation {
    /// Create a new attestation with a signature (non-sandbox path).
    ///
    /// Leaves `session_id` and `client_id` `None`; canonical bytes
    /// byte-match the pre-v1.1 format.
    ///
    /// # Arguments
    /// * `dob_days` - Days since Unix epoch for date of birth (negative for pre-1970)
    /// * `issuer_id` - Identifier for the issuing authority
    /// * `timestamp` - Unix timestamp for attestation creation
    /// * `nonce` - Random 32-byte nonce for replay prevention
    /// * `signing_key` - Ed25519 signing key for the issuer
    ///
    /// # Returns
    /// A signed `DobAttestation`
    pub fn create(
        dob_days: i32,
        issuer_id: &str,
        timestamp: u64,
        nonce: [u8; 32],
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let message =
            Self::compute_message_bytes(dob_days, issuer_id, timestamp, &nonce, None, None)?;
        let signature = signing_key.sign(&message);

        Ok(Self {
            dob_days,
            issuer_id: String::from(issuer_id),
            timestamp,
            nonce,
            session_id: None,
            client_id: None,
            signature: signature.to_bytes(),
        })
    }

    /// Create a new attestation bound to a docs-sandbox gateway session.
    ///
    /// Includes `session_id` and `client_id` in the canonical message
    /// bytes. Use this for the docs-sandbox flow only.
    ///
    /// # Errors
    ///
    /// Returns `Error::FieldTooLong` if `issuer_id`, `session_id`, or
    /// `client_id` exceeds 255 bytes.
    pub fn create_bound(
        dob_days: i32,
        issuer_id: &str,
        timestamp: u64,
        nonce: [u8; 32],
        session_id: &str,
        client_id: &str,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let message = Self::compute_message_bytes(
            dob_days,
            issuer_id,
            timestamp,
            &nonce,
            Some(session_id),
            Some(client_id),
        )?;
        let signature = signing_key.sign(&message);

        Ok(Self {
            dob_days,
            issuer_id: String::from(issuer_id),
            timestamp,
            nonce,
            session_id: Some(String::from(session_id)),
            client_id: Some(String::from(client_id)),
            signature: signature.to_bytes(),
        })
    }

    /// Create a new attestation with current timestamp and random nonce.
    ///
    /// # Arguments
    /// * `dob_days` - Days since Unix epoch for date of birth (negative for pre-1970)
    /// * `issuer_id` - Identifier for the issuing authority
    /// * `current_time` - Current Unix timestamp
    /// * `rng` - Random number generator for nonce
    /// * `signing_key` - Ed25519 signing key for the issuer
    #[cfg(feature = "std")]
    pub fn create_with_rng<R: rand_core::RngCore + rand_core::CryptoRng>(
        dob_days: i32,
        issuer_id: &str,
        current_time: u64,
        rng: &mut R,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        Self::create(dob_days, issuer_id, current_time, nonce, signing_key)
    }

    /// Verify the attestation signature.
    ///
    /// # Arguments
    /// * `verifying_key` - Ed25519 verifying key for the issuer
    ///
    /// # Returns
    /// `Ok(())` if signature is valid, `Err` otherwise
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let message = Self::compute_message_bytes(
            self.dob_days,
            &self.issuer_id,
            self.timestamp,
            &self.nonce,
            self.session_id.as_deref(),
            self.client_id.as_deref(),
        )?;

        // ed25519-dalek 2.x: from_bytes takes &[u8; 64] and returns Signature directly.
        // Use `verify_strict` per RFC 8032 Section 5.1.7: rejects small-order A,
        // mixed group-order components, and non-canonical R encodings. The
        // relaxed `verify` permits some malleable but still-valid signatures
        // that the spec forbids for attestation.
        let signature = Signature::from_bytes(&self.signature);

        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Verify the attestation with timestamp freshness check.
    ///
    /// # Arguments
    /// * `verifying_key` - Ed25519 verifying key for the issuer
    /// * `current_time` - Current Unix timestamp for freshness check
    ///
    /// # Returns
    /// `Ok(())` if valid, `Err` with reason otherwise
    pub fn verify_with_timestamp(
        &self,
        verifying_key: &VerifyingKey,
        current_time: u64,
    ) -> Result<()> {
        // Check timestamp is not unreasonably in the future
        if self.timestamp > current_time.saturating_add(ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS) {
            return Err(Error::InvalidInput);
        }

        // Check attestation is not too old
        if current_time.saturating_sub(self.timestamp) > ATTESTATION_MAX_AGE_SECONDS {
            return Err(Error::Expired);
        }

        // Verify signature
        self.verify(verifying_key)
    }

    /// Compute the message bytes that are signed.
    ///
    /// See the module-level docs for the full canonical byte layout.
    /// When `session_id` and `client_id` are both `None`, the output is
    /// byte-identical to the pre-v1.1 format. When either is `Some`,
    /// both session and client sections are emitted (a `None` field
    /// encodes as a single `0` length byte).
    ///
    /// # Errors
    ///
    /// Returns `Err(Error::FieldTooLong)` if any of `issuer_id`,
    /// `session_id`, or `client_id` exceeds 255 bytes.
    pub fn compute_message_bytes(
        dob_days: i32,
        issuer_id: &str,
        timestamp: u64,
        nonce: &[u8; 32],
        session_id: Option<&str>,
        client_id: Option<&str>,
    ) -> Result<[u8; 32]> {
        let issuer_bytes = issuer_id.as_bytes();

        if issuer_bytes.len() > 255 {
            return Err(Error::FieldTooLong);
        }

        let mut hasher = Blake2s256::new();
        hasher.update(DOB_ATTESTATION_DST);
        hasher.update(dob_days.to_le_bytes());
        hasher.update([u8::try_from(issuer_bytes.len()).map_err(|_| Error::FieldTooLong)?]);
        hasher.update(issuer_bytes);
        hasher.update(timestamp.to_le_bytes());
        hasher.update(nonce);

        // v1.1 binding fields: emit both sections only when at least one
        // is present, so legacy (None, None) attestations produce the
        // same bytes as before.
        if session_id.is_some() || client_id.is_some() {
            let sid_bytes = session_id.unwrap_or("").as_bytes();
            if sid_bytes.len() > 255 {
                return Err(Error::FieldTooLong);
            }
            hasher.update([u8::try_from(sid_bytes.len()).map_err(|_| Error::FieldTooLong)?]);
            hasher.update(sid_bytes);

            let cid_bytes = client_id.unwrap_or("").as_bytes();
            if cid_bytes.len() > 255 {
                return Err(Error::FieldTooLong);
            }
            hasher.update([u8::try_from(cid_bytes.len()).map_err(|_| Error::FieldTooLong)?]);
            hasher.update(cid_bytes);
        }

        let result = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        Ok(output)
    }

    /// Get the nonce as a hex string (useful for KV key lookups).
    pub fn nonce_hex(&self) -> String {
        hex::encode(self.nonce)
    }
}

#[cfg(test)]
// Test code: panic is used for golden-vector assertions where the failure message
// must include the observed hex value for fixture regeneration.
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn generate_test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn test_create_and_verify() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let dob_days = 7300i32;
        let issuer_id = "dmv.ca.gov";
        let timestamp = 1704067200u64; // 2024-01-01
        let nonce = [0x42u8; 32];

        let attestation =
            DobAttestation::create(dob_days, issuer_id, timestamp, nonce, &signing_key)?;

        assert_eq!(attestation.dob_days, dob_days);
        assert_eq!(attestation.issuer_id, issuer_id);
        assert_eq!(attestation.timestamp, timestamp);
        assert_eq!(attestation.nonce, nonce);
        assert!(attestation.verify(&verifying_key).is_ok());
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_wrong_key() -> Result<()> {
        let (signing_key, _) = generate_test_keypair();
        let wrong_key = SigningKey::from_bytes(&[0xFFu8; 32]);
        let wrong_verifying_key = wrong_key.verifying_key();

        let attestation =
            DobAttestation::create(7300, "dmv.ca.gov", 1704067200, [0x42u8; 32], &signing_key)?;

        assert!(attestation.verify(&wrong_verifying_key).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_modified_dob() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let mut attestation =
            DobAttestation::create(7300, "dmv.ca.gov", 1704067200, [0x42u8; 32], &signing_key)?;

        // Modify dob_days after signing
        attestation.dob_days = 9999;
        assert!(attestation.verify(&verifying_key).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_modified_issuer() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let mut attestation =
            DobAttestation::create(7300, "dmv.ca.gov", 1704067200, [0x42u8; 32], &signing_key)?;

        // Modify issuer after signing
        attestation.issuer_id = String::from("evil.attacker.com");
        assert!(attestation.verify(&verifying_key).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_modified_timestamp() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let mut attestation =
            DobAttestation::create(7300, "dmv.ca.gov", 1704067200, [0x42u8; 32], &signing_key)?;

        // Modify timestamp after signing
        attestation.timestamp = 9999999999;
        assert!(attestation.verify(&verifying_key).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_modified_nonce() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let mut attestation =
            DobAttestation::create(7300, "dmv.ca.gov", 1704067200, [0x42u8; 32], &signing_key)?;

        // Modify nonce after signing
        attestation.nonce = [0xFF; 32];
        assert!(attestation.verify(&verifying_key).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_with_timestamp_valid() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let current_time = 1704067200u64;

        let attestation = DobAttestation::create(
            7300,
            "dmv.ca.gov",
            current_time - 100, // 100 seconds ago
            [0x42u8; 32],
            &signing_key,
        )?;

        assert!(attestation
            .verify_with_timestamp(&verifying_key, current_time)
            .is_ok());
        Ok(())
    }

    #[test]
    fn test_verify_with_timestamp_expired() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let current_time = 1704067200u64;

        let attestation = DobAttestation::create(
            7300,
            "dmv.ca.gov",
            current_time - ATTESTATION_MAX_AGE_SECONDS - 1, // Just expired
            [0x42u8; 32],
            &signing_key,
        )?;

        let result = attestation.verify_with_timestamp(&verifying_key, current_time);
        assert!(result.is_err());
        assert_eq!(result, Err(Error::Expired));
        Ok(())
    }

    #[test]
    fn test_verify_with_timestamp_future() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let current_time = 1704067200u64;

        let attestation = DobAttestation::create(
            7300,
            "dmv.ca.gov",
            current_time + 100, // In the future
            [0x42u8; 32],
            &signing_key,
        )?;

        let result = attestation.verify_with_timestamp(&verifying_key, current_time);
        assert!(result.is_err());
        assert_eq!(result, Err(Error::InvalidInput));
        Ok(())
    }

    #[test]
    fn test_serialization_roundtrip() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let (signing_key, _) = generate_test_keypair();
        let attestation =
            DobAttestation::create(7300, "dmv.ca.gov", 1704067200, [0x42u8; 32], &signing_key)?;

        let json = serde_json::to_string(&attestation)?;
        let deserialized: DobAttestation = serde_json::from_str(&json)?;

        assert_eq!(attestation, deserialized);
        Ok(())
    }

    #[test]
    fn test_nonce_hex() -> Result<()> {
        let (signing_key, _) = generate_test_keypair();
        let attestation =
            DobAttestation::create(7300, "dmv.ca.gov", 1704067200, [0x42u8; 32], &signing_key)?;

        let hex = attestation.nonce_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn test_message_bytes_deterministic() -> Result<()> {
        let dob_days = 7300i32;
        let issuer_id = "dmv.ca.gov";
        let timestamp = 1704067200u64;
        let nonce = [0x42u8; 32];

        let msg1 = DobAttestation::compute_message_bytes(
            dob_days, issuer_id, timestamp, &nonce, None, None,
        )?;
        let msg2 = DobAttestation::compute_message_bytes(
            dob_days, issuer_id, timestamp, &nonce, None, None,
        )?;

        assert_eq!(msg1, msg2);
        Ok(())
    }

    #[test]
    fn test_message_bytes_different_inputs() -> Result<()> {
        let msg1 = DobAttestation::compute_message_bytes(
            7300,
            "dmv.ca.gov",
            1704067200,
            &[0x42; 32],
            None,
            None,
        )?;
        let msg2 = DobAttestation::compute_message_bytes(
            7301,
            "dmv.ca.gov",
            1704067200,
            &[0x42; 32],
            None,
            None,
        )?;
        let msg3 = DobAttestation::compute_message_bytes(
            7300,
            "dmv.ny.gov",
            1704067200,
            &[0x42; 32],
            None,
            None,
        )?;
        let msg4 = DobAttestation::compute_message_bytes(
            7300,
            "dmv.ca.gov",
            1704067201,
            &[0x42; 32],
            None,
            None,
        )?;
        let msg5 = DobAttestation::compute_message_bytes(
            7300,
            "dmv.ca.gov",
            1704067200,
            &[0x43; 32],
            None,
            None,
        )?;

        assert_ne!(msg1, msg2);
        assert_ne!(msg1, msg3);
        assert_ne!(msg1, msg4);
        assert_ne!(msg1, msg5);
        Ok(())
    }

    // --- v1.1 session/client binding tests ---

    #[test]
    fn test_legacy_bytes_unchanged_when_both_none() -> Result<()> {
        // Byte-for-byte golden: the pre-v1.1 layout for these inputs.
        // Computed manually to lock the canonical format in place.
        //
        // DST="provii.attestation.dob.v0" (25 bytes)
        //   || 7300i32 le (94 1c 00 00)
        //   || 0x0a (issuer len)
        //   || "dmv.ca.gov" (10 bytes)
        //   || 1704067200u64 le (00 9d 92 65 00 00 00 00)
        //   || 0x42 * 32
        //
        // Blake2s256 of that input:
        //   0b1aee332eb8f6cb0e4e090f001b99d077c74783d0abcb3d108e82f424757296
        const GOLDEN: [u8; 32] = [
            0x0b, 0x1a, 0xee, 0x33, 0x2e, 0xb8, 0xf6, 0xcb, 0x0e, 0x4e, 0x09, 0x0f, 0x00, 0x1b,
            0x99, 0xd0, 0x77, 0xc7, 0x47, 0x83, 0xd0, 0xab, 0xcb, 0x3d, 0x10, 0x8e, 0x82, 0xf4,
            0x24, 0x75, 0x72, 0x96,
        ];

        let msg = DobAttestation::compute_message_bytes(
            7300,
            "dmv.ca.gov",
            1704067200,
            &[0x42u8; 32],
            None,
            None,
        )?;

        // If this ever diverges, the legacy byte layout has been broken.
        // Regenerate the golden only if the pre-v1.1 format was
        // intentionally changed (it must not be).
        if msg != GOLDEN {
            // Emit the observed value so the fixture can be updated
            // intentionally. This is a golden-vector assertion, not a
            // coincidence.
            // nosemgrep: provii.crypto.explicit-panic-in-lib
            panic!(
                "legacy canonical bytes drift: observed = {}",
                hex::encode(msg)
            );
        }
        Ok(())
    }

    #[test]
    fn test_bytes_differ_when_session_present() -> Result<()> {
        let legacy = DobAttestation::compute_message_bytes(
            7300,
            "dmv.ca.gov",
            1704067200,
            &[0x42; 32],
            None,
            None,
        )?;
        let bound = DobAttestation::compute_message_bytes(
            7300,
            "dmv.ca.gov",
            1704067200,
            &[0x42; 32],
            Some("sess-32hex-00000000000000000000"),
            Some("docs-sbx-abc"),
        )?;
        assert_ne!(legacy, bound);
        Ok(())
    }

    #[test]
    fn test_bytes_differ_per_session_and_client() -> Result<()> {
        let base = DobAttestation::compute_message_bytes(
            7300,
            "dmv.ca.gov",
            1704067200,
            &[0x42; 32],
            Some("sess-A"),
            Some("docs-sbx-alpha"),
        )?;
        let diff_session = DobAttestation::compute_message_bytes(
            7300,
            "dmv.ca.gov",
            1704067200,
            &[0x42; 32],
            Some("sess-B"),
            Some("docs-sbx-alpha"),
        )?;
        let diff_client = DobAttestation::compute_message_bytes(
            7300,
            "dmv.ca.gov",
            1704067200,
            &[0x42; 32],
            Some("sess-A"),
            Some("docs-sbx-bravo"),
        )?;
        assert_ne!(base, diff_session);
        assert_ne!(base, diff_client);
        assert_ne!(diff_session, diff_client);
        Ok(())
    }

    #[test]
    fn test_bound_attestation_roundtrip() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let attestation = DobAttestation::create_bound(
            7300,
            "docs-sbx.provii.app",
            1704067200,
            [0x42; 32],
            "7f3a9c2e1b8d4a6f0c5e9b2d7a3f8c1e",
            "docs-sbx-abcd1234",
            &signing_key,
        )?;

        assert!(attestation.verify(&verifying_key).is_ok());
        assert_eq!(
            attestation.session_id.as_deref(),
            Some("7f3a9c2e1b8d4a6f0c5e9b2d7a3f8c1e")
        );
        assert_eq!(attestation.client_id.as_deref(), Some("docs-sbx-abcd1234"));

        // Any tamper rejects
        let mut tampered = attestation.clone();
        tampered.session_id = Some("different-session-id-value-00000".into());
        assert!(tampered.verify(&verifying_key).is_err());

        let mut tampered = attestation.clone();
        tampered.client_id = Some("docs-sbx-evil".into());
        assert!(tampered.verify(&verifying_key).is_err());
        Ok(())
    }

    #[test]
    fn test_bound_session_id_too_long_rejected() {
        let (signing_key, _) = generate_test_keypair();
        let long_sid = "a".repeat(256);
        let result = DobAttestation::create_bound(
            7300,
            "dmv.ca.gov",
            1704067200,
            [0x42; 32],
            &long_sid,
            "docs-sbx-x",
            &signing_key,
        );
        assert_eq!(result, Err(Error::FieldTooLong));
    }

    #[test]
    fn test_bound_client_id_too_long_rejected() {
        let (signing_key, _) = generate_test_keypair();
        let long_cid = "a".repeat(256);
        let result = DobAttestation::create_bound(
            7300,
            "dmv.ca.gov",
            1704067200,
            [0x42; 32],
            "sess",
            &long_cid,
            &signing_key,
        );
        assert_eq!(result, Err(Error::FieldTooLong));
    }

    #[test]
    fn test_serialization_skips_none_fields() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        // Legacy attestation serialises without session_id/client_id keys,
        // so existing consumers keep parsing the JSON unchanged.
        let (signing_key, _) = generate_test_keypair();
        let attestation =
            DobAttestation::create(7300, "dmv.ca.gov", 1704067200, [0x42u8; 32], &signing_key)?;
        let json = serde_json::to_string(&attestation)?;
        assert!(!json.contains("session_id"));
        assert!(!json.contains("client_id"));
        Ok(())
    }

    #[test]
    fn test_serialization_emits_bound_fields() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let (signing_key, _) = generate_test_keypair();
        let attestation = DobAttestation::create_bound(
            7300,
            "dmv.ca.gov",
            1704067200,
            [0x42; 32],
            "sess-32",
            "docs-sbx-abc",
            &signing_key,
        )?;
        let json = serde_json::to_string(&attestation)?;
        assert!(json.contains("session_id"));
        assert!(json.contains("client_id"));
        Ok(())
    }

    #[test]
    fn test_empty_issuer_id() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let attestation = DobAttestation::create(7300, "", 1704067200, [0x42u8; 32], &signing_key)?;

        // Verify fields are set correctly
        assert_eq!(attestation.issuer_id, "");
        assert_eq!(attestation.dob_days, 7300);
        assert_eq!(attestation.timestamp, 1704067200);
        assert_eq!(attestation.nonce, [0x42u8; 32]);
        // Signature must not be all zeros (a valid Ed25519 signature is non-trivial)
        assert_ne!(attestation.signature, [0u8; 64]);
        assert!(attestation.verify(&verifying_key).is_ok());
        Ok(())
    }

    #[test]
    fn test_long_issuer_id() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let long_issuer = "a".repeat(200);
        let attestation =
            DobAttestation::create(7300, &long_issuer, 1704067200, [0x42u8; 32], &signing_key)?;

        // Verify the long issuer_id is stored correctly
        assert_eq!(attestation.issuer_id, long_issuer);
        assert_eq!(attestation.issuer_id.len(), 200);
        assert_ne!(attestation.signature, [0u8; 64]);
        assert!(attestation.verify(&verifying_key).is_ok());
        Ok(())
    }

    #[test]
    fn test_issuer_id_too_long_rejected() {
        let (signing_key, _) = generate_test_keypair();
        let long_issuer = "a".repeat(256);
        let result =
            DobAttestation::create(7300, &long_issuer, 1704067200, [0x42u8; 32], &signing_key);
        assert_eq!(result, Err(Error::FieldTooLong));
    }

    #[test]
    fn test_issuer_id_255_bytes_ok() -> Result<()> {
        let (signing_key, verifying_key) = generate_test_keypair();
        let issuer = "b".repeat(255);
        let attestation =
            DobAttestation::create(7300, &issuer, 1704067200, [0x42u8; 32], &signing_key)?;
        assert_eq!(attestation.issuer_id.len(), 255);
        assert_eq!(attestation.issuer_id, issuer);
        assert_ne!(attestation.signature, [0u8; 64]);
        assert!(attestation.verify(&verifying_key).is_ok());
        Ok(())
    }

    /* ========================================================================== */
    /*                    PC-246: EXPIRED ATTESTATION TESTS                       */
    /* ========================================================================== */

    #[test]
    fn test_verify_with_timestamp_far_in_past_rejected() -> Result<()> {
        // PC-246: An attestation with a timestamp far in the past (e.g. 24 hours ago)
        // must be rejected as expired by verify_with_timestamp.
        let (signing_key, verifying_key) = generate_test_keypair();
        let current_time = 1704067200u64;
        let far_past_timestamp = current_time - 86400; // 24 hours ago

        let attestation = DobAttestation::create(
            7300,
            "dmv.ca.gov",
            far_past_timestamp,
            [0x42u8; 32],
            &signing_key,
        )?;

        // Signature itself is valid
        assert!(attestation.verify(&verifying_key).is_ok());

        // But timestamp check rejects it as expired
        let result = attestation.verify_with_timestamp(&verifying_key, current_time);
        assert_eq!(
            result,
            Err(Error::Expired),
            "Attestation 24 hours old must be rejected as Expired"
        );
        Ok(())
    }

    #[test]
    fn test_verify_with_timestamp_one_week_old_rejected() -> Result<()> {
        // PC-246: An attestation one week old must be rejected
        let (signing_key, verifying_key) = generate_test_keypair();
        let current_time = 1704067200u64;
        let one_week_ago = current_time - (7 * 86400);

        let attestation = DobAttestation::create(
            -3650, // pre-1970 DOB
            "passport.gov.au",
            one_week_ago,
            [0xAA; 32],
            &signing_key,
        )?;

        assert!(attestation.verify(&verifying_key).is_ok());
        let result = attestation.verify_with_timestamp(&verifying_key, current_time);
        assert_eq!(
            result,
            Err(Error::Expired),
            "Attestation one week old must be rejected as Expired"
        );
        Ok(())
    }

    #[test]
    fn test_verify_with_timestamp_boundary_exactly_max_age() -> Result<()> {
        // PC-246: An attestation at exactly ATTESTATION_MAX_AGE_SECONDS should pass
        // (the check is >  not >=)
        let (signing_key, verifying_key) = generate_test_keypair();
        let current_time = 1704067200u64;
        let boundary_timestamp = current_time - ATTESTATION_MAX_AGE_SECONDS;

        let attestation = DobAttestation::create(
            7300,
            "dmv.ca.gov",
            boundary_timestamp,
            [0x42u8; 32],
            &signing_key,
        )?;

        // At exactly the boundary: current_time - timestamp == MAX_AGE_SECONDS,
        // the check is ">" so this should still pass.
        let result = attestation.verify_with_timestamp(&verifying_key, current_time);
        assert!(
            result.is_ok(),
            "Attestation at exactly max age boundary should pass (> not >=)"
        );
        Ok(())
    }
}
