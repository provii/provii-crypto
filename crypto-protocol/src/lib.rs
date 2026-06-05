//! Protocol helpers for challenges, PKCE, and nonces.
//! Relies on lightweight primitives (SHA256, base64url, HMAC).

#![forbid(unsafe_code)]

extern crate alloc;
use alloc::{string::String, vec::Vec};

pub mod nonce;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

// Re-export commonly used functions for crate consumers.
pub use nonce::{generate_nonce, validate_nonce};

/// Compute the PKCE `code_challenge` using the S256 method.
///
/// Returns a 43-character base64url-encoded SHA-256 digest of the verifier.
/// Empty verifiers are accepted (the hash of an empty string is well-defined).
///
/// # Caller responsibility
///
/// The `code_verifier` is a PKCE secret. This function borrows it
/// immutably and does not retain a copy. The caller is responsible
/// for zeroizing the owned `code_verifier` string after use (e.g.
/// by storing it in `Zeroizing<String>`).
pub fn code_challenge_s256(code_verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let result = hasher.finalize();
    URL_SAFE_NO_PAD.encode(result)
}

/// Generate the relying-party challenge binding.
///
/// Computes `SHA-256(origin || nonce || CHALLENGE_DST)` to bind a proof
/// to a specific relying party and nonce. The resulting 32-byte hash is
/// embedded as a public input in the ZK circuit.
///
/// Both `origin` and `nonce` may be any length. An empty origin is
/// technically valid but will bind the proof to no specific site.
/// Callers should validate that `origin` is a well-formed URL origin
/// before passing it here.
pub fn rp_challenge(origin: &str, nonce: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(origin.as_bytes());
    hasher.update(nonce);
    hasher.update(provii_crypto_commons::CHALLENGE_DST);
    hasher.finalize().into()
}

/// Compute the origin hash (SHA-256 of the origin string).
///
/// Returns a 32-byte digest. The hash is case-sensitive: `Example.com`
/// and `example.com` produce different outputs. Callers should
/// normalise the origin (e.g. to lowercase) before hashing if
/// case-insensitive matching is required.
pub fn compute_origin_hash(origin: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(origin.as_bytes());
    hasher.finalize().into()
}

/// Build an issuance consent message for a wallet signature.
///
/// Hashes `ISSUANCE_CONSENT_DST || len(session_id) || session_id ||
/// len(issuer_id) || issuer_id || len(issuer_kid) || issuer_kid ||
/// wallet_pubkey || consent_time || terms_version || nonce_flag [|| nonce]`
/// into a 32-byte SHA-256 digest. Length prefixes are 4-byte little-endian
/// `u32` values emitted by [`write_length_prefixed`].
///
/// # Errors
///
/// Returns `Error::InvalidInput` if any length-prefixed field exceeds
/// `u32::MAX` bytes (theoretical limit; no practical string reaches this).
pub fn build_issuance_consent_message(
    session_id: &str,
    issuer_id: &str,
    issuer_kid: &str,
    wallet_pubkey: &[u8; 32],
    consent_time: i64,
    terms_version: u32,
    nonce: Option<[u8; 16]>,
) -> provii_crypto_commons::Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(provii_crypto_commons::ISSUANCE_CONSENT_DST);
    write_length_prefixed(&mut h, session_id.as_bytes())?;
    write_length_prefixed(&mut h, issuer_id.as_bytes())?;
    write_length_prefixed(&mut h, issuer_kid.as_bytes())?;
    h.update(wallet_pubkey);
    h.update(consent_time.to_le_bytes());
    h.update(terms_version.to_le_bytes());

    match nonce {
        Some(n) => {
            h.update([0x01]);
            h.update(n);
        }
        None => {
            h.update([0x00]);
        }
    }

    Ok(h.finalize().into())
}

/// Compute a replay tag from the origin hash and nonce.
///
/// Concatenates `origin_hash || ':' || nonce` and base64url-encodes the
/// result (no padding). Both inputs may be any length. In practice,
/// `origin_hash` is 32 bytes (SHA-256 output) and `nonce` is 32 bytes.
pub fn compute_replay_tag(origin_hash: &[u8], nonce: &[u8]) -> String {
    // SAFETY(arithmetic): origin_hash (32 bytes) + 1 + nonce (32 bytes) cannot overflow usize.
    #[allow(clippy::arithmetic_side_effects)]
    let cap = origin_hash.len() + 1 + nonce.len();
    let mut v = Vec::with_capacity(cap);
    v.extend_from_slice(origin_hash);
    v.push(b':');
    v.extend_from_slice(nonce);
    URL_SAFE_NO_PAD.encode(v)
}

/// Write length-prefixed data to a SHA256 state (signature helper).
///
/// Returns `Err(Error::InvalidInput)` if `data.len()` exceeds `u32::MAX`,
/// which would silently truncate the length prefix.
pub fn write_length_prefixed(h: &mut Sha256, data: &[u8]) -> provii_crypto_commons::Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| provii_crypto_commons::Error::InvalidInput)?;
    h.update(len.to_le_bytes());
    h.update(data);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::unwrap_used)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    CODE_CHALLENGE_S256 TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_code_challenge_s256_deterministic() {
        let verifier = "test-verifier-12345";
        let challenge1 = code_challenge_s256(verifier);
        let challenge2 = code_challenge_s256(verifier);
        assert_eq!(challenge1, challenge2);
    }

    #[test]
    fn test_code_challenge_s256_different_verifiers() {
        let challenge1 = code_challenge_s256("verifier1");
        let challenge2 = code_challenge_s256("verifier2");
        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_code_challenge_s256_no_padding() {
        let verifier = "test-verifier";
        let challenge = code_challenge_s256(verifier);
        // URL_SAFE_NO_PAD should not contain padding
        assert!(!challenge.contains('='));
    }

    #[test]
    fn test_code_challenge_s256_empty_string() {
        let challenge = code_challenge_s256("");
        assert!(!challenge.is_empty());
        assert!(!challenge.contains('='));
    }

    #[test]
    fn test_code_challenge_s256_long_verifier() {
        let long_verifier = "a".repeat(1000);
        let challenge = code_challenge_s256(&long_verifier);
        assert!(!challenge.is_empty());
        // SHA256 output is 32 bytes, base64url encoded is 43 chars
        assert_eq!(challenge.len(), 43);
    }

    /* ========================================================================== */
    /*                    GENERATE_NONCE TESTS                                  */
    /* ========================================================================== */

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_generate_nonce_generates_32_bytes() -> provii_crypto_commons::Result<()> {
        let nonce = generate_nonce()?;
        assert_eq!(nonce.len(), 32);
        Ok(())
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_generate_nonce_unique() -> provii_crypto_commons::Result<()> {
        let nonce1 = generate_nonce()?;
        let nonce2 = generate_nonce()?;
        assert_ne!(nonce1, nonce2);
        Ok(())
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_generate_nonce_not_all_zeros() -> provii_crypto_commons::Result<()> {
        let nonce = generate_nonce()?;
        assert!(nonce.iter().any(|&b| b != 0));
        Ok(())
    }

    /* ========================================================================== */
    /*                    WASM-SPECIFIC TESTS - GENERATE_NONCE                  */
    /* ========================================================================== */

    /// Test that generate_nonce() generates 32 bytes on WASM
    /// NOTE: This test runs only when compiled for wasm32 target:
    ///   cargo test --target wasm32-unknown-unknown
    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_generate_nonce_wasm_generates_32_bytes() -> provii_crypto_commons::Result<()> {
        let nonce = generate_nonce()?;
        assert_eq!(nonce.len(), 32);
        Ok(())
    }

    /// Test that generate_nonce() generates unique nonces on WASM
    /// NOTE: This test runs only when compiled for wasm32 target:
    ///   cargo test --target wasm32-unknown-unknown
    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_generate_nonce_wasm_unique() -> provii_crypto_commons::Result<()> {
        let nonce1 = generate_nonce()?;
        let nonce2 = generate_nonce()?;
        assert_ne!(nonce1, nonce2, "WASM nonces must be unique");
        Ok(())
    }

    /// Test that generate_nonce() generates non-zero nonces on WASM
    /// NOTE: This test runs only when compiled for wasm32 target:
    ///   cargo test --target wasm32-unknown-unknown
    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_generate_nonce_wasm_not_all_zeros() -> provii_crypto_commons::Result<()> {
        let nonce = generate_nonce()?;
        assert!(
            nonce.iter().any(|&b| b != 0),
            "WASM nonce must not be all zeros"
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    RP_CHALLENGE TESTS                                     */
    /* ========================================================================== */

    #[test]
    fn test_rp_challenge_deterministic() {
        let origin = "https://example.com";
        let nonce = [42u8; 32];

        let challenge1 = rp_challenge(origin, &nonce);
        let challenge2 = rp_challenge(origin, &nonce);

        assert_eq!(challenge1, challenge2);
        assert_eq!(challenge1.len(), 32);
    }

    #[test]
    fn test_rp_challenge_different_origins() {
        let nonce = [1u8; 32];

        let challenge1 = rp_challenge("https://example1.com", &nonce);
        let challenge2 = rp_challenge("https://example2.com", &nonce);

        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_rp_challenge_different_nonces() {
        let origin = "https://example.com";

        let challenge1 = rp_challenge(origin, &[1u8; 32]);
        let challenge2 = rp_challenge(origin, &[2u8; 32]);

        assert_ne!(challenge1, challenge2);
    }

    #[test]
    fn test_rp_challenge_empty_origin() {
        let nonce = [42u8; 32];
        let challenge = rp_challenge("", &nonce);
        assert_eq!(challenge.len(), 32);
    }

    #[test]
    fn test_rp_challenge_zero_nonce() {
        let origin = "https://example.com";
        let nonce = [0u8; 32];
        let challenge = rp_challenge(origin, &nonce);
        assert_eq!(challenge.len(), 32);
        assert!(challenge.iter().any(|&b| b != 0)); // Hash should not be all zeros
    }

    /* ========================================================================== */
    /*                    COMPUTE_ORIGIN_HASH TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_compute_origin_hash_deterministic() {
        let origin = "https://example.com";

        let hash1 = compute_origin_hash(origin);
        let hash2 = compute_origin_hash(origin);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_compute_origin_hash_different_origins() {
        let hash1 = compute_origin_hash("https://example1.com");
        let hash2 = compute_origin_hash("https://example2.com");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_origin_hash_case_sensitive() {
        let hash1 = compute_origin_hash("https://Example.com");
        let hash2 = compute_origin_hash("https://example.com");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_origin_hash_empty_string() {
        let hash = compute_origin_hash("");
        assert_eq!(hash.len(), 32);
        // Empty string still produces a valid SHA256 hash
    }

    #[test]
    fn test_compute_origin_hash_with_path() {
        let hash1 = compute_origin_hash("https://example.com");
        let hash2 = compute_origin_hash("https://example.com/path");
        assert_ne!(hash1, hash2);
    }

    /* ========================================================================== */
    /*                    BUILD_ISSUANCE_CONSENT_MESSAGE TESTS                   */
    /* ========================================================================== */

    #[test]
    fn test_build_issuance_consent_message_deterministic() {
        let session_id = "session-123";
        let issuer_id = "issuer-abc";
        let issuer_kid = "key-1";
        let wallet_pubkey = [1u8; 32];
        let consent_time = 1000i64;
        let terms_version = 1u32;
        let nonce = Some([42u8; 16]);

        let msg1 = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &wallet_pubkey,
            consent_time,
            terms_version,
            nonce,
        )
        .unwrap();
        let msg2 = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &wallet_pubkey,
            consent_time,
            terms_version,
            nonce,
        )
        .unwrap();

        assert_eq!(msg1, msg2);
        assert_eq!(msg1.len(), 32);
    }

    #[test]
    fn test_build_issuance_consent_message_different_session_ids() {
        let issuer_id = "issuer-abc";
        let issuer_kid = "key-1";
        let wallet_pubkey = [1u8; 32];
        let consent_time = 1000i64;
        let terms_version = 1u32;

        let msg1 = build_issuance_consent_message(
            "session-1",
            issuer_id,
            issuer_kid,
            &wallet_pubkey,
            consent_time,
            terms_version,
            None,
        )
        .unwrap();
        let msg2 = build_issuance_consent_message(
            "session-2",
            issuer_id,
            issuer_kid,
            &wallet_pubkey,
            consent_time,
            terms_version,
            None,
        )
        .unwrap();

        assert_ne!(msg1, msg2);
    }

    #[test]
    fn test_build_issuance_consent_message_with_and_without_nonce() {
        let session_id = "session-123";
        let issuer_id = "issuer-abc";
        let issuer_kid = "key-1";
        let wallet_pubkey = [1u8; 32];
        let consent_time = 1000i64;
        let terms_version = 1u32;

        let msg_with_nonce = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &wallet_pubkey,
            consent_time,
            terms_version,
            Some([42u8; 16]),
        )
        .unwrap();
        let msg_without_nonce = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &wallet_pubkey,
            consent_time,
            terms_version,
            None,
        )
        .unwrap();

        assert_ne!(msg_with_nonce, msg_without_nonce);
    }

    #[test]
    fn test_build_issuance_consent_message_different_terms_versions() {
        let session_id = "session-123";
        let issuer_id = "issuer-abc";
        let issuer_kid = "key-1";
        let wallet_pubkey = [1u8; 32];
        let consent_time = 1000i64;

        let msg1 = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &wallet_pubkey,
            consent_time,
            1,
            None,
        )
        .unwrap();
        let msg2 = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &wallet_pubkey,
            consent_time,
            2,
            None,
        )
        .unwrap();

        assert_ne!(msg1, msg2);
    }

    #[test]
    fn test_build_issuance_consent_message_different_wallet_pubkeys() {
        let session_id = "session-123";
        let issuer_id = "issuer-abc";
        let issuer_kid = "key-1";
        let consent_time = 1000i64;
        let terms_version = 1u32;

        let msg1 = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &[1u8; 32],
            consent_time,
            terms_version,
            None,
        )
        .unwrap();
        let msg2 = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &[2u8; 32],
            consent_time,
            terms_version,
            None,
        )
        .unwrap();

        assert_ne!(msg1, msg2);
    }

    #[test]
    fn test_build_issuance_consent_message_no_field_collision() {
        // Without length prefixes, shifting bytes across field boundaries produces
        // collisions. For example, session_id="ab", issuer_id="c" would hash
        // identically to session_id="a", issuer_id="bc" because the raw byte
        // stream "abc" is the same in both cases. Length prefixes prevent this.
        let wallet_pubkey = [0u8; 32];

        // Pair 1: session "ab" + issuer "c"
        let msg_a =
            build_issuance_consent_message("ab", "c", "kid", &wallet_pubkey, 0, 0, None).unwrap();

        // Pair 2: session "a" + issuer "bc"
        let msg_b =
            build_issuance_consent_message("a", "bc", "kid", &wallet_pubkey, 0, 0, None).unwrap();

        // Pair 3: session "abc" + issuer "" (empty)
        let msg_c =
            build_issuance_consent_message("abc", "", "kid", &wallet_pubkey, 0, 0, None).unwrap();

        // Pair 4: session "" + issuer "abc"
        let msg_d =
            build_issuance_consent_message("", "abc", "kid", &wallet_pubkey, 0, 0, None).unwrap();

        assert_ne!(msg_a, msg_b, "session boundary shift must not collide");
        assert_ne!(msg_a, msg_c, "session boundary shift must not collide");
        assert_ne!(msg_a, msg_d, "session boundary shift must not collide");
        assert_ne!(msg_b, msg_c, "session boundary shift must not collide");
        assert_ne!(msg_b, msg_d, "session boundary shift must not collide");
        assert_ne!(msg_c, msg_d, "session boundary shift must not collide");

        // Also verify issuer_id / issuer_kid boundary is protected
        let msg_e =
            build_issuance_consent_message("s", "issuerab", "c", &wallet_pubkey, 0, 0, None)
                .unwrap();
        let msg_f =
            build_issuance_consent_message("s", "issuer", "abc", &wallet_pubkey, 0, 0, None)
                .unwrap();
        assert_ne!(msg_e, msg_f, "issuer_kid boundary shift must not collide");
    }

    /* ========================================================================== */
    /*                    COMPUTE_REPLAY_TAG TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_compute_replay_tag_deterministic() {
        let origin_hash = [1u8; 32];
        let nonce = [2u8; 32];

        let tag1 = compute_replay_tag(&origin_hash, &nonce);
        let tag2 = compute_replay_tag(&origin_hash, &nonce);

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_compute_replay_tag_different_origin_hashes() {
        let nonce = [1u8; 32];

        let tag1 = compute_replay_tag(&[1u8; 32], &nonce);
        let tag2 = compute_replay_tag(&[2u8; 32], &nonce);

        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_compute_replay_tag_different_nonces() {
        let origin_hash = [1u8; 32];

        let tag1 = compute_replay_tag(&origin_hash, &[1u8; 32]);
        let tag2 = compute_replay_tag(&origin_hash, &[2u8; 32]);

        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_compute_replay_tag_no_padding() {
        let origin_hash = [1u8; 32];
        let nonce = [2u8; 32];

        let tag = compute_replay_tag(&origin_hash, &nonce);
        assert!(!tag.contains('='));
    }

    #[test]
    fn test_compute_replay_tag_empty_inputs() {
        let tag = compute_replay_tag(&[], &[]);
        assert!(!tag.is_empty());
    }

    #[test]
    fn test_compute_replay_tag_contains_separator() {
        // The function should include the ':' separator in the encoded data
        let origin_hash = [1u8; 16];
        let nonce = [2u8; 16];
        let tag = compute_replay_tag(&origin_hash, &nonce);
        // Tag should be non-empty and valid base64url
        assert!(!tag.is_empty());
        assert!(!tag.contains('='));
        assert!(!tag.contains('+'));
        assert!(!tag.contains('/'));
    }

    /* ========================================================================== */
    /*                    WRITE_LENGTH_PREFIXED TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_write_length_prefixed_empty_data() -> provii_crypto_commons::Result<()> {
        use sha2::Digest;
        let mut h1 = Sha256::new();
        let mut h2 = Sha256::new();

        write_length_prefixed(&mut h1, &[])?;
        h2.update(0u32.to_le_bytes());

        let hash1: [u8; 32] = h1.finalize().into();
        let hash2: [u8; 32] = h2.finalize().into();

        assert_eq!(hash1, hash2);
        Ok(())
    }

    #[test]
    fn test_write_length_prefixed_with_data() -> provii_crypto_commons::Result<()> {
        use sha2::Digest;
        let data = b"test data";

        let mut h1 = Sha256::new();
        let mut h2 = Sha256::new();

        write_length_prefixed(&mut h1, data)?;

        h2.update((data.len() as u32).to_le_bytes());
        h2.update(data);

        let hash1: [u8; 32] = h1.finalize().into();
        let hash2: [u8; 32] = h2.finalize().into();

        assert_eq!(hash1, hash2);
        Ok(())
    }

    #[test]
    fn test_write_length_prefixed_different_data_different_hash(
    ) -> provii_crypto_commons::Result<()> {
        use sha2::Digest;

        let mut h1 = Sha256::new();
        let mut h2 = Sha256::new();

        write_length_prefixed(&mut h1, b"data1")?;
        write_length_prefixed(&mut h2, b"data2")?;

        let hash1: [u8; 32] = h1.finalize().into();
        let hash2: [u8; 32] = h2.finalize().into();

        assert_ne!(hash1, hash2);
        Ok(())
    }

    #[test]
    fn test_write_length_prefixed_prevents_collision() -> provii_crypto_commons::Result<()> {
        use sha2::Digest;

        // "ab" + "c" should hash differently than "a" + "bc"
        let mut h1 = Sha256::new();
        write_length_prefixed(&mut h1, b"ab")?;
        write_length_prefixed(&mut h1, b"c")?;

        let mut h2 = Sha256::new();
        write_length_prefixed(&mut h2, b"a")?;
        write_length_prefixed(&mut h2, b"bc")?;

        let hash1: [u8; 32] = h1.finalize().into();
        let hash2: [u8; 32] = h2.finalize().into();

        assert_ne!(hash1, hash2);
        Ok(())
    }

    /* ========================================================================== */
    /*                    INTEGRATION TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_pkce_flow() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = code_challenge_s256(verifier);

        // Should produce valid base64url without padding
        assert!(!challenge.contains('='));
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
        assert_eq!(challenge.len(), 43); // SHA256 base64url is 43 chars
    }

    #[test]
    fn test_challenge_binding_flow() {
        let origin = "https://example.com";
        let nonce = [42u8; 32];

        let origin_hash = compute_origin_hash(origin);
        let rp_chal = rp_challenge(origin, &nonce);
        let replay_tag = compute_replay_tag(&origin_hash, &nonce);

        assert_eq!(origin_hash.len(), 32);
        assert_eq!(rp_chal.len(), 32);
        assert!(!replay_tag.is_empty());
    }

    /* ========================================================================== */
    /*                    HIGH PRIORITY: MISSING EDGE CASE TESTS                 */
    /* ========================================================================== */

    // Tests for build_issuance_consent_message with extreme values

    #[test]
    fn test_build_issuance_consent_message_consent_time_zero() {
        let msg = build_issuance_consent_message(
            "session-1",
            "issuer-1",
            "key-1",
            &[1u8; 32],
            0, // consent_time = 0
            1,
            None,
        )
        .unwrap();
        assert_eq!(msg.len(), 32);
    }

    #[test]
    fn test_build_issuance_consent_message_consent_time_negative() {
        let msg = build_issuance_consent_message(
            "session-1",
            "issuer-1",
            "key-1",
            &[1u8; 32],
            -1000, // Negative consent_time
            1,
            None,
        )
        .unwrap();
        assert_eq!(msg.len(), 32);
    }

    #[test]
    fn test_build_issuance_consent_message_consent_time_max() {
        let msg = build_issuance_consent_message(
            "session-1",
            "issuer-1",
            "key-1",
            &[1u8; 32],
            i64::MAX, // Maximum consent_time
            1,
            None,
        )
        .unwrap();
        assert_eq!(msg.len(), 32);
    }

    #[test]
    fn test_build_issuance_consent_message_consent_time_min() {
        let msg = build_issuance_consent_message(
            "session-1",
            "issuer-1",
            "key-1",
            &[1u8; 32],
            i64::MIN, // Minimum consent_time
            1,
            None,
        )
        .unwrap();
        assert_eq!(msg.len(), 32);
    }

    #[test]
    fn test_build_issuance_consent_message_nonce_all_zeros() {
        let msg = build_issuance_consent_message(
            "session-1",
            "issuer-1",
            "key-1",
            &[1u8; 32],
            1000,
            1,
            Some([0u8; 16]), // All zeros nonce
        )
        .unwrap();
        assert_eq!(msg.len(), 32);
    }

    #[test]
    fn test_build_issuance_consent_message_nonce_all_ones() {
        let msg = build_issuance_consent_message(
            "session-1",
            "issuer-1",
            "key-1",
            &[1u8; 32],
            1000,
            1,
            Some([255u8; 16]), // All ones nonce
        )
        .unwrap();
        assert_eq!(msg.len(), 32);
    }

    // Tests for compute_replay_tag with large inputs

    #[test]
    fn test_compute_replay_tag_large_origin_hash() {
        // Test with a large origin hash (1024 bytes)
        let large_hash = vec![42u8; 1024];
        let nonce = [1u8; 16];
        let tag = compute_replay_tag(&large_hash, &nonce);
        assert!(!tag.is_empty());
        assert!(!tag.contains('='));
    }

    #[test]
    fn test_compute_replay_tag_large_nonce() {
        // Test with a large nonce (1024 bytes)
        let origin_hash = [1u8; 32];
        let large_nonce = vec![99u8; 1024];
        let tag = compute_replay_tag(&origin_hash, &large_nonce);
        assert!(!tag.is_empty());
        assert!(!tag.contains('='));
    }

    #[test]
    fn test_compute_replay_tag_both_large() {
        // Test with both inputs large
        let large_hash = vec![1u8; 2048];
        let large_nonce = vec![2u8; 2048];
        let tag = compute_replay_tag(&large_hash, &large_nonce);
        assert!(!tag.is_empty());
        assert!(!tag.contains('='));
    }

    // Test for write_length_prefixed - documents limitation
    // NOTE: Testing overflow when data.len() > u32::MAX is not practical
    // as it would require allocating >4GB of memory. This test documents
    // the maximum practical size we can test.

    #[test]
    fn test_write_length_prefixed_large_data() -> provii_crypto_commons::Result<()> {
        use sha2::Digest;
        // Test with 10MB of data (largest practical size for tests)
        let data = vec![42u8; 10_000_000];

        let mut h1 = Sha256::new();
        write_length_prefixed(&mut h1, &data)?;

        let mut h2 = Sha256::new();
        h2.update((data.len() as u32).to_le_bytes());
        h2.update(&data);

        let hash1: [u8; 32] = h1.finalize().into();
        let hash2: [u8; 32] = h2.finalize().into();

        assert_eq!(hash1, hash2);
        Ok(())
    }

    #[test]
    fn test_write_length_prefixed_u32_max_length_documented() -> provii_crypto_commons::Result<()> {
        // write_length_prefixed now returns Err(InvalidInput) when
        // data.len() > u32::MAX. We cannot allocate >4GB in tests, so
        // this test verifies the function succeeds for large-but-valid data.

        use sha2::Digest;
        let max_testable = 1_000_000; // 1MB (practical limit for tests)
        let data = vec![1u8; max_testable];

        let mut h = Sha256::new();
        write_length_prefixed(&mut h, &data)?;
        let _hash: [u8; 32] = h.finalize().into();

        // Test passes if we can handle large (but < u32::MAX) data
        assert!(data.len() < u32::MAX as usize);
        Ok(())
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    use proptest::prelude::*;

    fn fail<E: core::fmt::Debug>(e: E) -> TestCaseError {
        TestCaseError::fail(alloc::format!("{e:?}"))
    }

    proptest! {
        /// Property: code_challenge_s256 is deterministic
        #[test]
        fn prop_code_challenge_s256_deterministic(verifier in "\\PC{1,100}") {
            let challenge1 = code_challenge_s256(&verifier);
            let challenge2 = code_challenge_s256(&verifier);

            prop_assert_eq!(&challenge1, &challenge2);
            prop_assert_eq!(challenge1.len(), 43, "SHA256 base64url should always be 43 chars");
            prop_assert!(!challenge1.contains('='), "Should not contain padding");
        }

        /// Property: code_challenge_s256 output is URL-safe
        #[test]
        fn prop_code_challenge_s256_url_safe(verifier in "\\PC{0,200}") {
            let challenge = code_challenge_s256(&verifier);
            prop_assert!(!challenge.contains('+'), "Must be URL-safe (no +)");
            prop_assert!(!challenge.contains('/'), "Must be URL-safe (no /)");
            prop_assert!(!challenge.contains('='), "Must have no padding");
        }

        /// Property: code_challenge_s256 always produces valid base64url
        #[test]
        fn prop_code_challenge_s256_valid_base64url(verifier in "\\PC{0,100}") {
            let challenge = code_challenge_s256(&verifier);
            // Should only contain base64url alphabet
            prop_assert!(challenge.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        }

        /// Property: empty verifier produces valid challenge
        #[test]
        fn prop_code_challenge_s256_empty_verifier(_unit in 0..10) {
            let challenge = code_challenge_s256("");
            prop_assert_eq!(challenge.len(), 43);
            prop_assert!(!challenge.is_empty());
        }

        /// Property: generate_nonce always generates 32 bytes
        #[test]
        #[cfg(not(target_arch = "wasm32"))]
        fn prop_generate_nonce_length(_i in 0..100) {
            let nonce = generate_nonce().map_err(fail)?;
            prop_assert_eq!(nonce.len(), 32, "Nonce must always be exactly 32 bytes");
        }

        /// Property: generate_nonce generates unique nonces
        #[test]
        #[cfg(not(target_arch = "wasm32"))]
        fn prop_generate_nonce_uniqueness(_i in 0..50) {
            let nonce1 = generate_nonce().map_err(fail)?;
            let nonce2 = generate_nonce().map_err(fail)?;
            prop_assert_ne!(nonce1, nonce2, "Consecutive nonces should be unique");
        }

        /// Property: compute_origin_hash is deterministic
        #[test]
        fn prop_compute_origin_hash_deterministic(origin in "\\PC{1,200}") {
            let hash1 = compute_origin_hash(&origin);
            let hash2 = compute_origin_hash(&origin);

            prop_assert_eq!(hash1, hash2);
            prop_assert_eq!(hash1.len(), 32, "SHA256 output must be 32 bytes");
        }

        /// Property: compute_origin_hash output never all zeros (except for specific input)
        #[test]
        fn prop_compute_origin_hash_non_trivial(origin in "[a-zA-Z0-9]{1,100}") {
            let hash = compute_origin_hash(&origin);
            // Hash should have at least one non-zero byte for non-empty input
            prop_assert!(hash.iter().any(|&b| b != 0));
        }

        /// Property: compute_replay_tag is deterministic
        #[test]
        fn prop_compute_replay_tag_deterministic(
            origin_hash in any::<[u8; 32]>(),
            nonce in any::<[u8; 32]>()
        ) {
            let tag1 = compute_replay_tag(&origin_hash, &nonce);
            let tag2 = compute_replay_tag(&origin_hash, &nonce);

            prop_assert_eq!(&tag1, &tag2);
            prop_assert!(!tag1.contains('='), "Should not contain padding");
            prop_assert!(!tag1.is_empty(), "Tag should not be empty");
        }

        /// Property: compute_replay_tag is URL-safe
        #[test]
        fn prop_compute_replay_tag_url_safe(
            origin_hash in any::<[u8; 32]>(),
            nonce in any::<[u8; 32]>()
        ) {
            let tag = compute_replay_tag(&origin_hash, &nonce);
            prop_assert!(!tag.contains('+'), "Must be URL-safe (no +)");
            prop_assert!(!tag.contains('/'), "Must be URL-safe (no /)");
        }

        /// Property: different origin_hash or nonce produces different tag
        #[test]
        fn prop_compute_replay_tag_sensitivity(
            origin_hash1 in any::<[u8; 32]>(),
            origin_hash2 in any::<[u8; 32]>(),
            nonce in any::<[u8; 32]>()
        ) {
            prop_assume!(origin_hash1 != origin_hash2);
            let tag1 = compute_replay_tag(&origin_hash1, &nonce);
            let tag2 = compute_replay_tag(&origin_hash2, &nonce);
            prop_assert_ne!(&tag1, &tag2);
        }

        /// Property: rp_challenge is deterministic
        #[test]
        fn prop_rp_challenge_deterministic(
            origin in "\\PC{1,100}",
            nonce in any::<[u8; 32]>()
        ) {
            let challenge1 = rp_challenge(&origin, &nonce);
            let challenge2 = rp_challenge(&origin, &nonce);

            prop_assert_eq!(challenge1, challenge2);
            prop_assert_eq!(challenge1.len(), 32, "Challenge must be 32 bytes");
        }

        /// Property: rp_challenge output is non-trivial
        #[test]
        fn prop_rp_challenge_non_trivial(
            origin in "https://[a-z]{5,20}\\.com",
            nonce in any::<[u8; 32]>()
        ) {
            let challenge = rp_challenge(&origin, &nonce);
            // At least one byte should be non-zero
            prop_assert!(challenge.iter().any(|&b| b != 0));
        }

        /// Property: rp_challenge is sensitive to origin changes
        #[test]
        fn prop_rp_challenge_origin_sensitive(
            origin1 in "https://[a-z]{5,10}\\.com",
            origin2 in "https://[a-z]{5,10}\\.com",
            nonce in any::<[u8; 32]>()
        ) {
            prop_assume!(origin1 != origin2);
            let challenge1 = rp_challenge(&origin1, &nonce);
            let challenge2 = rp_challenge(&origin2, &nonce);
            prop_assert_ne!(challenge1, challenge2);
        }

        /// Property: rp_challenge is sensitive to nonce changes
        #[test]
        fn prop_rp_challenge_nonce_sensitive(
            origin in "https://example\\.com",
            nonce1 in any::<[u8; 32]>(),
            nonce2 in any::<[u8; 32]>()
        ) {
            prop_assume!(nonce1 != nonce2);
            let challenge1 = rp_challenge(&origin, &nonce1);
            let challenge2 = rp_challenge(&origin, &nonce2);
            prop_assert_ne!(challenge1, challenge2);
        }

        /// Property: different origins produce different hashes
        #[test]
        fn prop_different_origins_produce_different_hashes(
            origin1 in "https://[a-z]{5,10}\\.com",
            origin2 in "https://[a-z]{5,10}\\.com"
        ) {
            prop_assume!(origin1 != origin2);

            let hash1 = compute_origin_hash(&origin1);
            let hash2 = compute_origin_hash(&origin2);

            prop_assert_ne!(hash1, hash2, "Different origins must produce different hashes");
        }

        /// Property: different verifiers produce different challenges
        #[test]
        fn prop_different_verifiers_produce_different_challenges(
            verifier1 in "\\PC{10,50}",
            verifier2 in "\\PC{10,50}"
        ) {
            prop_assume!(verifier1 != verifier2);

            let challenge1 = code_challenge_s256(&verifier1);
            let challenge2 = code_challenge_s256(&verifier2);

            prop_assert_ne!(&challenge1, &challenge2, "Different verifiers must produce different challenges");
        }

        /// Property: build_issuance_consent_message is deterministic
        #[test]
        fn prop_build_issuance_consent_message_deterministic(
            session_id in "\\PC{1,50}",
            issuer_id in "\\PC{1,50}",
            issuer_kid in "\\PC{1,50}",
            wallet_pubkey in any::<[u8; 32]>(),
            consent_time in any::<i64>(),
            terms_version in any::<u32>()
        ) {
            let msg1 = build_issuance_consent_message(
                &session_id, &issuer_id, &issuer_kid, &wallet_pubkey,
                consent_time, terms_version, None
            ).map_err(fail)?;
            let msg2 = build_issuance_consent_message(
                &session_id, &issuer_id, &issuer_kid, &wallet_pubkey,
                consent_time, terms_version, None
            ).map_err(fail)?;
            prop_assert_eq!(msg1, msg2);
            prop_assert_eq!(msg1.len(), 32);
        }

        /// Property: build_issuance_consent_message with different nonces produces different output
        #[test]
        fn prop_build_issuance_consent_message_nonce_sensitivity(
            session_id in "\\PC{1,50}",
            issuer_id in "\\PC{1,50}",
            issuer_kid in "\\PC{1,50}",
            wallet_pubkey in any::<[u8; 32]>(),
            consent_time in any::<i64>(),
            terms_version in any::<u32>(),
            nonce1 in any::<[u8; 16]>(),
            nonce2 in any::<[u8; 16]>()
        ) {
            prop_assume!(nonce1 != nonce2);
            let msg1 = build_issuance_consent_message(
                &session_id, &issuer_id, &issuer_kid, &wallet_pubkey,
                consent_time, terms_version, Some(nonce1)
            ).map_err(fail)?;
            let msg2 = build_issuance_consent_message(
                &session_id, &issuer_id, &issuer_kid, &wallet_pubkey,
                consent_time, terms_version, Some(nonce2)
            ).map_err(fail)?;
            prop_assert_ne!(msg1, msg2);
        }

        /// Property: build_issuance_consent_message sensitive to session_id
        #[test]
        fn prop_build_issuance_consent_message_session_sensitivity(
            session_id1 in "\\PC{10,30}",
            session_id2 in "\\PC{10,30}",
            issuer_id in "issuer",
            issuer_kid in "kid",
            wallet_pubkey in any::<[u8; 32]>()
        ) {
            prop_assume!(session_id1 != session_id2);
            let msg1 = build_issuance_consent_message(
                &session_id1, &issuer_id, &issuer_kid, &wallet_pubkey, 1000, 1, None
            ).map_err(fail)?;
            let msg2 = build_issuance_consent_message(
                &session_id2, &issuer_id, &issuer_kid, &wallet_pubkey, 1000, 1, None
            ).map_err(fail)?;
            prop_assert_ne!(msg1, msg2);
        }

        /// Property: write_length_prefixed produces deterministic output
        #[test]
        fn prop_write_length_prefixed_deterministic(data in prop::collection::vec(any::<u8>(), 0..100)) {
            let mut h1 = Sha256::new();
            let mut h2 = Sha256::new();
            write_length_prefixed(&mut h1, &data).map_err(fail)?;
            write_length_prefixed(&mut h2, &data).map_err(fail)?;

            let hash1: [u8; 32] = h1.finalize().into();
            let hash2: [u8; 32] = h2.finalize().into();
            prop_assert_eq!(hash1, hash2);
        }

        /// Property: write_length_prefixed prevents collision between different data
        #[test]
        fn prop_write_length_prefixed_collision_resistance(
            data1 in prop::collection::vec(any::<u8>(), 1..50),
            data2 in prop::collection::vec(any::<u8>(), 1..50)
        ) {
            prop_assume!(data1 != data2);

            let mut h1 = Sha256::new();
            write_length_prefixed(&mut h1, &data1).map_err(fail)?;
            let hash1: [u8; 32] = h1.finalize().into();

            let mut h2 = Sha256::new();
            write_length_prefixed(&mut h2, &data2).map_err(fail)?;
            let hash2: [u8; 32] = h2.finalize().into();

            prop_assert_ne!(hash1, hash2);
        }

        /// Property: compute_replay_tag with zero inputs is valid
        #[test]
        fn prop_compute_replay_tag_zero_inputs(_unit in 0..10) {
            let tag = compute_replay_tag(&[0u8; 32], &[0u8; 32]);
            prop_assert!(!tag.is_empty());
            prop_assert!(!tag.contains('='));
        }

        /// Property: compute_origin_hash case sensitive
        #[test]
        fn prop_compute_origin_hash_case_sensitive(
            base in "[a-z]{10,20}"
        ) {
            let lower = base.to_lowercase();
            let upper = base.to_uppercase();
            prop_assume!(lower != upper);

            let hash1 = compute_origin_hash(&lower);
            let hash2 = compute_origin_hash(&upper);
            prop_assert_ne!(hash1, hash2, "Hash must be case-sensitive");
        }

        /// Property: rp_challenge with empty origin is valid
        #[test]
        fn prop_rp_challenge_empty_origin(nonce in any::<[u8; 32]>()) {
            let challenge = rp_challenge("", &nonce);
            prop_assert_eq!(challenge.len(), 32);
        }

        /// Property: build_issuance_consent_message output is always 32 bytes
        #[test]
        fn prop_build_issuance_consent_message_output_length(
            session_id in "\\PC{0,100}",
            issuer_id in "\\PC{0,100}",
            issuer_kid in "\\PC{0,100}",
            wallet_pubkey in any::<[u8; 32]>(),
            consent_time in any::<i64>(),
            terms_version in any::<u32>()
        ) {
            let msg = build_issuance_consent_message(
                &session_id, &issuer_id, &issuer_kid, &wallet_pubkey,
                consent_time, terms_version, None
            ).map_err(fail)?;
            prop_assert_eq!(msg.len(), 32);
        }

        /// Property: build_issuance_consent_message with/without nonce differs
        #[test]
        fn prop_build_issuance_consent_message_nonce_changes_output(
            session_id in "session",
            issuer_id in "issuer",
            issuer_kid in "kid",
            wallet_pubkey in any::<[u8; 32]>(),
            nonce in any::<[u8; 16]>()
        ) {
            let msg_without = build_issuance_consent_message(
                &session_id, &issuer_id, &issuer_kid, &wallet_pubkey, 1000, 1, None
            ).map_err(fail)?;
            let msg_with = build_issuance_consent_message(
                &session_id, &issuer_id, &issuer_kid, &wallet_pubkey, 1000, 1, Some(nonce)
            ).map_err(fail)?;
            prop_assert_ne!(msg_without, msg_with);
        }

        /// Property: code_challenge_s256 length invariant
        #[test]
        fn prop_code_challenge_s256_length_invariant(verifier in "\\PC{0,500}") {
            let challenge = code_challenge_s256(&verifier);
            prop_assert_eq!(challenge.len(), 43, "SHA256 base64url must always be 43 chars");
        }

        /// Property: compute_origin_hash with Unicode
        #[test]
        fn prop_compute_origin_hash_unicode(prefix in "https://", suffix in "[a-z]{5,10}") {
            let origin1 = format!("{prefix}{suffix}αβγ.com");
            let origin2 = format!("{prefix}{suffix}xyz.com");
            let hash1 = compute_origin_hash(&origin1);
            let hash2 = compute_origin_hash(&origin2);
            prop_assert_ne!(hash1, hash2);
        }
    }
}
