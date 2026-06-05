#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_protocol::build_issuance_consent_message;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    session_id: Vec<u8>,
    issuer_id: Vec<u8>,
    issuer_kid: Vec<u8>,
    wallet_pubkey: [u8; 32],
    consent_time: i64,
    terms_version: u32,
    nonce: Option<[u8; 16]>,
}

/// Fuzz build_issuance_consent_message function
/// Tests:
/// - Various string inputs (empty, long, Unicode, special chars)
/// - Extreme timestamp values (negative, zero, max)
/// - With and without nonce
/// - Determinism
/// - Output is always 32 bytes
fuzz_target!(|input: FuzzInput| {
    if let (Ok(session_id), Ok(issuer_id), Ok(issuer_kid)) = (
        std::str::from_utf8(&input.session_id),
        std::str::from_utf8(&input.issuer_id),
        std::str::from_utf8(&input.issuer_kid),
    ) {
        let message = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &input.wallet_pubkey,
            input.consent_time,
            input.terms_version,
            input.nonce,
        ).unwrap();

        // Invariant: output is always 32 bytes
        assert_eq!(message.len(), 32, "Message must be 32 bytes");

        // Invariant: determinism
        let message2 = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &input.wallet_pubkey,
            input.consent_time,
            input.terms_version,
            input.nonce,
        ).unwrap();
        assert_eq!(message, message2, "Function must be deterministic");

        // Invariant: with/without nonce produces different results
        let message_no_nonce = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &input.wallet_pubkey,
            input.consent_time,
            input.terms_version,
            None,
        ).unwrap();

        if input.nonce.is_some() {
            assert_ne!(message, message_no_nonce, "Nonce should affect output");
        } else {
            assert_eq!(message, message_no_nonce, "Same parameters should produce same output");
        }

        // Test extreme values
        let _ = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &input.wallet_pubkey,
            i64::MIN,
            input.terms_version,
            input.nonce,
        ).unwrap();

        let _ = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &input.wallet_pubkey,
            i64::MAX,
            input.terms_version,
            input.nonce,
        ).unwrap();

        let _ = build_issuance_consent_message(
            session_id,
            issuer_id,
            issuer_kid,
            &input.wallet_pubkey,
            0,
            u32::MAX,
            input.nonce,
        ).unwrap();
    }
});
