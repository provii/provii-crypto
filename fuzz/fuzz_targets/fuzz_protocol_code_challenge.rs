#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_protocol::code_challenge_s256;

/// Fuzz code_challenge_s256 function
/// Tests:
/// - Empty strings
/// - Very long strings
/// - Unicode characters
/// - Special characters
/// - Binary data
/// - Determinism (same input → same output)
/// - Output is always valid URL-safe base64 (no padding, 43 chars)
fuzz_target!(|data: &[u8]| {
    // Convert bytes to string (may contain invalid UTF-8, that's OK to test)
    if let Ok(verifier) = std::str::from_utf8(data) {
        let challenge = code_challenge_s256(verifier);

        // Invariant: output should always be 43 characters (SHA256 base64url)
        assert_eq!(challenge.len(), 43, "Output length must be 43 characters");

        // Invariant: output should not contain padding
        assert!(!challenge.contains('='), "Output must not contain padding");

        // Invariant: output should not contain non-URL-safe characters
        assert!(!challenge.contains('+'), "Output must not contain '+'");
        assert!(!challenge.contains('/'), "Output must not contain '/'");

        // Invariant: output should only contain valid base64url characters
        assert!(challenge.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_'
        }), "Output must only contain base64url characters");

        // Invariant: determinism - same input produces same output
        let challenge2 = code_challenge_s256(verifier);
        assert_eq!(challenge, challenge2, "Function must be deterministic");
    }
});
