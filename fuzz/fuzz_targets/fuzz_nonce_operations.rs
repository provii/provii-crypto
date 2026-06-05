#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_protocol::nonce::{validate_nonce, has_sufficient_entropy};

/// Fuzz nonce validation functions
/// Tests:
/// - validate_nonce with various inputs
/// - has_sufficient_entropy with various inputs
/// - All-zero nonces
/// - Single unique byte
/// - Multiple unique bytes
/// - Edge cases around 8 unique bytes threshold
fuzz_target!(|data: &[u8]| {
    // Test with variable-length input
    if data.len() >= 32 {
        let nonce_slice = &data[0..32];
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(nonce_slice);

        // Test validate_nonce
        let is_valid = validate_nonce(&nonce);
        let has_entropy = has_sufficient_entropy(&nonce);

        // Invariant: all-zero nonce is invalid
        if nonce == [0u8; 32] {
            assert!(!is_valid, "All-zero nonce must be invalid");
        }

        // Invariant: validate_nonce now requires non-zero AND sufficient entropy
        if nonce.iter().any(|&b| b != 0) && has_entropy {
            assert!(is_valid, "Non-zero nonce with sufficient entropy must be valid");
        }
        if !nonce.iter().any(|&b| b != 0) || !has_entropy {
            assert!(!is_valid, "Zero nonce or insufficient entropy must be invalid");
        }

        // Test has_sufficient_entropy

        // Count unique bytes
        let mut seen = [false; 256];
        let mut unique_count = 0;
        for &b in &nonce {
            if !seen[b as usize] {
                seen[b as usize] = true;
                unique_count += 1;
            }
        }

        // Invariant: >= 8 unique bytes means sufficient entropy
        if unique_count >= 8 {
            assert!(has_entropy,
                "Nonce with {} unique bytes must have sufficient entropy", unique_count);
        }

        // Invariant: < 8 unique bytes means insufficient entropy
        if unique_count < 8 {
            assert!(!has_entropy,
                "Nonce with {} unique bytes must not have sufficient entropy", unique_count);
        }

        // Test edge cases
        let all_same = [42u8; 32];
        assert!(!has_sufficient_entropy(&all_same), "All same byte has insufficient entropy");

        let mut seven_unique = [0u8; 32];
        for i in 0..7 {
            seven_unique[i] = i as u8;
        }
        assert!(!has_sufficient_entropy(&seven_unique), "7 unique bytes is insufficient");

        let mut eight_unique = [0u8; 32];
        for i in 0..8 {
            eight_unique[i] = i as u8;
        }
        assert!(has_sufficient_entropy(&eight_unique), "8 unique bytes is sufficient");

        let mut many_unique = [0u8; 32];
        for i in 0..32 {
            many_unique[i] = i as u8;
        }
        assert!(has_sufficient_entropy(&many_unique), "32 unique bytes is sufficient");
    }

    // Test with all possible single-byte nonces
    for byte_val in 0..=255u8 {
        let single_byte_nonce = [byte_val; 32];
        let is_valid = validate_nonce(&single_byte_nonce);
        let has_entropy = has_sufficient_entropy(&single_byte_nonce);

        // All single-byte-repeated nonces fail: either all-zero (non-zero check)
        // or all-same (entropy check requires 8+ unique bytes).
        assert!(!is_valid, "Uniform nonce must be invalid (insufficient entropy)");
        assert!(!has_entropy, "Single unique byte never has sufficient entropy");
    }
});
