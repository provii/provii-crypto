#![no_main]

use libfuzzer_sys::fuzz_target;
use hex;

/// Fuzz hex encoding/decoding
/// Tests:
/// - Encoding determinism
/// - Output is lowercase
/// - Output length is 2x input
/// - Only valid hex characters
/// - Round-trip encoding/decoding
/// - Decoding various inputs
fuzz_target!(|data: &[u8]| {
    // Test encoding
    let encoded = hex::encode(data);

    // Invariant: output length is 2x input length
    assert_eq!(encoded.len(), data.len() * 2,
        "Hex encoding length must be 2x input length");

    // Invariant: output is lowercase hex digits
    for ch in encoded.chars() {
        assert!(ch.is_ascii_hexdigit(),
            "Hex encoding must produce hex digits");
        assert!(!ch.is_ascii_uppercase(),
            "Hex encoding must be lowercase");
    }

    // Invariant: determinism
    let encoded2 = hex::encode(data);
    assert_eq!(encoded, encoded2, "Hex encoding must be deterministic");

    // Invariant: round-trip encoding/decoding
    if let Ok(decoded) = hex::decode(&encoded) {
        assert_eq!(decoded, data, "Round-trip must preserve data");
    } else {
        panic!("hex::decode failed on hex::encode output");
    }

    // Test decoding the input (if it's valid UTF-8)
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = hex::decode(s);  // Should not panic, may fail for invalid hex
    }

    // Test with various invalid hex strings
    let invalid_hex = vec![
        "xyz",  // Invalid characters
        "12G4",  // Invalid character G
        "123",  // Odd length
        "",  // Empty (should succeed and return empty vec)
    ];

    for invalid in invalid_hex {
        let result = hex::decode(invalid);
        if invalid.is_empty() {
            assert!(result.is_ok(), "Empty string should decode to empty vec");
            assert_eq!(result.unwrap(), Vec::<u8>::new());
        } else if invalid.len() % 2 != 0 {
            assert!(result.is_err(), "Odd-length hex string should fail");
        }
    }

    // Test that different data encodes to different hex
    if data.len() > 0 {
        let mut modified = data.to_vec();
        modified[0] = modified[0].wrapping_add(1);
        let encoded_modified = hex::encode(&modified);
        assert_ne!(encoded, encoded_modified,
            "Different data must encode to different hex");
    }

    // Test special patterns
    let all_zeros = vec![0u8; data.len()];
    let all_zeros_hex = hex::encode(&all_zeros);
    assert_eq!(all_zeros_hex, "0".repeat(data.len() * 2),
        "All zeros should encode to all '0' characters");

    let all_ff = vec![0xFFu8; data.len()];
    let all_ff_hex = hex::encode(&all_ff);
    assert_eq!(all_ff_hex, "f".repeat(data.len() * 2),
        "All 0xFF should encode to all 'f' characters");
});
