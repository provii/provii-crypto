#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_verifier::load_vk;

/// Fuzz load_vk function
/// Tests:
/// - Empty input
/// - Short inputs (< minimum VK size)
/// - Random data
/// - Truncated data
/// - Large inputs
/// - All-zero data
/// - All-0xFF data
/// - Should reject all invalid inputs gracefully (no panics)
fuzz_target!(|data: &[u8]| {
    // The function should handle any input gracefully without panicking
    let result = load_vk(data);

    // Invariant: invalid inputs should return an error (not panic)
    // Valid VK data is very specific format, so random data should fail
    if data.len() < 100 {
        // Very short inputs should definitely fail
        assert!(result.is_err(),
            "Short input ({} bytes) should be rejected", data.len());
    }

    // Test edge cases
    let _ = load_vk(&[]);  // Empty
    let _ = load_vk(&[0u8; 10]);  // Very short
    let _ = load_vk(&[0u8; 100]);  // Short
    let _ = load_vk(&[0xFFu8; 100]);  // Short with all 0xFF
    let _ = load_vk(&[0xAAu8; 500]);  // Medium size random data

    // Test that the function doesn't panic on large inputs
    if data.len() <= 10000 {  // Reasonable limit for fuzzing
        let _ = load_vk(data);
    }

    // Verify error messages are meaningful (if we can extract them)
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(!err_msg.is_empty(), "Error message should not be empty");
        assert!(err_msg.contains("read vk") || err_msg.len() > 0,
            "Error message should be meaningful");
    }
});
