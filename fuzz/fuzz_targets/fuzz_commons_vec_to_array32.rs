#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_commons::vec_to_array32;

/// Fuzz vec_to_array32 function
/// Tests:
/// - Accepts exactly 32 bytes
/// - Rejects < 32 bytes
/// - Rejects > 32 bytes
/// - Empty input
/// - Determinism
/// - Data preservation
fuzz_target!(|data: &[u8]| {
    let result = vec_to_array32(data);

    if data.len() == 32 {
        // Invariant: exactly 32 bytes should succeed
        assert!(result.is_ok(), "Exactly 32 bytes must succeed");

        let arr = result.unwrap();

        // Invariant: data preservation
        for i in 0..32 {
            assert_eq!(arr[i], data[i], "Data must be preserved at index {}", i);
        }

        // Invariant: determinism
        let result2 = vec_to_array32(data);
        assert!(result2.is_ok());
        assert_eq!(arr, result2.unwrap(), "Function must be deterministic");
    } else {
        // Invariant: non-32-byte inputs should fail
        assert!(result.is_err(), "Non-32-byte input must fail: got {} bytes", data.len());
    }

    // Test boundary cases
    let _ = vec_to_array32(&[]);  // Empty
    let _ = vec_to_array32(&vec![0u8; 31]);  // One byte short
    let _ = vec_to_array32(&vec![0u8; 32]);  // Exactly right
    let _ = vec_to_array32(&vec![0u8; 33]);  // One byte over
    let _ = vec_to_array32(&vec![0u8; 1]);   // Way too short
    let _ = vec_to_array32(&vec![0u8; 100]); // Way too long

    // Test all-zero input
    if data.len() == 32 {
        let zeros = vec![0u8; 32];
        let result_zeros = vec_to_array32(&zeros);
        assert!(result_zeros.is_ok());
        assert_eq!(result_zeros.unwrap(), [0u8; 32]);
    }

    // Test all-ones input
    if data.len() == 32 {
        let ones = vec![0xFFu8; 32];
        let result_ones = vec_to_array32(&ones);
        assert!(result_ones.is_ok());
        assert_eq!(result_ones.unwrap(), [0xFFu8; 32]);
    }
});
