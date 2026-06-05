#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_public_inputs::bits_le_from_bytes;

/// Fuzz bits_le_from_bytes function
/// Tests:
/// - Empty input
/// - Single byte
/// - Multiple bytes
/// - Various byte values (0x00, 0xFF, etc.)
/// - Large inputs
/// - Correct bit extraction (LSB first)
/// - Determinism
fuzz_target!(|data: &[u8]| {
    let bits = bits_le_from_bytes(data);

    // Invariant: output length is always 8 * input length
    assert_eq!(bits.len(), data.len() * 8,
        "Output length must be 8x input length");

    // Invariant: determinism
    let bits2 = bits_le_from_bytes(data);
    assert_eq!(bits, bits2, "Function must be deterministic");

    // Invariant: verify bit extraction is correct (LSB first)
    for (byte_idx, &byte_val) in data.iter().enumerate() {
        for bit_idx in 0..8 {
            let expected = (byte_val >> bit_idx) & 1 == 1;
            let actual = bits[byte_idx * 8 + bit_idx];
            assert_eq!(actual, expected,
                "Bit mismatch at byte {} bit {}: expected {}, got {}",
                byte_idx, bit_idx, expected, actual);
        }
    }

    // Test special cases
    let empty_bits = bits_le_from_bytes(&[]);
    assert_eq!(empty_bits.len(), 0, "Empty input should produce empty output");

    let zero_bits = bits_le_from_bytes(&[0u8]);
    assert_eq!(zero_bits.len(), 8);
    assert!(zero_bits.iter().all(|&b| !b), "All zeros should produce all false bits");

    let ff_bits = bits_le_from_bytes(&[0xFFu8]);
    assert_eq!(ff_bits.len(), 8);
    assert!(ff_bits.iter().all(|&b| b), "All ones should produce all true bits");

    // Test alternating pattern
    let aa_bits = bits_le_from_bytes(&[0xAAu8]);  // 0b10101010
    assert_eq!(aa_bits.len(), 8);
    // LSB first: bit 0=0, bit 1=1, bit 2=0, bit 3=1, etc.
    assert!(!aa_bits[0]);
    assert!(aa_bits[1]);
    assert!(!aa_bits[2]);
    assert!(aa_bits[3]);

    // Test round-trip property: if we reconstruct the bytes from bits, we should get original
    if data.len() > 0 && data.len() <= 100 {  // Limit size for test
        for (byte_idx, &byte_val) in data.iter().enumerate() {
            let mut reconstructed = 0u8;
            for bit_idx in 0..8 {
                if bits[byte_idx * 8 + bit_idx] {
                    reconstructed |= 1 << bit_idx;
                }
            }
            assert_eq!(reconstructed, byte_val,
                "Reconstructed byte {} doesn't match original", byte_idx);
        }
    }
});
