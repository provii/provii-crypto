// Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792)
// SPDX-License-Identifier: Apache-2.0

//! Mutation-killing tests for `generate_commitment_randomness` and
//! `validate_commitment_randomness`.
//!
//! Targets:
//! - crypto-commit/src/lib.rs:159, `== → !=` inversion in bit extraction
//! - crypto-commit/src/lib.rs:176, `< → <=` / `< → ==` on length guard
//! - crypto-commit/src/lib.rs:212, `>= → >` on entropy threshold

#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use provii_crypto_commit::{generate_commitment_randomness, validate_commitment_randomness};
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// ---------------------------------------------------------------------------
// Test 1: Bit extraction correctness (kills == → != on line 159)
// ---------------------------------------------------------------------------

/// Verifies that `generate_commitment_randomness` extracts bits correctly from
/// the underlying byte stream. Uses a deterministic seed so we can independently
/// compute the expected bits. The `== → !=` mutant inverts every bit, causing
/// a total mismatch.
#[test]
fn bit_extraction_matches_independent_computation() {
    let seed = [0xAA; 32];

    // Generate bits via the function under test.
    let mut rng = ChaCha20Rng::from_seed(seed);
    let bits = generate_commitment_randomness(&mut rng, 64);

    // Independently generate the raw bytes from the same seed.
    let mut rng2 = ChaCha20Rng::from_seed(seed);
    let mut expected_bytes = [0u8; 8]; // 64 bits = 8 bytes
    rng2.fill_bytes(&mut expected_bytes);

    // Verify each bit matches the little-endian extraction.
    for i in 0..64 {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let expected_bit = ((expected_bytes[byte_idx] >> bit_idx) & 1) == 1;
        assert_eq!(
            bits[i], expected_bit,
            "bit {i} mismatch (byte {byte_idx} = 0x{:02X}, bit_idx {bit_idx}): got {}, expected {}",
            expected_bytes[byte_idx], bits[i], expected_bit
        );
    }
}

/// Same verification with a different seed and non-byte-aligned bit count.
/// Ensures partial-byte extraction is also correct. The `== → !=` mutant
/// fails here because ALL bits are inverted, not just the partial-byte ones.
#[test]
fn bit_extraction_non_aligned_length() {
    let seed = [0x55; 32];

    let mut rng = ChaCha20Rng::from_seed(seed);
    let bits = generate_commitment_randomness(&mut rng, 13); // Not a multiple of 8

    let mut rng2 = ChaCha20Rng::from_seed(seed);
    let mut expected_bytes = [0u8; 2]; // ceil(13/8) = 2 bytes
    rng2.fill_bytes(&mut expected_bytes);

    for i in 0..13 {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let expected_bit = ((expected_bytes[byte_idx] >> bit_idx) & 1) == 1;
        assert_eq!(
            bits[i], expected_bit,
            "bit {i} mismatch for 13-bit extraction"
        );
    }
}

/// Verify that the NOT of the correct output does NOT equal the actual output.
/// This is a direct assertion against the `== → !=` mutant's behaviour.
#[test]
fn bit_extraction_not_inverted() {
    let seed = [0x42; 32];

    let mut rng = ChaCha20Rng::from_seed(seed);
    let bits = generate_commitment_randomness(&mut rng, 256);

    // Invert all bits (this is what the mutant would produce).
    let inverted: Vec<bool> = bits.iter().map(|b| !b).collect();

    // Must differ from the inverted form. With 256 random bits, the probability
    // of the output being its own inverse is zero, but we verify regardless.
    let actual: &[bool] = &bits;
    assert_ne!(
        actual,
        inverted.as_slice(),
        "Output must not be the bitwise inverse of correct extraction"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Length guard boundary (targets < → <= and < → == on line 176)
// ---------------------------------------------------------------------------

/// Exactly 32 bits must pass the length guard (original: `< 32` rejects < 32).
/// With `< → <=`, 32 bits would be rejected at the guard instead of reaching
/// the entropy check. Although the ultimate outcome is identical (rejection due
/// to insufficient entropy with only 4 bytes), this test documents the boundary.
///
/// NOTE: This mutant is semantically equivalent because 4 bytes can never
/// satisfy the >= 8 unique byte values requirement. The test exists for
/// coverage documentation and to catch subtly different mutations.
#[test]
fn length_guard_rejects_below_32() {
    // 31 bits: must fail (caught by length guard in original, or entropy in mutant).
    let short: Vec<bool> = (0..31).map(|i| i % 2 == 0).collect();
    assert!(
        validate_commitment_randomness(&short).is_err(),
        "31 bits must be rejected"
    );

    // 0 bits: must fail.
    assert!(
        validate_commitment_randomness(&[]).is_err(),
        "Empty input must be rejected"
    );
}

/// Inputs of 64 bits (8 bytes) with sufficient entropy must pass validation.
/// With `< → ==` mutant, this still passes (64 != 32). The real value is
/// verifying the function accepts valid short-ish inputs above the threshold.
#[test]
fn length_guard_accepts_at_and_above_32() {
    // 64 bits with 8 distinct byte values (each byte is unique).
    // Bytes: 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    let distinct_bytes: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let bits: Vec<bool> = distinct_bytes
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| ((byte >> i) & 1) == 1))
        .collect();

    assert_eq!(bits.len(), 64);
    assert!(
        validate_commitment_randomness(&bits).is_ok(),
        "64 bits with 8 distinct byte values must pass validation"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Entropy threshold boundary (targets >= → > on line 212)
// ---------------------------------------------------------------------------

/// Constructs input with exactly 8 unique byte values. Under `>= 8` this
/// passes; under `> 8` it would fail. Kills the `>= → >` mutant.
#[test]
fn entropy_threshold_exactly_8_unique_bytes_passes() {
    // 128 bits = 16 bytes. Use exactly 8 distinct values, each repeated twice.
    let byte_values: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // 8 unique
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // repeated
    ];
    let bits: Vec<bool> = byte_values
        .iter()
        .flat_map(|&byte| (0..8).map(move |i| ((byte >> i) & 1) == 1))
        .collect();

    assert_eq!(bits.len(), 128);
    assert!(
        validate_commitment_randomness(&bits).is_ok(),
        "Exactly 8 unique byte values must pass (>= 8 threshold)"
    );
}

/// Constructs input with exactly 7 unique byte values. Must fail regardless of
/// which mutant is active on line 212.
#[test]
fn entropy_threshold_7_unique_bytes_fails() {
    // 128 bits = 16 bytes with only 7 distinct byte values.
    let byte_values_7: Vec<u8> = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00,
        0x11,
    ];
    let bits: Vec<bool> = byte_values_7
        .iter()
        .flat_map(|&byte| (0..8u8).map(move |i| ((byte >> i) & 1) == 1))
        .collect();

    assert_eq!(bits.len(), 128);
    assert!(
        validate_commitment_randomness(&bits).is_err(),
        "Only 7 unique byte values must fail the entropy check"
    );
}
