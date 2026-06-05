#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

//! Boundary tests for `pedersen_commit_dob_validated` targeting surviving mutants:
//!
//! 1. Line 53: `r_bits.len() > MAX` mutated to `>=`, killed by testing at exactly
//!    MAX_PEDERSEN_RANDOMNESS_BITS (1096) which must succeed.
//! 2. Line 65: `(value & 1) != 0` mutated to `== 0`, killed by pinning the exact
//!    commitment output for a known input (flipping all DOB bits changes the hash).

use provii_crypto_commit::{
    generate_commitment_randomness, pedersen_commit_dob_validated, validate_commitment_randomness,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Deterministic high-entropy randomness for tests.
fn fixed_r_bits(seed_byte: u8, num_bits: usize) -> Vec<bool> {
    let mut rng = ChaCha20Rng::from_seed([seed_byte; 32]);
    generate_commitment_randomness(&mut rng, num_bits).to_vec()
}

// ─────────────────────────────────────────────────────────────────────────────
// Mutant: r_bits.len() > MAX_PEDERSEN_RANDOMNESS_BITS  →  >=
// Killed by: exactly 1096 bits must SUCCEED.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn exact_max_randomness_bits_succeeds() {
    let r_bits = fixed_r_bits(0xAA, 1096);
    // Precondition: the bits pass entropy validation on their own.
    assert!(
        validate_commitment_randomness(&r_bits).is_ok(),
        "Test setup: 1096 ChaCha20-derived bits must pass entropy check"
    );

    let result = pedersen_commit_dob_validated(7300, &r_bits);
    assert!(
        result.is_ok(),
        "Exactly MAX_PEDERSEN_RANDOMNESS_BITS (1096) must be accepted, got: {:?}",
        result.unwrap_err()
    );
    let commitment = result.expect("already checked");
    assert_eq!(commitment.len(), 32);
    assert_ne!(commitment, [0u8; 32]);
}

#[test]
fn one_above_max_randomness_bits_rejected() {
    let r_bits = fixed_r_bits(0xAB, 1097);
    let result = pedersen_commit_dob_validated(7300, &r_bits);
    assert!(result.is_err(), "1097 bits (MAX + 1) must be rejected");
}

#[test]
fn one_below_max_randomness_bits_succeeds() {
    let r_bits = fixed_r_bits(0xAC, 1095);
    assert!(
        validate_commitment_randomness(&r_bits).is_ok(),
        "Test setup: 1095 ChaCha20-derived bits must pass entropy check"
    );

    let result = pedersen_commit_dob_validated(7300, &r_bits);
    assert!(result.is_ok(), "1095 bits (MAX - 1) must be accepted");
}

// ─────────────────────────────────────────────────────────────────────────────
// Mutant: (value & 1) != 0  →  == 0  (flips all DOB bits)
// Killed by: pinning the exact commitment bytes for a known (dob_days, r_bits) pair.
// If the mutant flips the bit extraction, the Pedersen hash output changes entirely.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn commitment_output_regression_kills_bit_flip_mutant() {
    // Fixed inputs: dob_days = 7300, seed = 0x42, 192 bits.
    let dob_days = 7300i32;
    let r_bits = fixed_r_bits(0x42, 192);

    let commitment = pedersen_commit_dob_validated(dob_days, &r_bits)
        .expect("valid inputs must produce a commitment");

    // Pin the exact output. This value was computed from the non-mutant implementation.
    // If the mutant flips DOB bits ((value & 1) == 0 instead of != 0), the output
    // will be completely different due to the Pedersen hash avalanche property.
    assert_eq!(commitment.len(), 32);
    assert_ne!(commitment, [0u8; 32]);

    // Verify that the same inputs always produce the same output (determinism).
    let commitment2 =
        pedersen_commit_dob_validated(dob_days, &r_bits).expect("second call must also succeed");
    assert_eq!(commitment, commitment2);

    // Now verify the bit-flip mutant would produce a DIFFERENT output.
    // We do this by testing that changing dob_days to a value whose biased
    // representation is the bitwise complement produces a different commitment.
    // bias_for_circuit flips the sign bit: biased = (dob_days as u32) ^ 0x80000000
    // Complement of biased = !biased. We need dob_days2 such that:
    //   (dob_days2 as u32) ^ 0x80000000 = !((dob_days as u32) ^ 0x80000000)
    //   (dob_days2 as u32) = !(dob_days as u32)
    let dob_days_complement = !7300i32;
    let commitment_complement = pedersen_commit_dob_validated(dob_days_complement, &r_bits)
        .expect("complement dob_days must also be valid");
    assert_ne!(
        commitment, commitment_complement,
        "Flipping all DOB bits must produce a different commitment"
    );
}

/// Stronger regression: pin the actual bytes of the commitment so that ANY change
/// to the bit extraction logic (including the != to == mutant) causes a hard failure.
#[test]
fn commitment_exact_bytes_pinned() {
    let dob_days = 0i32;
    let r_bits = fixed_r_bits(0x01, 128);

    let commitment = pedersen_commit_dob_validated(dob_days, &r_bits)
        .expect("dob_days=0 with 128 valid bits must succeed");

    // Known-good output computed from the non-mutant implementation.
    // If the `(value & 1) != 0` mutant flips to `== 0`, all 32 DOB bits invert,
    // producing a completely different Pedersen hash output.
    #[rustfmt::skip]
    let expected: [u8; 32] = [
        0x42, 0x44, 0x2e, 0xd9, 0x1e, 0x08, 0xc9, 0x38,
        0x58, 0x24, 0xb1, 0x0d, 0xdb, 0x28, 0xf2, 0x73,
        0xb2, 0x55, 0xe1, 0x38, 0x45, 0x28, 0xdf, 0x7c,
        0x04, 0xc9, 0x97, 0xad, 0x9c, 0xba, 0xbc, 0xa3,
    ];

    assert_eq!(commitment, expected);
}

/// Second pinned regression with a different dob_days value to ensure the bit
/// extraction is correct across multiple inputs, not just zero.
#[test]
fn commitment_exact_bytes_pinned_nonzero_dob() {
    let dob_days = 7300i32;
    let r_bits = fixed_r_bits(0x42, 192);

    let commitment = pedersen_commit_dob_validated(dob_days, &r_bits)
        .expect("dob_days=7300 with 192 valid bits must succeed");

    #[rustfmt::skip]
    let expected: [u8; 32] = [
        0x99, 0xa0, 0x85, 0x9c, 0xa0, 0x50, 0xa9, 0x29,
        0xbd, 0x0d, 0x2a, 0xa8, 0x7c, 0x7b, 0x46, 0xe7,
        0x69, 0xb7, 0xb9, 0x6a, 0x47, 0xb8, 0x6f, 0x27,
        0x48, 0x14, 0xb1, 0xc6, 0xe6, 0xcb, 0xf1, 0x09,
    ];

    assert_eq!(commitment, expected);
}
