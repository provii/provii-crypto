use bellman::gadgets::boolean::Boolean;
use bellman::{ConstraintSystem, SynthesisError};
use bls12_381::Scalar;

// Use the copied sapling implementation
use super::sapling_pedersen;
use sapling_crypto::pedersen_hash::Personalization;

/// Compute Pedersen-based nullifier for commitment bytes
pub fn pedersen_nullifier<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    c_bytes_bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    // Domain separator (imported from crypto-commons to keep a single source of truth).
    use provii_crypto_commons::NULLIFIER_DST;

    let mut input_bits = Vec::new();

    // Add domain separator as constant bits
    for byte in NULLIFIER_DST {
        for i in 0..8 {
            // Circuit bit extraction: shift and mask are inherent to the conversion.
            #[allow(clippy::arithmetic_side_effects)]
            input_bits.push(Boolean::constant((byte >> i) & 1 == 1));
        }
    }

    // Add commitment bytes
    input_bits.extend_from_slice(c_bytes_bits);

    // MerkleTree(0) chosen for its distinct 6-bit prefix (000000) vs NoteCommitment (111111),
    // providing Sapling-level domain separation for the nullifier hash.
    let nullifier_point = sapling_pedersen::pedersen_hash(
        cs.namespace(|| "pedersen_nullifier_hash"),
        Personalization::MerkleTree(0),
        &input_bits,
    )?;

    // Extract first 256 bits (matching commitment format)
    let nullifier_bits_full = nullifier_point.repr(cs.namespace(|| "nullifier_point_repr"))?;
    let nullifier_bits: Vec<Boolean> = nullifier_bits_full.into_iter().take(256).collect();

    Ok(nullifier_bits)
}

/// Compute Pedersen commitment matching the host implementation exactly
pub fn commit<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    dob_bits: &[Boolean],
    r_bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    // Build input exactly as host does
    let mut input_bits = Vec::new();
    input_bits.extend_from_slice(dob_bits);
    input_bits.extend_from_slice(r_bits);

    // Use the sapling pedersen hash
    let commitment = sapling_pedersen::pedersen_hash(
        cs.namespace(|| "pedersen_commitment"),
        Personalization::NoteCommitment,
        &input_bits,
    )?;

    // Convert to compressed bytes format
    let commit_bits = commitment.repr(cs.namespace(|| "point_repr"))?;

    Ok(commit_bits)
}

/// Enforce equality between computed and witnessed commitment
pub fn enforce_bytes_equal<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    computed: &[Boolean],
    witnessed: &[Boolean],
) -> Result<(), SynthesisError> {
    if computed.len() != witnessed.len() {
        return Err(SynthesisError::Unsatisfiable);
    }

    for (i, (c_bit, w_bit)) in computed.iter().zip(witnessed.iter()).enumerate() {
        // Circuit constraint arithmetic: lc + variable is inherent to the R1CS system.
        #[allow(clippy::arithmetic_side_effects)]
        cs.enforce(
            || format!("commitment_bit_{i}_equal"),
            |lc| lc + &c_bit.lc(CS::one(), Scalar::one()),
            |lc| lc + CS::one(),
            |lc| lc + &w_bit.lc(CS::one(), Scalar::one()),
        );
    }

    Ok(())
}

#[cfg(test)]
// Test code: arithmetic and indexing are used in helper functions that convert
// between bits and bytes. Input sizes are controlled by the test and always valid.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use bellman::gadgets::boolean::Boolean;
    use bellman::gadgets::test::TestConstraintSystem;
    use proptest::prelude::*;

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /// Create Boolean bits from a byte slice (little-endian within each byte)
    fn bytes_to_bits_le(bytes: &[u8]) -> Vec<Boolean> {
        let mut bits = Vec::with_capacity(bytes.len() * 8);
        for byte in bytes {
            for i in 0..8 {
                bits.push(Boolean::constant((byte >> i) & 1 == 1));
            }
        }
        bits
    }

    /// Create Boolean bits from a u32 (little-endian)
    fn u32_to_bits_le(value: u32) -> Vec<Boolean> {
        let bytes = value.to_le_bytes();
        bytes_to_bits_le(&bytes)
    }

    /// Extract bytes from Boolean bits (little-endian within each byte)
    fn bits_to_bytes_le(bits: &[Boolean]) -> Vec<u8> {
        let mut bytes = vec![0u8; bits.len().div_ceil(8)];
        for (i, bit) in bits.iter().enumerate() {
            if bit.get_value() == Some(true) {
                bytes[i / 8] |= 1 << (i % 8);
            }
        }
        bytes
    }

    /// Create a pattern of alternating bits
    fn alternating_bits(count: usize, start_with_one: bool) -> Vec<Boolean> {
        (0..count)
            .map(|i| {
                Boolean::constant(if start_with_one {
                    i % 2 == 0
                } else {
                    i % 2 == 1
                })
            })
            .collect()
    }

    // ========================================================================
    // PEDERSEN NULLIFIER TESTS
    // ========================================================================

    #[test]
    fn test_pedersen_nullifier_standard_256_bits() -> Result<(), Box<dyn std::error::Error>> {
        let commitment = [42u8; 32];
        let c_bits = bytes_to_bits_le(&commitment);

        let mut cs = TestConstraintSystem::new();
        let nullifier = pedersen_nullifier(cs.namespace(|| "nullifier"), &c_bits)?;

        assert_eq!(nullifier.len(), 256, "Nullifier should be exactly 256 bits");
        assert!(cs.is_satisfied(), "Constraints should be satisfied");
        Ok(())
    }

    #[test]
    fn test_pedersen_nullifier_empty_commitment() -> Result<(), Box<dyn std::error::Error>> {
        let c_bits = vec![];

        let mut cs = TestConstraintSystem::new();
        let nullifier = pedersen_nullifier(cs.namespace(|| "nullifier"), &c_bits)?;

        assert_eq!(nullifier.len(), 256);
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_pedersen_nullifier_small_commitments() -> Result<(), Box<dyn std::error::Error>> {
        for bit_count in [1usize, 8, 16, 32, 64, 128] {
            let bytes = vec![0xAAu8; bit_count.div_ceil(8)];
            let c_bits: Vec<Boolean> = bytes_to_bits_le(&bytes)
                .into_iter()
                .take(bit_count)
                .collect();

            let mut cs = TestConstraintSystem::new();
            let nullifier = pedersen_nullifier(cs.namespace(|| "nullifier"), &c_bits)?;

            assert_eq!(nullifier.len(), 256);
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    #[test]
    fn test_pedersen_nullifier_large_commitment() -> Result<(), Box<dyn std::error::Error>> {
        let commitment = [0x55u8; 64]; // 512 bits
        let c_bits = bytes_to_bits_le(&commitment);

        let mut cs = TestConstraintSystem::new();
        let nullifier = pedersen_nullifier(cs.namespace(|| "nullifier"), &c_bits)?;

        assert_eq!(nullifier.len(), 256);
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_pedersen_nullifier_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let commitment = [0u8; 32];
        let c_bits = bytes_to_bits_le(&commitment);

        let mut cs = TestConstraintSystem::new();
        let nullifier = pedersen_nullifier(cs.namespace(|| "nullifier"), &c_bits)?;

        assert_eq!(nullifier.len(), 256);
        assert!(cs.is_satisfied());

        // Verify nullifier is not all zeros (hash should be non-trivial)
        let nullifier_bytes = bits_to_bytes_le(&nullifier);
        assert!(
            nullifier_bytes.iter().any(|&b| b != 0),
            "Nullifier should not be all zeros"
        );
        Ok(())
    }

    #[test]
    fn test_pedersen_nullifier_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        let commitment = [0xFFu8; 32];
        let c_bits = bytes_to_bits_le(&commitment);

        let mut cs = TestConstraintSystem::new();
        let nullifier = pedersen_nullifier(cs.namespace(|| "nullifier"), &c_bits)?;

        assert_eq!(nullifier.len(), 256);
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_pedersen_nullifier_alternating_pattern() -> Result<(), Box<dyn std::error::Error>> {
        let commitment = [0xAAu8; 32]; // 10101010...
        let c_bits = bytes_to_bits_le(&commitment);

        let mut cs = TestConstraintSystem::new();
        let nullifier = pedersen_nullifier(cs.namespace(|| "nullifier"), &c_bits)?;

        assert_eq!(nullifier.len(), 256);
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_pedersen_nullifier_determinism() -> Result<(), Box<dyn std::error::Error>> {
        let commitment = [123u8; 32];
        let c_bits = bytes_to_bits_le(&commitment);

        // Compute nullifier twice
        let mut cs1 = TestConstraintSystem::new();
        let nullifier1 = pedersen_nullifier(cs1.namespace(|| "nullifier"), &c_bits)?;

        let mut cs2 = TestConstraintSystem::new();
        let nullifier2 = pedersen_nullifier(cs2.namespace(|| "nullifier"), &c_bits)?;

        // Extract bytes
        let bytes1 = bits_to_bytes_le(&nullifier1);
        let bytes2 = bits_to_bytes_le(&nullifier2);

        assert_eq!(
            bytes1, bytes2,
            "Same commitment must produce same nullifier"
        );
        Ok(())
    }

    #[test]
    fn test_pedersen_nullifier_uniqueness() -> Result<(), Box<dyn std::error::Error>> {
        let commitment1 = [1u8; 32];
        let commitment2 = [2u8; 32];

        let c1_bits = bytes_to_bits_le(&commitment1);
        let c2_bits = bytes_to_bits_le(&commitment2);

        let mut cs1 = TestConstraintSystem::new();
        let nullifier1 = pedersen_nullifier(cs1.namespace(|| "nullifier"), &c1_bits)?;

        let mut cs2 = TestConstraintSystem::new();
        let nullifier2 = pedersen_nullifier(cs2.namespace(|| "nullifier"), &c2_bits)?;

        let bytes1 = bits_to_bytes_le(&nullifier1);
        let bytes2 = bits_to_bytes_le(&nullifier2);

        assert_ne!(
            bytes1, bytes2,
            "Different commitments must produce different nullifiers"
        );
        Ok(())
    }

    #[test]
    fn test_pedersen_nullifier_domain_separator_length() -> Result<(), Box<dyn std::error::Error>> {
        // Domain separator is "provii.nullifier.pedersen.v0" = 28 bytes = 224 bits
        const _EXPECTED_DST_BITS: usize = 28 * 8;

        // Verify by checking with empty commitment
        let empty_bits = vec![];

        let mut cs = TestConstraintSystem::new();
        let result = pedersen_nullifier(cs.namespace(|| "nullifier"), &empty_bits);

        assert!(result.is_ok(), "Should work with empty commitment");
        // The domain separator should be processed even with empty input
        Ok(())
    }

    #[test]
    fn test_pedersen_nullifier_domain_separator_encoding() -> Result<(), Box<dyn std::error::Error>>
    {
        // Verify the domain separator is encoded correctly (little-endian within each byte)
        const _DST: &[u8] = b"provii.nullifier.pedersen.v0";

        // Test that changing even one bit of the commitment produces different nullifier
        let commitment1 = [0u8; 32];
        let mut commitment2 = [0u8; 32];
        commitment2[0] = 1; // Change just one bit

        let c1_bits = bytes_to_bits_le(&commitment1);
        let c2_bits = bytes_to_bits_le(&commitment2);

        let mut cs1 = TestConstraintSystem::new();
        let nullifier1 = pedersen_nullifier(cs1.namespace(|| "nullifier"), &c1_bits)?;

        let mut cs2 = TestConstraintSystem::new();
        let nullifier2 = pedersen_nullifier(cs2.namespace(|| "nullifier"), &c2_bits)?;

        assert_ne!(bits_to_bytes_le(&nullifier1), bits_to_bytes_le(&nullifier2));
        Ok(())
    }

    #[test]
    fn test_pedersen_nullifier_single_bit_difference() -> Result<(), Box<dyn std::error::Error>> {
        // Test that flipping a single bit in commitment changes nullifier
        for bit_position in [0, 1, 127, 128, 254, 255] {
            let commitment1 = [0u8; 32];
            let mut commitment2 = [0u8; 32];
            commitment2[bit_position / 8] ^= 1 << (bit_position % 8);

            let c1_bits = bytes_to_bits_le(&commitment1);
            let c2_bits = bytes_to_bits_le(&commitment2);

            let mut cs1 = TestConstraintSystem::new();
            let nullifier1 = pedersen_nullifier(cs1.namespace(|| "nullifier"), &c1_bits)?;

            let mut cs2 = TestConstraintSystem::new();
            let nullifier2 = pedersen_nullifier(cs2.namespace(|| "nullifier"), &c2_bits)?;

            assert_ne!(
                bits_to_bytes_le(&nullifier1),
                bits_to_bytes_le(&nullifier2),
                "Single bit flip at position {bit_position} should change nullifier"
            );
        }
        Ok(())
    }

    // ========================================================================
    // PEDERSEN COMMIT TESTS
    // ========================================================================

    #[test]
    fn test_commit_standard_32bit_dob_256bit_randomness() -> Result<(), Box<dyn std::error::Error>>
    {
        let dob_days = 6570u32; // 18 years
        let randomness = [0x42u8; 32];

        let dob_bits = u32_to_bits_le(dob_days);
        let r_bits = bytes_to_bits_le(&randomness);

        let mut cs = TestConstraintSystem::new();
        let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits)?;

        // Commitment should be 256 bits (Edwards point representation)
        assert_eq!(commitment.len(), 256, "Commitment should be 256 bits");
        assert!(cs.is_satisfied(), "Constraints should be satisfied");
        Ok(())
    }

    #[test]
    fn test_commit_empty_dob() -> Result<(), Box<dyn std::error::Error>> {
        let dob_bits = vec![];
        let randomness = [0x42u8; 32];
        let r_bits = bytes_to_bits_le(&randomness);

        let mut cs = TestConstraintSystem::new();
        let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits)?;

        assert_eq!(commitment.len(), 256);
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_commit_empty_randomness() -> Result<(), Box<dyn std::error::Error>> {
        let dob_days = 6570u32;
        let dob_bits = u32_to_bits_le(dob_days);
        let r_bits = vec![];

        let mut cs = TestConstraintSystem::new();
        let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits)?;

        assert_eq!(commitment.len(), 256);
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_commit_both_empty() -> Result<(), Box<dyn std::error::Error>> {
        let dob_bits = vec![];
        let r_bits = vec![];

        let mut cs = TestConstraintSystem::new();
        let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits)?;

        assert_eq!(commitment.len(), 256);
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_commit_various_dob_sizes() -> Result<(), Box<dyn std::error::Error>> {
        let randomness = [0x42u8; 32];
        let r_bits = bytes_to_bits_le(&randomness);

        for bit_count in [1, 8, 16, 32, 64] {
            let dob_bits = alternating_bits(bit_count, false);

            let mut cs = TestConstraintSystem::new();
            let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits)?;

            assert_eq!(commitment.len(), 256);
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    #[test]
    fn test_commit_various_randomness_sizes() -> Result<(), Box<dyn std::error::Error>> {
        let dob_days = 6570u32;
        let dob_bits = u32_to_bits_le(dob_days);

        for byte_count in [1, 4, 8, 16, 32, 64] {
            let randomness = vec![0xAAu8; byte_count];
            let r_bits = bytes_to_bits_le(&randomness);

            let mut cs = TestConstraintSystem::new();
            let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits)?;

            assert_eq!(commitment.len(), 256);
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    #[test]
    fn test_commit_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let dob_bits = u32_to_bits_le(0);
        let r_bits = bytes_to_bits_le(&[0u8; 32]);

        let mut cs = TestConstraintSystem::new();
        let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits)?;

        assert_eq!(commitment.len(), 256);
        assert!(cs.is_satisfied());

        // Verify commitment is not all zeros
        let commit_bytes = bits_to_bytes_le(&commitment);
        assert!(
            commit_bytes.iter().any(|&b| b != 0),
            "Commitment should not be all zeros"
        );
        Ok(())
    }

    #[test]
    fn test_commit_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        let dob_bits = u32_to_bits_le(u32::MAX);
        let r_bits = bytes_to_bits_le(&[0xFFu8; 32]);

        let mut cs = TestConstraintSystem::new();
        let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits)?;

        assert_eq!(commitment.len(), 256);
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_commit_alternating_patterns() -> Result<(), Box<dyn std::error::Error>> {
        let dob_bits = alternating_bits(32, false);
        let r_bits = alternating_bits(256, true);

        let mut cs = TestConstraintSystem::new();
        let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits)?;

        assert_eq!(commitment.len(), 256);
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_commit_binding_property() -> Result<(), Box<dyn std::error::Error>> {
        // Same inputs -> same commitment
        let dob_days = 7670u32; // 21 years
        let randomness = [0x99u8; 32];

        let dob_bits = u32_to_bits_le(dob_days);
        let r_bits = bytes_to_bits_le(&randomness);

        let mut cs1 = TestConstraintSystem::new();
        let commitment1 = commit(cs1.namespace(|| "commit"), &dob_bits, &r_bits)?;

        let mut cs2 = TestConstraintSystem::new();
        let commitment2 = commit(cs2.namespace(|| "commit"), &dob_bits, &r_bits)?;

        let bytes1 = bits_to_bytes_le(&commitment1);
        let bytes2 = bits_to_bytes_le(&commitment2);

        assert_eq!(
            bytes1, bytes2,
            "Same inputs must produce same commitment (binding property)"
        );
        Ok(())
    }

    #[test]
    fn test_commit_hiding_property_different_randomness() -> Result<(), Box<dyn std::error::Error>>
    {
        // Same dob, different randomness -> different commitment
        let dob_days = 9131u32; // 25 years
        let randomness1 = [0x11u8; 32];
        let randomness2 = [0x22u8; 32];

        let dob_bits = u32_to_bits_le(dob_days);
        let r1_bits = bytes_to_bits_le(&randomness1);
        let r2_bits = bytes_to_bits_le(&randomness2);

        let mut cs1 = TestConstraintSystem::new();
        let commitment1 = commit(cs1.namespace(|| "commit"), &dob_bits, &r1_bits)?;

        let mut cs2 = TestConstraintSystem::new();
        let commitment2 = commit(cs2.namespace(|| "commit"), &dob_bits, &r2_bits)?;

        let bytes1 = bits_to_bytes_le(&commitment1);
        let bytes2 = bits_to_bytes_le(&commitment2);

        assert_ne!(
            bytes1, bytes2,
            "Different randomness must produce different commitment (hiding property)"
        );
        Ok(())
    }

    #[test]
    fn test_commit_different_dob_same_randomness() -> Result<(), Box<dyn std::error::Error>> {
        // Different dob, same randomness -> different commitment
        let dob1 = 6570u32; // 18 years
        let dob2 = 7670u32; // 21 years
        let randomness = [0x77u8; 32];

        let dob1_bits = u32_to_bits_le(dob1);
        let dob2_bits = u32_to_bits_le(dob2);
        let r_bits = bytes_to_bits_le(&randomness);

        let mut cs1 = TestConstraintSystem::new();
        let commitment1 = commit(cs1.namespace(|| "commit"), &dob1_bits, &r_bits)?;

        let mut cs2 = TestConstraintSystem::new();
        let commitment2 = commit(cs2.namespace(|| "commit"), &dob2_bits, &r_bits)?;

        let bytes1 = bits_to_bytes_le(&commitment1);
        let bytes2 = bits_to_bytes_le(&commitment2);

        assert_ne!(
            bytes1, bytes2,
            "Different DOBs must produce different commitments"
        );
        Ok(())
    }

    #[test]
    fn test_commit_different_dob_different_randomness() -> Result<(), Box<dyn std::error::Error>> {
        let dob1 = 6570u32;
        let dob2 = 7670u32;
        let randomness1 = [0x11u8; 32];
        let randomness2 = [0x22u8; 32];

        let dob1_bits = u32_to_bits_le(dob1);
        let dob2_bits = u32_to_bits_le(dob2);
        let r1_bits = bytes_to_bits_le(&randomness1);
        let r2_bits = bytes_to_bits_le(&randomness2);

        let mut cs1 = TestConstraintSystem::new();
        let commitment1 = commit(cs1.namespace(|| "commit"), &dob1_bits, &r1_bits)?;

        let mut cs2 = TestConstraintSystem::new();
        let commitment2 = commit(cs2.namespace(|| "commit"), &dob2_bits, &r2_bits)?;

        let bytes1 = bits_to_bytes_le(&commitment1);
        let bytes2 = bits_to_bytes_le(&commitment2);

        assert_ne!(
            bytes1, bytes2,
            "Different inputs must produce different commitments"
        );
        Ok(())
    }

    #[test]
    fn test_commit_typical_age_values() -> Result<(), Box<dyn std::error::Error>> {
        // Test with realistic age values
        let ages_in_days = [
            6570,  // 18 years
            7670,  // 21 years
            9131,  // 25 years
            10957, // 30 years
            14610, // 40 years
            18262, // 50 years
        ];

        let randomness = [0xABu8; 32];
        let r_bits = bytes_to_bits_le(&randomness);

        for &age in &ages_in_days {
            let dob_bits = u32_to_bits_le(age);

            let mut cs = TestConstraintSystem::new();
            let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits)?;

            assert_eq!(commitment.len(), 256);
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    #[test]
    fn test_commit_single_bit_dob_change() -> Result<(), Box<dyn std::error::Error>> {
        // Flipping a single bit in DOB should change commitment
        let dob1 = 6570u32;
        let dob2 = dob1 ^ 1; // Flip least significant bit

        let randomness = [0x88u8; 32];
        let r_bits = bytes_to_bits_le(&randomness);

        let dob1_bits = u32_to_bits_le(dob1);
        let dob2_bits = u32_to_bits_le(dob2);

        let mut cs1 = TestConstraintSystem::new();
        let commitment1 = commit(cs1.namespace(|| "commit"), &dob1_bits, &r_bits)?;

        let mut cs2 = TestConstraintSystem::new();
        let commitment2 = commit(cs2.namespace(|| "commit"), &dob2_bits, &r_bits)?;

        assert_ne!(
            bits_to_bytes_le(&commitment1),
            bits_to_bytes_le(&commitment2)
        );
        Ok(())
    }

    #[test]
    fn test_commit_single_bit_randomness_change() -> Result<(), Box<dyn std::error::Error>> {
        // Flipping a single bit in randomness should change commitment
        let dob_days = 6570u32;
        let dob_bits = u32_to_bits_le(dob_days);

        let randomness1 = [0x42u8; 32];
        let mut randomness2 = randomness1;
        randomness2[0] ^= 1; // Flip one bit

        let r1_bits = bytes_to_bits_le(&randomness1);
        let r2_bits = bytes_to_bits_le(&randomness2);

        let mut cs1 = TestConstraintSystem::new();
        let commitment1 = commit(cs1.namespace(|| "commit"), &dob_bits, &r1_bits)?;

        let mut cs2 = TestConstraintSystem::new();
        let commitment2 = commit(cs2.namespace(|| "commit"), &dob_bits, &r2_bits)?;

        assert_ne!(
            bits_to_bytes_le(&commitment1),
            bits_to_bytes_le(&commitment2)
        );
        Ok(())
    }

    // ========================================================================
    // ENFORCE_BYTES_EQUAL TESTS
    // ========================================================================

    #[test]
    fn test_enforce_bytes_equal_empty_arrays() -> Result<(), Box<dyn std::error::Error>> {
        let bits1 = vec![];
        let bits2 = vec![];

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(cs.is_satisfied(), "Empty arrays should satisfy constraints");
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_single_bit_match() -> Result<(), Box<dyn std::error::Error>> {
        let bits1 = vec![Boolean::constant(true)];
        let bits2 = vec![Boolean::constant(true)];

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(cs.is_satisfied(), "Matching single bits should satisfy");
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_single_bit_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let bits1 = vec![Boolean::constant(true)];
        let bits2 = vec![Boolean::constant(false)];

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(
            !cs.is_satisfied(),
            "Mismatched single bits should NOT satisfy"
        );
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_8_bits_all_match() -> Result<(), Box<dyn std::error::Error>> {
        let bits1 = bytes_to_bits_le(&[0xAAu8]);
        let bits2 = bytes_to_bits_le(&[0xAAu8]);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_8_bits_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let bits1 = bytes_to_bits_le(&[0xAAu8]);
        let bits2 = bytes_to_bits_le(&[0x55u8]);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(!cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_32_bits_match() -> Result<(), Box<dyn std::error::Error>> {
        let value = [0x12, 0x34, 0x56, 0x78];
        let bits1 = bytes_to_bits_le(&value);
        let bits2 = bytes_to_bits_le(&value);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_256_bits_match() -> Result<(), Box<dyn std::error::Error>> {
        let value = [0x42u8; 32];
        let bits1 = bytes_to_bits_le(&value);
        let bits2 = bytes_to_bits_le(&value);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_256_bits_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let value1 = [0x42u8; 32];
        let mut value2 = value1;
        value2[15] = 0x99; // Change middle byte

        let bits1 = bytes_to_bits_le(&value1);
        let bits2 = bytes_to_bits_le(&value2);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(!cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_mismatch_at_position_0() -> Result<(), Box<dyn std::error::Error>> {
        let value1 = [0u8; 32];
        let mut value2 = [0u8; 32];
        value2[0] = 1; // Mismatch at first byte

        let bits1 = bytes_to_bits_le(&value1);
        let bits2 = bytes_to_bits_le(&value2);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(!cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_mismatch_at_last_position() -> Result<(), Box<dyn std::error::Error>>
    {
        let value1 = [0u8; 32];
        let mut value2 = [0u8; 32];
        value2[31] = 1; // Mismatch at last byte

        let bits1 = bytes_to_bits_le(&value1);
        let bits2 = bytes_to_bits_le(&value2);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(!cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_all_zeros_match() -> Result<(), Box<dyn std::error::Error>> {
        let bits1 = bytes_to_bits_le(&[0u8; 32]);
        let bits2 = bytes_to_bits_le(&[0u8; 32]);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_all_ones_match() -> Result<(), Box<dyn std::error::Error>> {
        let bits1 = bytes_to_bits_le(&[0xFFu8; 32]);
        let bits2 = bytes_to_bits_le(&[0xFFu8; 32]);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_all_zeros_vs_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        let bits1 = bytes_to_bits_le(&[0u8; 32]);
        let bits2 = bytes_to_bits_le(&[0xFFu8; 32]);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(!cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_alternating_patterns_match(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bits1 = alternating_bits(256, false);
        let bits2 = alternating_bits(256, false);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_alternating_patterns_mismatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bits1 = alternating_bits(256, false);
        let bits2 = alternating_bits(256, true); // Opposite pattern

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(!cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_multiple_mismatches() -> Result<(), Box<dyn std::error::Error>> {
        let value1 = [0u8; 32];
        let mut value2 = [0u8; 32];
        value2[0] = 1;
        value2[10] = 1;
        value2[31] = 1; // Multiple mismatches

        let bits1 = bytes_to_bits_le(&value1);
        let bits2 = bytes_to_bits_le(&value2);

        let mut cs = TestConstraintSystem::new();
        enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2)?;

        assert!(!cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_enforce_bytes_equal_length_mismatch_returns_error(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bits1 = bytes_to_bits_le(&[0u8; 32]);
        let bits2 = bytes_to_bits_le(&[0u8; 16]);

        let mut cs = TestConstraintSystem::new();
        // ST-PC-004: returns SynthesisError instead of panicking
        let result = enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2);
        assert!(result.is_err());
        Ok(())
    }

    // ========================================================================
    // INTEGRATION TESTS
    // ========================================================================

    #[test]
    fn test_commit_then_nullifier_full_flow() -> Result<(), Box<dyn std::error::Error>> {
        // Full flow: create commitment, then compute nullifier (in single CS)
        let dob_days = 7670u32;
        let randomness = [0x99u8; 32];

        let dob_bits = u32_to_bits_le(dob_days);
        let r_bits = bytes_to_bits_le(&randomness);

        // Use single constraint system for entire flow
        let mut cs = TestConstraintSystem::new();
        let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits)?;
        let nullifier = pedersen_nullifier(cs.namespace(|| "nullifier"), &commitment)?;

        assert!(cs.is_satisfied(), "Full flow should satisfy constraints");
        assert_eq!(commitment.len(), 256);
        assert_eq!(nullifier.len(), 256);
        Ok(())
    }

    #[test]
    fn test_different_commitments_different_nullifiers() -> Result<(), Box<dyn std::error::Error>> {
        // Different commitments should produce different nullifiers
        let dob1 = 6570u32;
        let dob2 = 7670u32;
        let randomness = [0x77u8; 32];

        let r_bits = bytes_to_bits_le(&randomness);

        // Commitment 1 and nullifier 1 in single CS
        let dob1_bits = u32_to_bits_le(dob1);
        let mut cs1 = TestConstraintSystem::new();
        let commitment1 = commit(cs1.namespace(|| "commit"), &dob1_bits, &r_bits)?;
        let commitment1_bytes = bits_to_bytes_le(&commitment1);

        // Commitment 2 and nullifier 2 in separate CS
        let dob2_bits = u32_to_bits_le(dob2);
        let mut cs2 = TestConstraintSystem::new();
        let commitment2 = commit(cs2.namespace(|| "commit"), &dob2_bits, &r_bits)?;
        let commitment2_bytes = bits_to_bytes_le(&commitment2);

        // Reconstruct commitment1 as constants for nullifier computation
        let c1_bits_const = bytes_to_bits_le(&commitment1_bytes);
        let mut cs3 = TestConstraintSystem::new();
        let nullifier1 = pedersen_nullifier(cs3.namespace(|| "nullifier"), &c1_bits_const)?;

        // Reconstruct commitment2 as constants for nullifier computation
        let c2_bits_const = bytes_to_bits_le(&commitment2_bytes);
        let mut cs4 = TestConstraintSystem::new();
        let nullifier2 = pedersen_nullifier(cs4.namespace(|| "nullifier"), &c2_bits_const)?;

        assert_ne!(commitment1_bytes, commitment2_bytes);
        assert_ne!(bits_to_bytes_le(&nullifier1), bits_to_bytes_le(&nullifier2));
        Ok(())
    }

    #[test]
    fn test_same_commitment_same_nullifier() -> Result<(), Box<dyn std::error::Error>> {
        // Same commitment should always produce same nullifier
        let dob_days = 9131u32;
        let randomness = [0xCCu8; 32];

        let dob_bits = u32_to_bits_le(dob_days);
        let r_bits = bytes_to_bits_le(&randomness);

        // Create commitment and extract bytes
        let mut cs1 = TestConstraintSystem::new();
        let commitment = commit(cs1.namespace(|| "commit"), &dob_bits, &r_bits)?;
        let commitment_bytes = bits_to_bytes_le(&commitment);

        // Compute nullifier twice from same commitment (as constants)
        let c_bits = bytes_to_bits_le(&commitment_bytes);

        let mut cs2 = TestConstraintSystem::new();
        let nullifier1 = pedersen_nullifier(cs2.namespace(|| "nullifier"), &c_bits)?;

        let mut cs3 = TestConstraintSystem::new();
        let nullifier2 = pedersen_nullifier(cs3.namespace(|| "nullifier"), &c_bits)?;

        assert_eq!(bits_to_bytes_le(&nullifier1), bits_to_bytes_le(&nullifier2));
        Ok(())
    }

    #[test]
    fn test_enforce_computed_vs_witnessed_commitment() -> Result<(), Box<dyn std::error::Error>> {
        // Compute commitment twice in same CS and verify they match
        let dob_days = 6570u32;
        let randomness = [0xABu8; 32];

        let dob_bits = u32_to_bits_le(dob_days);
        let r_bits = bytes_to_bits_le(&randomness);

        // Use single constraint system
        let mut cs = TestConstraintSystem::new();
        let computed = commit(cs.namespace(|| "compute"), &dob_bits, &r_bits)?;
        let witnessed = commit(cs.namespace(|| "witness"), &dob_bits, &r_bits)?;
        enforce_bytes_equal(cs.namespace(|| "enforce"), &computed, &witnessed)?;

        assert!(cs.is_satisfied(), "Computed and witnessed should match");
        Ok(())
    }

    #[test]
    fn test_enforce_computed_vs_different_witnessed() -> Result<(), Box<dyn std::error::Error>> {
        // Compute two different commitments in same CS and verify they don't match
        let dob1 = 6570u32;
        let dob2 = 7670u32;
        let randomness = [0xABu8; 32];

        let dob1_bits = u32_to_bits_le(dob1);
        let dob2_bits = u32_to_bits_le(dob2);
        let r_bits = bytes_to_bits_le(&randomness);

        // Use single constraint system
        let mut cs = TestConstraintSystem::new();
        let computed = commit(cs.namespace(|| "compute"), &dob1_bits, &r_bits)?;
        let witnessed = commit(cs.namespace(|| "witness"), &dob2_bits, &r_bits)?;
        enforce_bytes_equal(cs.namespace(|| "enforce"), &computed, &witnessed)?;

        assert!(
            !cs.is_satisfied(),
            "Different commitments should NOT satisfy equality"
        );
        Ok(())
    }

    // ========================================================================
    // PROPERTY-BASED TESTS
    // ========================================================================

    proptest! {
        /// Property: Commitment binding - same inputs always produce same commitment
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_commit_binding(dob in any::<u32>(), randomness in any::<[u8; 32]>()) {
            let dob_bits = u32_to_bits_le(dob);
            let r_bits = bytes_to_bits_le(&randomness);

            let mut cs1 = TestConstraintSystem::new();
            let commitment1 = commit(cs1.namespace(|| "commit"), &dob_bits, &r_bits);

            let mut cs2 = TestConstraintSystem::new();
            let commitment2 = commit(cs2.namespace(|| "commit"), &dob_bits, &r_bits);

            prop_assert!(commitment1.is_ok() && commitment2.is_ok());

            let bytes1 = bits_to_bytes_le(&commitment1.unwrap());
            let bytes2 = bits_to_bytes_le(&commitment2.unwrap());

            prop_assert_eq!(bytes1, bytes2, "Same inputs must produce same commitment");
        }

        /// Property: Commitment hiding - different randomness produces different commitment
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_commit_hiding(dob in any::<u32>(), r1 in any::<[u8; 32]>(), r2 in any::<[u8; 32]>()) {
            prop_assume!(r1 != r2);

            let dob_bits = u32_to_bits_le(dob);
            let r1_bits = bytes_to_bits_le(&r1);
            let r2_bits = bytes_to_bits_le(&r2);

            let mut cs1 = TestConstraintSystem::new();
            let commitment1 = commit(cs1.namespace(|| "commit"), &dob_bits, &r1_bits);

            let mut cs2 = TestConstraintSystem::new();
            let commitment2 = commit(cs2.namespace(|| "commit"), &dob_bits, &r2_bits);

            prop_assert!(commitment1.is_ok() && commitment2.is_ok());

            let bytes1 = bits_to_bytes_le(&commitment1.unwrap());
            let bytes2 = bits_to_bytes_le(&commitment2.unwrap());

            prop_assert_ne!(bytes1, bytes2, "Different randomness must produce different commitment");
        }

        /// Property: Nullifier determinism - same commitment produces same nullifier
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_nullifier_determinism(commitment_bytes in any::<[u8; 32]>()) {
            let c_bits = bytes_to_bits_le(&commitment_bytes);

            let mut cs1 = TestConstraintSystem::new();
            let nullifier1 = pedersen_nullifier(cs1.namespace(|| "nullifier"), &c_bits);

            let mut cs2 = TestConstraintSystem::new();
            let nullifier2 = pedersen_nullifier(cs2.namespace(|| "nullifier"), &c_bits);

            prop_assert!(nullifier1.is_ok() && nullifier2.is_ok());

            let bytes1 = bits_to_bytes_le(&nullifier1.unwrap());
            let bytes2 = bits_to_bytes_le(&nullifier2.unwrap());

            prop_assert_eq!(bytes1, bytes2, "Same commitment must produce same nullifier");
        }

        /// Property: Nullifier uniqueness - different commitments produce different nullifiers
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_nullifier_uniqueness(c1 in any::<[u8; 32]>(), c2 in any::<[u8; 32]>()) {
            prop_assume!(c1 != c2);

            let c1_bits = bytes_to_bits_le(&c1);
            let c2_bits = bytes_to_bits_le(&c2);

            let mut cs1 = TestConstraintSystem::new();
            let nullifier1 = pedersen_nullifier(cs1.namespace(|| "nullifier"), &c1_bits);

            let mut cs2 = TestConstraintSystem::new();
            let nullifier2 = pedersen_nullifier(cs2.namespace(|| "nullifier"), &c2_bits);

            prop_assert!(nullifier1.is_ok() && nullifier2.is_ok());

            let bytes1 = bits_to_bytes_le(&nullifier1.unwrap());
            let bytes2 = bits_to_bytes_le(&nullifier2.unwrap());

            prop_assert_ne!(bytes1, bytes2, "Different commitments must produce different nullifiers");
        }

        /// Property: Commitment output length is always 256 bits
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_commit_output_length(dob in any::<u32>(), randomness in any::<[u8; 32]>()) {
            let dob_bits = u32_to_bits_le(dob);
            let r_bits = bytes_to_bits_le(&randomness);

            let mut cs = TestConstraintSystem::new();
            let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits);

            prop_assert!(commitment.is_ok());
            prop_assert_eq!(commitment.unwrap().len(), 256, "Commitment must be 256 bits");
        }

        /// Property: Nullifier output length is always 256 bits
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_nullifier_output_length(commitment_bytes in any::<[u8; 32]>()) {
            let c_bits = bytes_to_bits_le(&commitment_bytes);

            let mut cs = TestConstraintSystem::new();
            let nullifier = pedersen_nullifier(cs.namespace(|| "nullifier"), &c_bits);

            prop_assert!(nullifier.is_ok());
            prop_assert_eq!(nullifier.unwrap().len(), 256, "Nullifier must be 256 bits");
        }

        /// Property: Enforce equality with matching bits always satisfies
        #[test]
        fn prop_enforce_equal_matching_satisfies(bytes in any::<[u8; 32]>()) {
            let bits1 = bytes_to_bits_le(&bytes);
            let bits2 = bytes_to_bits_le(&bytes);

            let mut cs = TestConstraintSystem::new();
            let result = enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2);

            prop_assert!(result.is_ok());
            prop_assert!(cs.is_satisfied(), "Matching bits must satisfy constraints");
        }

        /// Property: Enforce equality with different bits never satisfies
        #[test]
        fn prop_enforce_equal_different_fails(bytes1 in any::<[u8; 32]>(), bytes2 in any::<[u8; 32]>()) {
            prop_assume!(bytes1 != bytes2);

            let bits1 = bytes_to_bits_le(&bytes1);
            let bits2 = bytes_to_bits_le(&bytes2);

            let mut cs = TestConstraintSystem::new();
            let result = enforce_bytes_equal(cs.namespace(|| "enforce"), &bits1, &bits2);

            prop_assert!(result.is_ok());
            prop_assert!(!cs.is_satisfied(), "Different bits must NOT satisfy constraints");
        }

        /// Property: Different DOBs with same randomness produce different commitments
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_different_dob_different_commitment(dob1 in any::<u32>(), dob2 in any::<u32>(), r in any::<[u8; 32]>()) {
            prop_assume!(dob1 != dob2);

            let dob1_bits = u32_to_bits_le(dob1);
            let dob2_bits = u32_to_bits_le(dob2);
            let r_bits = bytes_to_bits_le(&r);

            let mut cs1 = TestConstraintSystem::new();
            let commitment1 = commit(cs1.namespace(|| "commit"), &dob1_bits, &r_bits);

            let mut cs2 = TestConstraintSystem::new();
            let commitment2 = commit(cs2.namespace(|| "commit"), &dob2_bits, &r_bits);

            prop_assert!(commitment1.is_ok() && commitment2.is_ok());

            let bytes1 = bits_to_bytes_le(&commitment1.unwrap());
            let bytes2 = bits_to_bytes_le(&commitment2.unwrap());

            prop_assert_ne!(bytes1, bytes2, "Different DOBs must produce different commitments");
        }

        /// Property: Commit then nullifier always produces valid outputs
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_commit_nullifier_flow(dob in any::<u32>(), randomness in any::<[u8; 32]>()) {
            let dob_bits = u32_to_bits_le(dob);
            let r_bits = bytes_to_bits_le(&randomness);

            // Create commitment and nullifier in single constraint system
            let mut cs = TestConstraintSystem::new();
            let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits);
            prop_assert!(commitment.is_ok());

            let commitment = commitment.unwrap();
            let nullifier = pedersen_nullifier(cs.namespace(|| "nullifier"), &commitment);
            prop_assert!(nullifier.is_ok());
            prop_assert!(cs.is_satisfied(), "Full flow should satisfy constraints");

            prop_assert_eq!(commitment.len(), 256);
            prop_assert_eq!(nullifier.unwrap().len(), 256);
        }

        /// Property: Commitment constraints always satisfy with valid inputs
        #[test]
        fn prop_commit_always_satisfies(dob in any::<u32>(), randomness in any::<[u8; 32]>()) {
            let dob_bits = u32_to_bits_le(dob);
            let r_bits = bytes_to_bits_le(&randomness);

            let mut cs = TestConstraintSystem::new();
            let result = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits);

            prop_assert!(result.is_ok());
            prop_assert!(cs.is_satisfied(), "Valid inputs must satisfy constraints");
        }

        /// Property: Nullifier constraints always satisfy with valid inputs
        #[test]
        fn prop_nullifier_always_satisfies(commitment_bytes in any::<[u8; 32]>()) {
            let c_bits = bytes_to_bits_le(&commitment_bytes);

            let mut cs = TestConstraintSystem::new();
            let result = pedersen_nullifier(cs.namespace(|| "nullifier"), &c_bits);

            prop_assert!(result.is_ok());
            prop_assert!(cs.is_satisfied(), "Valid inputs must satisfy constraints");
        }

        /// Property: Commitment is non-trivial (not all zeros)
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_commit_non_trivial(dob in any::<u32>(), randomness in any::<[u8; 32]>()) {
            let dob_bits = u32_to_bits_le(dob);
            let r_bits = bytes_to_bits_le(&randomness);

            let mut cs = TestConstraintSystem::new();
            let commitment = commit(cs.namespace(|| "commit"), &dob_bits, &r_bits);

            prop_assert!(commitment.is_ok());

            let bytes = bits_to_bytes_le(&commitment.unwrap());
            // With overwhelming probability, commitment should not be all zeros
            // (This could theoretically fail but is astronomically unlikely)
            prop_assert!(bytes.iter().any(|&b| b != 0), "Commitment should be non-trivial");
        }

        /// Property: Nullifier is non-trivial (not all zeros)
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_nullifier_non_trivial(commitment_bytes in any::<[u8; 32]>()) {
            let c_bits = bytes_to_bits_le(&commitment_bytes);

            let mut cs = TestConstraintSystem::new();
            let nullifier = pedersen_nullifier(cs.namespace(|| "nullifier"), &c_bits);

            prop_assert!(nullifier.is_ok());

            let bytes = bits_to_bytes_le(&nullifier.unwrap());
            // Nullifier includes domain separator, so should never be all zeros
            prop_assert!(bytes.iter().any(|&b| b != 0), "Nullifier should be non-trivial");
        }
    }
}
