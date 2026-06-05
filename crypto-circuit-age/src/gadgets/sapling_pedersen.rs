// Circuit constraint code ported from Zcash sapling-crypto.
// Arithmetic on Scalar and generator table indexing are inherent
// to the ZK constraint system.
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

//! Gadget for Zcash's Pedersen hash.

use super::sapling_ecc::{EdwardsPoint, MontgomeryPoint};
pub use sapling_crypto::pedersen_hash::Personalization;

use bellman::gadgets::boolean::Boolean;
use bellman::gadgets::lookup::*;
use bellman::{ConstraintSystem, SynthesisError};

use super::sapling_constants::PEDERSEN_CIRCUIT_GENERATORS;

fn get_constant_bools(person: &Personalization) -> Vec<Boolean> {
    person
        .get_bits()
        .into_iter()
        .map(Boolean::constant)
        .collect()
}

pub fn pedersen_hash<CS>(
    mut cs: CS,
    personalization: Personalization,
    bits: &[Boolean],
) -> Result<EdwardsPoint, SynthesisError>
where
    CS: ConstraintSystem<bls12_381::Scalar>,
{
    let personalization = get_constant_bools(&personalization);
    if personalization.len() != 6 {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut edwards_result = None;
    let mut bits = personalization.iter().chain(bits.iter()).peekable();
    let mut segment_generators = PEDERSEN_CIRCUIT_GENERATORS.iter();
    let boolean_false = Boolean::constant(false);

    let mut segment_i = 0;
    while bits.peek().is_some() {
        let mut segment_result = None;
        let mut segment_windows = &segment_generators
            .next()
            .ok_or(SynthesisError::Unsatisfiable)?[..];

        let mut window_i = 0;
        while let Some(a) = bits.next() {
            let b = bits.next().unwrap_or(&boolean_false);
            let c = bits.next().unwrap_or(&boolean_false);

            let tmp = lookup3_xy_with_conditional_negation(
                cs.namespace(|| format!("segment {segment_i}, window {window_i}")),
                &[a.clone(), b.clone(), c.clone()],
                &segment_windows[0],
            )?;

            let tmp = MontgomeryPoint::interpret_unchecked(tmp.0, tmp.1);

            match segment_result {
                None => {
                    segment_result = Some(tmp);
                }
                Some(ref mut segment_result) => {
                    *segment_result = tmp.add(
                        cs.namespace(|| {
                            format!("addition of segment {segment_i}, window {window_i}")
                        }),
                        segment_result,
                    )?;
                }
            }

            segment_windows = &segment_windows[1..];

            if segment_windows.is_empty() {
                break;
            }

            window_i += 1;
        }

        let segment_result = segment_result.ok_or(SynthesisError::Unsatisfiable)?;

        // Convert the segment into twisted Edwards form.
        let segment_result = segment_result.into_edwards(
            cs.namespace(|| format!("conversion of segment {segment_i} into edwards")),
        )?;

        match edwards_result {
            Some(ref mut edwards_result) => {
                *edwards_result = segment_result.add(
                    cs.namespace(|| format!("addition of segment {segment_i} to accumulator")),
                    edwards_result,
                )?;
            }
            None => {
                edwards_result = Some(segment_result);
            }
        }

        segment_i += 1;
    }

    edwards_result.ok_or(SynthesisError::Unsatisfiable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellman::gadgets::test::TestConstraintSystem;

    // ========================================================================
    // PERSONALIZATION TESTS (3 tests)
    // ========================================================================

    #[test]
    fn test_personalization_note_commitment() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true); 128];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_personalization_merkle_tree_0() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(false); 128];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::MerkleTree(0),
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_personalization_merkle_tree_31() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true); 64];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::MerkleTree(31),
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    // ========================================================================
    // INPUT SIZES - SEGMENT BOUNDARIES (10 tests)
    // ========================================================================
    // Personalization is 6 bits, segments have 21 windows (3 bits each = 63 bits)
    // First segment can take 57 input bits (6 + 57 = 63)

    #[test]
    fn test_input_size_0_bits() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "0 bits should work (only personalization)");
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_input_size_1_bit() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true)];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_input_size_2_bits() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(false); 2];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_input_size_3_bits() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true); 3];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_input_size_6_bits() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(false); 6];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_input_size_57_bits_segment_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true); 57];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(
            result.is_ok(),
            "57 bits + 6 personalization = 63 bits = exactly 21 windows"
        );
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_input_size_58_bits_crosses_segment() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(false); 58];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "58 bits should cross into second segment");
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_input_size_120_bits_two_segments() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true); 120];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "120 bits should span 2 segments");
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_input_size_189_bits_three_segments() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(false); 189];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "189 bits should span 3 segments");
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_input_size_252_bits_four_segments() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true); 252];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "252 bits should span 4 segments");
        assert!(cs.is_satisfied());
        Ok(())
    }

    // ========================================================================
    // EDGE CASES (8 tests)
    // ========================================================================

    #[test]
    fn test_all_zeros_input() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(false); 256];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_all_ones_input() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true); 256];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_alternating_pattern() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = (0..128)
            .map(|i| Boolean::constant(i % 2 == 0))
            .collect::<Vec<_>>();
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_single_bit_zero() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(false)];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_single_bit_one() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true)];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_maximum_safe_input() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        // Use a large input that's still within safe bounds
        let bits = vec![Boolean::constant(true); 500];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "Should handle large inputs");
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_segment_window_exhaustion() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        // Exactly fill one segment (57 bits input + 6 personalization = 63 = 21 windows)
        let bits = vec![Boolean::constant(false); 57];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "Should handle exact segment boundary");
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_first_window_in_segment() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        // Use just 3 bits to test the first window case (segment_result = None path)
        let bits = vec![
            Boolean::constant(true),
            Boolean::constant(false),
            Boolean::constant(true),
        ];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    // ========================================================================
    // BRANCH COVERAGE (7 tests)
    // ========================================================================
    // Testing all 8 possible (a,b,c) combinations for lookup3_xy

    #[test]
    fn test_window_bits_000() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(false),
        ];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_window_bits_100() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![
            Boolean::constant(true),
            Boolean::constant(false),
            Boolean::constant(false),
        ];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_window_bits_010() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![
            Boolean::constant(false),
            Boolean::constant(true),
            Boolean::constant(false),
        ];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_window_bits_001() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![
            Boolean::constant(false),
            Boolean::constant(false),
            Boolean::constant(true),
        ];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_window_bits_111() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![
            Boolean::constant(true),
            Boolean::constant(true),
            Boolean::constant(true),
        ];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_incomplete_window_only_a() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        // Only 1 bit provided, b and c should default to false
        let bits = vec![Boolean::constant(true)];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "Should handle incomplete window (only a)");
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_incomplete_window_a_and_b() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        // Only 2 bits provided, c should default to false
        let bits = vec![Boolean::constant(true), Boolean::constant(false)];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "Should handle incomplete window (a and b)");
        assert!(cs.is_satisfied());
        Ok(())
    }

    // ========================================================================
    // INTEGRATION TESTS (7 tests)
    // ========================================================================

    #[test]
    fn test_montgomery_to_edwards_conversion() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true); 64];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "Montgomery→Edwards conversion should work");
        assert!(cs.is_satisfied());
        // Result should be an EdwardsPoint
        let _point = result?;
        // Just verify we got a point (any additional checks would require accessing internals)
        Ok(())
    }

    #[test]
    fn test_first_segment_path() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        // Use small input to stay in first segment (edwards_result = None path)
        let bits = vec![Boolean::constant(false); 10];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "First segment path should work");
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_subsequent_segment_path() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        // Use large enough input to cross into second segment (edwards_result = Some path)
        let bits = vec![Boolean::constant(true); 100];
        let result = pedersen_hash(
            cs.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        );
        assert!(result.is_ok(), "Subsequent segment path should work");
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_determinism_same_input_same_output() -> Result<(), Box<dyn std::error::Error>> {
        let bits = vec![Boolean::constant(true); 128];

        let mut cs1 = TestConstraintSystem::new();
        let result1 = pedersen_hash(
            cs1.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        )?;

        let mut cs2 = TestConstraintSystem::new();
        let result2 = pedersen_hash(
            cs2.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        )?;

        // Both should produce the same point (verify via x coordinate)
        let x1 = result1.get_u().get_value();
        let x2 = result2.get_u().get_value();
        assert_eq!(x1, x2, "Same input should produce same output");
        Ok(())
    }

    #[test]
    fn test_uniqueness_different_input_different_output() -> Result<(), Box<dyn std::error::Error>>
    {
        let bits1 = vec![Boolean::constant(false); 128];
        let bits2 = vec![Boolean::constant(true); 128];

        let mut cs1 = TestConstraintSystem::new();
        let result1 = pedersen_hash(
            cs1.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits1,
        )?;

        let mut cs2 = TestConstraintSystem::new();
        let result2 = pedersen_hash(
            cs2.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits2,
        )?;

        // Different inputs should produce different points
        let x1 = result1.get_u().get_value();
        let x2 = result2.get_u().get_value();
        assert_ne!(x1, x2, "Different inputs should produce different outputs");
        Ok(())
    }

    #[test]
    fn test_different_personalization_different_output() -> Result<(), Box<dyn std::error::Error>> {
        let bits = vec![Boolean::constant(true); 64];

        let mut cs1 = TestConstraintSystem::new();
        let result1 = pedersen_hash(
            cs1.namespace(|| "pedersen"),
            Personalization::NoteCommitment,
            &bits,
        )?;

        let mut cs2 = TestConstraintSystem::new();
        let result2 = pedersen_hash(
            cs2.namespace(|| "pedersen"),
            Personalization::MerkleTree(0),
            &bits,
        )?;

        // Different personalizations should produce different outputs
        let x1 = result1.get_u().get_value();
        let x2 = result2.get_u().get_value();
        assert_ne!(
            x1, x2,
            "Different personalizations should produce different outputs"
        );
        Ok(())
    }

    #[test]
    fn test_get_constant_bools_length() -> Result<(), Box<dyn std::error::Error>> {
        let person = Personalization::NoteCommitment;
        let bools = get_constant_bools(&person);
        assert_eq!(bools.len(), 6, "Personalization should be 6 bits");
        Ok(())
    }
}
