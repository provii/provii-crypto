// Circuit constraint code: indexing into fixed-size Blake2s state arrays
// is inherent to the ZK constraint system.
#![allow(clippy::indexing_slicing)]

use bellman::gadgets::boolean::Boolean;
use bellman::{ConstraintSystem, SynthesisError};
use bls12_381::Scalar;

/// Personalization bytes shared between the in-circuit and off-circuit Blake2s.
///
/// Both paths MUST use identical personalization. The in-circuit gadget passes
/// these bytes to `bellman::gadgets::blake2s::blake2s`; the off-circuit code in
/// `crypto-commit` and `crypto-protocol` uses plain Blake2s (no personalization),
/// which is equivalent to 8 zero bytes.
pub const BLAKE2S_NO_PERSONALIZATION: [u8; 8] = [0u8; 8];

pub fn blake2s_256<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    bellman::gadgets::blake2s::blake2s(
        cs.namespace(|| "blake2s"),
        bits,
        &BLAKE2S_NO_PERSONALIZATION,
    )
}

/// Blake2s with custom personalization
pub fn blake2s_with_personalization<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    bits: &[Boolean],
    personalization: &[u8; 8],
) -> Result<Vec<Boolean>, SynthesisError> {
    bellman::gadgets::blake2s::blake2s(
        cs.namespace(|| "blake2s_personalized"),
        bits,
        personalization,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellman::gadgets::test::TestConstraintSystem;

    // ========================================================================
    // BLAKE2S_256 TESTS (no personalization)
    // ========================================================================

    #[test]
    fn test_blake2s_256_empty() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![];
        let result = blake2s_256(cs.namespace(|| "blake2s"), &bits);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        let hash = result?;
        assert_eq!(hash.len(), 256, "Blake2s output should be 256 bits");
        Ok(())
    }

    #[test]
    fn test_blake2s_256_single_byte() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![
            Boolean::constant(true),
            Boolean::constant(false),
            Boolean::constant(true),
            Boolean::constant(false),
            Boolean::constant(true),
            Boolean::constant(false),
            Boolean::constant(true),
            Boolean::constant(false),
        ]; // 0xAA
        let result = blake2s_256(cs.namespace(|| "blake2s"), &bits);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        let hash = result?;
        assert_eq!(hash.len(), 256);
        Ok(())
    }

    #[test]
    fn test_blake2s_256_multiple_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = (0..32)
            .flat_map(|i| {
                vec![
                    Boolean::constant(i % 2 == 0),
                    Boolean::constant(i % 2 == 1),
                    Boolean::constant(i % 3 == 0),
                    Boolean::constant(i % 3 == 1),
                    Boolean::constant(i % 3 == 2),
                    Boolean::constant(i % 5 == 0),
                    Boolean::constant(i % 5 == 1),
                    Boolean::constant(i % 5 == 2),
                ]
            })
            .collect::<Vec<_>>();
        let result = blake2s_256(cs.namespace(|| "blake2s"), &bits);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        let hash = result?;
        assert_eq!(hash.len(), 256);
        Ok(())
    }

    #[test]
    fn test_blake2s_256_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(false); 256];
        let result = blake2s_256(cs.namespace(|| "blake2s"), &bits);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        let hash = result?;
        assert_eq!(hash.len(), 256);
        Ok(())
    }

    #[test]
    fn test_blake2s_256_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true); 256];
        let result = blake2s_256(cs.namespace(|| "blake2s"), &bits);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        let hash = result?;
        assert_eq!(hash.len(), 256);
        Ok(())
    }

    #[test]
    fn test_blake2s_256_different_inputs_different_outputs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut cs1 = TestConstraintSystem::new();
        let bits1 = vec![Boolean::constant(false); 256];
        let hash1 = blake2s_256(cs1.namespace(|| "blake2s"), &bits1)?;

        let mut cs2 = TestConstraintSystem::new();
        let bits2 = vec![Boolean::constant(true); 256];
        let hash2 = blake2s_256(cs2.namespace(|| "blake2s"), &bits2)?;

        // Hashes should differ (check at least one bit is different)
        let mut different = false;
        for i in 0..256 {
            if let (Some(v1), Some(v2)) = (hash1[i].get_value(), hash2[i].get_value()) {
                if v1 != v2 {
                    different = true;
                    break;
                }
            }
        }
        assert!(
            different,
            "Different inputs should produce different hashes"
        );
        Ok(())
    }

    #[test]
    fn test_blake2s_256_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let bits = vec![Boolean::constant(true); 8];

        let mut cs1 = TestConstraintSystem::new();
        let hash1 = blake2s_256(cs1.namespace(|| "blake2s"), &bits)?;

        let mut cs2 = TestConstraintSystem::new();
        let hash2 = blake2s_256(cs2.namespace(|| "blake2s"), &bits)?;

        // Same inputs should produce same outputs
        for i in 0..256 {
            if let (Some(v1), Some(v2)) = (hash1[i].get_value(), hash2[i].get_value()) {
                assert_eq!(v1, v2, "Hash should be deterministic");
            }
        }
        Ok(())
    }

    #[test]
    fn test_blake2s_256_various_sizes() -> Result<(), Box<dyn std::error::Error>> {
        for size in [8, 16, 32, 64, 128, 256, 512] {
            let mut cs = TestConstraintSystem::new();
            let bits = vec![Boolean::constant(true); size];
            let result = blake2s_256(cs.namespace(|| "blake2s"), &bits);
            assert!(result.is_ok(), "Failed for size {size}");
            assert!(cs.is_satisfied());
            assert_eq!(result?.len(), 256);
        }
        Ok(())
    }

    // ========================================================================
    // BLAKE2S_WITH_PERSONALIZATION TESTS
    // ========================================================================

    #[test]
    fn test_blake2s_with_personalization_empty() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![];
        let personalization = [0u8; 8];
        let result =
            blake2s_with_personalization(cs.namespace(|| "blake2s"), &bits, &personalization);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        let hash = result?;
        assert_eq!(hash.len(), 256);
        Ok(())
    }

    #[test]
    fn test_blake2s_with_personalization_custom() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true); 256];
        let personalization = [1, 2, 3, 4, 5, 6, 7, 8];
        let result =
            blake2s_with_personalization(cs.namespace(|| "blake2s"), &bits, &personalization);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        let hash = result?;
        assert_eq!(hash.len(), 256);
        Ok(())
    }

    #[test]
    fn test_blake2s_different_personalizations_different_outputs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bits = vec![Boolean::constant(false); 256];

        let mut cs1 = TestConstraintSystem::new();
        let personalization1 = [0u8; 8];
        let hash1 =
            blake2s_with_personalization(cs1.namespace(|| "blake2s"), &bits, &personalization1)?;

        let mut cs2 = TestConstraintSystem::new();
        let personalization2 = [1, 2, 3, 4, 5, 6, 7, 8];
        let hash2 =
            blake2s_with_personalization(cs2.namespace(|| "blake2s"), &bits, &personalization2)?;

        // Different personalizations should produce different hashes
        let mut different = false;
        for i in 0..256 {
            if let (Some(v1), Some(v2)) = (hash1[i].get_value(), hash2[i].get_value()) {
                if v1 != v2 {
                    different = true;
                    break;
                }
            }
        }
        assert!(
            different,
            "Different personalizations should produce different hashes"
        );
        Ok(())
    }

    #[test]
    fn test_blake2s_personalization_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let bits = vec![Boolean::constant(true); 8];
        let personalization = [42u8; 8];

        let mut cs1 = TestConstraintSystem::new();
        let hash1 =
            blake2s_with_personalization(cs1.namespace(|| "blake2s"), &bits, &personalization)?;

        let mut cs2 = TestConstraintSystem::new();
        let hash2 =
            blake2s_with_personalization(cs2.namespace(|| "blake2s"), &bits, &personalization)?;

        // Same inputs and personalization should produce same outputs
        for i in 0..256 {
            if let (Some(v1), Some(v2)) = (hash1[i].get_value(), hash2[i].get_value()) {
                assert_eq!(v1, v2, "Personalized hash should be deterministic");
            }
        }
        Ok(())
    }

    #[test]
    fn test_blake2s_personalization_various_values() -> Result<(), Box<dyn std::error::Error>> {
        let bits = vec![Boolean::constant(true); 128];

        for i in 0..8 {
            let mut personalization = [0u8; 8];
            personalization[i] = 255;

            let mut cs = TestConstraintSystem::new();
            let result =
                blake2s_with_personalization(cs.namespace(|| "blake2s"), &bits, &personalization);
            assert!(result.is_ok(), "Failed for personalization byte {i}");
            assert!(cs.is_satisfied());
            assert_eq!(result?.len(), 256);
        }
        Ok(())
    }

    #[test]
    fn test_blake2s_no_personalization_matches_blake2s_256(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bits = vec![Boolean::constant(true); 64];

        let mut cs1 = TestConstraintSystem::new();
        let hash1 = blake2s_256(cs1.namespace(|| "blake2s"), &bits)?;

        let mut cs2 = TestConstraintSystem::new();
        let personalization = [0u8; 8];
        let hash2 =
            blake2s_with_personalization(cs2.namespace(|| "blake2s"), &bits, &personalization)?;

        // Zero personalization should match blake2s_256
        for i in 0..256 {
            if let (Some(v1), Some(v2)) = (hash1[i].get_value(), hash2[i].get_value()) {
                assert_eq!(
                    v1, v2,
                    "Zero personalization should match blake2s_256 at bit {i}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn test_blake2s_personalization_all_same() -> Result<(), Box<dyn std::error::Error>> {
        let bits = vec![Boolean::constant(false); 128];

        for value in [0u8, 1, 42, 127, 255] {
            let personalization = [value; 8];

            let mut cs = TestConstraintSystem::new();
            let result =
                blake2s_with_personalization(cs.namespace(|| "blake2s"), &bits, &personalization);
            assert!(result.is_ok(), "Failed for personalization value {value}");
            assert!(cs.is_satisfied());
            assert_eq!(result?.len(), 256);
        }
        Ok(())
    }

    #[test]
    fn test_blake2s_personalization_various_sizes() -> Result<(), Box<dyn std::error::Error>> {
        let personalization = [1, 2, 3, 4, 5, 6, 7, 8];

        for size in [0, 8, 16, 32, 64, 128, 256, 512] {
            let mut cs = TestConstraintSystem::new();
            let bits = vec![Boolean::constant(false); size];
            let result =
                blake2s_with_personalization(cs.namespace(|| "blake2s"), &bits, &personalization);
            assert!(result.is_ok(), "Failed for size {size}");
            assert!(cs.is_satisfied());
            assert_eq!(result?.len(), 256);
        }
        Ok(())
    }

    // ========================================================================
    // EDGE CASE AND INTEGRATION TESTS
    // ========================================================================

    #[test]
    fn test_blake2s_256_large_input() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(true); 1024];
        let result = blake2s_256(cs.namespace(|| "blake2s"), &bits);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        assert_eq!(result?.len(), 256);
        Ok(())
    }

    #[test]
    fn test_blake2s_personalization_large_input() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = vec![Boolean::constant(false); 2048];
        let personalization = [255u8; 8];
        let result =
            blake2s_with_personalization(cs.namespace(|| "blake2s"), &bits, &personalization);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        assert_eq!(result?.len(), 256);
        Ok(())
    }

    #[test]
    fn test_blake2s_alternating_bits() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let bits = (0..256)
            .map(|i| Boolean::constant(i % 2 == 0))
            .collect::<Vec<_>>();
        let result = blake2s_256(cs.namespace(|| "blake2s"), &bits);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        assert_eq!(result?.len(), 256);
        Ok(())
    }

    #[test]
    fn test_blake2s_with_personalization_alternating_bits() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut cs = TestConstraintSystem::new();
        let bits = (0..256)
            .map(|i| Boolean::constant(i % 2 == 1))
            .collect::<Vec<_>>();
        let personalization = [170u8; 8]; // 0xAA
        let result =
            blake2s_with_personalization(cs.namespace(|| "blake2s"), &bits, &personalization);
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        assert_eq!(result?.len(), 256);
        Ok(())
    }
}
