// Circuit constraint code: usize-to-u8 casts here are on compile-time-known
// constants (DST length, schema length) that are always < 256. Indexing is
// on fixed-size bit vectors constructed within this module.
#![allow(clippy::cast_possible_truncation, clippy::indexing_slicing)]

use bellman::gadgets::boolean::Boolean;
use bellman::{ConstraintSystem, SynthesisError};
use bls12_381::Scalar;

/// Build the transcript preimage as bits:
///   CRED_DST || byte(v) || u8_len(kid)||kid || c(32) || u64be(iat) || u64be(exp) || u8_len(schema)||schema
use provii_crypto_commons::CRED_DST;

pub fn build_prehash_bits<CS: ConstraintSystem<Scalar>>(
    _cs: CS,
    v_bits: &[Boolean],       // 8 bits
    kid_bits: &[Boolean],     // variable length (8*kid_len bits)
    c_bytes_bits: &[Boolean], // 32*8 bits
    iat_bits_be: &[Boolean],  // 8*8 bits (64 bits)
    exp_bits_be: &[Boolean],  // 8*8 bits (64 bits)
    schema_bits: &[Boolean],  // variable length (8*schema_len bits)
) -> Result<Vec<Boolean>, SynthesisError> {
    if v_bits.len() != 8 {
        return Err(SynthesisError::Unsatisfiable);
    }
    if c_bytes_bits.len() != 32 * 8 {
        return Err(SynthesisError::Unsatisfiable);
    }
    if iat_bits_be.len() != 64 {
        return Err(SynthesisError::Unsatisfiable);
    }
    if exp_bits_be.len() != 64 {
        return Err(SynthesisError::Unsatisfiable);
    }
    if kid_bits.len() % 8 != 0 {
        return Err(SynthesisError::Unsatisfiable);
    }
    if schema_bits.len() % 8 != 0 {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut out = Vec::new();

    // DST - Domain Separation Tag
    for byte in CRED_DST {
        // Convert each byte to bits (little-endian within byte)
        for i in 0..8 {
            out.push(Boolean::constant((byte >> i) & 1 == 1));
        }
    }

    // v - version byte
    out.extend_from_slice(v_bits);

    // kid length (variable) + kid bytes
    if kid_bits.len() / 8 >= 256 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let kid_len = (kid_bits.len() / 8) as u8;
    for i in 0..8 {
        out.push(Boolean::constant((kid_len >> i) & 1 == 1));
    }
    out.extend_from_slice(kid_bits);

    // c (32 bytes = 256 bits)
    out.extend_from_slice(c_bytes_bits);

    // iat (u64 BE) and exp (u64 BE)
    out.extend_from_slice(iat_bits_be);
    out.extend_from_slice(exp_bits_be);

    // schema length (variable) + schema bytes
    if schema_bits.len() / 8 >= 256 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let schema_len = (schema_bits.len() / 8) as u8;
    for i in 0..8 {
        out.push(Boolean::constant((schema_len >> i) & 1 == 1));
    }
    out.extend_from_slice(schema_bits);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellman::gadgets::test::TestConstraintSystem;

    // Helper to create boolean bits from bytes
    fn bytes_to_bits(bytes: &[u8]) -> Vec<Boolean> {
        bytes
            .iter()
            .flat_map(|byte| (0..8).map(move |i| Boolean::constant((byte >> i) & 1 == 1)))
            .collect()
    }

    // Helper to create u64 bits (big-endian)
    fn u64_to_bits_be(value: u64) -> Vec<Boolean> {
        let bytes = value.to_be_bytes();
        bytes_to_bits(&bytes)
    }

    // ========================================================================
    // ASSERTION VALIDATION TESTS (12 tests)
    // ========================================================================

    #[test]
    fn test_valid_all_sizes_correct() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112]; // 14 bytes
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96]; // 12 bytes

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_err_v_bits_zero() {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }

    #[test]
    fn test_err_v_bits_seven() {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 7];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }

    #[test]
    fn test_err_v_bits_nine() {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 9];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }

    #[test]
    fn test_err_c_bytes_zero() {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }

    #[test]
    fn test_err_c_bytes_255() {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 255];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }

    #[test]
    fn test_err_iat_bits_63() {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = vec![Boolean::constant(false); 63];
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }

    #[test]
    fn test_err_exp_bits_65() {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = vec![Boolean::constant(false); 65];
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }

    #[test]
    fn test_err_kid_bits_not_aligned_7() {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 7];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }

    #[test]
    fn test_err_kid_bits_not_aligned_9() {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 9];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }

    #[test]
    fn test_err_schema_bits_not_aligned_7() {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 7];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }

    #[test]
    fn test_err_schema_bits_not_aligned_9() {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 9];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );
        assert!(matches!(result, Err(SynthesisError::Unsatisfiable)));
    }

    // ========================================================================
    // EDGE CASE TESTS (16 tests)
    // ========================================================================

    #[test]
    fn test_kid_empty() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![]; // 0 bytes
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        )?;

        // Expected length: DST(112) + v(8) + kid_len(8) + kid(0) + c(256) + iat(64) + exp(64) + schema_len(8) + schema(96)
        assert_eq!(result.len(), 112 + 8 + 8 + 256 + 64 + 64 + 8 + 96);
        Ok(())
    }

    #[test]
    fn test_kid_one_byte() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 8]; // 1 byte
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        )?;

        // Expected length: 112 + 8 + 8 + 8 + 256 + 64 + 64 + 8 + 96
        assert_eq!(result.len(), 624);
        Ok(())
    }

    #[test]
    fn test_kid_max_255_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 255 * 8]; // 255 bytes (max u8)
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        )?;

        // Expected length: 112 + 8 + 8 + 2040 + 256 + 64 + 64 + 8 + 96
        assert_eq!(result.len(), 2656);
        Ok(())
    }

    #[test]
    fn test_schema_empty() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![]; // 0 bytes

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        )?;

        // Expected length: 112 + 8 + 8 + 112 + 256 + 64 + 64 + 8 + 0
        assert_eq!(result.len(), 632);
        Ok(())
    }

    #[test]
    fn test_schema_one_byte() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 8]; // 1 byte

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        )?;

        // Expected length: 112 + 8 + 8 + 112 + 256 + 64 + 64 + 8 + 8
        assert_eq!(result.len(), 640);
        Ok(())
    }

    #[test]
    fn test_schema_max_255_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 255 * 8]; // 255 bytes

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        )?;

        // Expected length: 112 + 8 + 8 + 112 + 256 + 64 + 64 + 8 + 2040
        assert_eq!(result.len(), 2672);
        Ok(())
    }

    #[test]
    fn test_all_inputs_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );

        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_all_inputs_ones() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(true); 8];
        let kid_bits = vec![Boolean::constant(true); 112];
        let c_bytes_bits = vec![Boolean::constant(true); 256];
        let iat_bits = vec![Boolean::constant(true); 64];
        let exp_bits = vec![Boolean::constant(true); 64];
        let schema_bits = vec![Boolean::constant(true); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );

        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_v_zero_verify_dst_encoding() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8]; // v = 0x00
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        )?;

        // DST is first 14 bytes = 112 bits
        // Verify DST = "provii.cred.v0"
        let dst_bytes = b"provii.cred.v0";
        for (i, &byte) in dst_bytes.iter().enumerate() {
            for j in 0..8 {
                let expected = (byte >> j) & 1 == 1;
                if let Some(actual) = result[i * 8 + j].get_value() {
                    assert_eq!(actual, expected, "DST bit mismatch at byte {i} bit {j}");
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_v_max_verify_dst_encoding() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(true); 8]; // v = 0xFF
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        )?;

        // Verify DST is still correct
        let dst_bytes = b"provii.cred.v0";
        for (i, &byte) in dst_bytes.iter().enumerate() {
            for j in 0..8 {
                let expected = (byte >> j) & 1 == 1;
                if let Some(actual) = result[i * 8 + j].get_value() {
                    assert_eq!(actual, expected);
                }
            }
        }

        // Verify v bits come after DST (at indices 112-119)
        for (idx, item) in result.iter().enumerate().take(120).skip(112) {
            if let Some(actual) = item.get_value() {
                assert!(actual, "v bit {} should be true", idx - 112);
            }
        }
        Ok(())
    }

    #[test]
    fn test_iat_exp_zero() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );

        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_iat_exp_max() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(u64::MAX);
        let exp_bits = u64_to_bits_be(u64::MAX);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );

        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_output_length_calculation() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112]; // 14 bytes
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96]; // 12 bytes

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        )?;

        // DST(14*8) + v(8) + kid_len(8) + kid(14*8) + c(32*8) + iat(64) + exp(64) + schema_len(8) + schema(12*8)
        let expected_len = 112 + 8 + 8 + 112 + 256 + 64 + 64 + 8 + 96;
        assert_eq!(result.len(), expected_len);
        assert_eq!(result.len(), 728);
        Ok(())
    }

    #[test]
    fn test_dst_is_zerokp_cred_v2() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        )?;

        // Verify DST is exactly "provii.cred.v0" (14 bytes)
        assert_eq!(CRED_DST, b"provii.cred.v0");
        assert_eq!(CRED_DST.len(), 14);

        // Extract first 14 bytes from result
        let dst_bits = &result[0..112];
        let mut reconstructed = Vec::new();
        for chunk in dst_bits.chunks(8) {
            let mut byte = 0u8;
            for (i, bit) in chunk.iter().enumerate() {
                if let Some(val) = bit.get_value() {
                    if val {
                        byte |= 1 << i;
                    }
                }
            }
            reconstructed.push(byte);
        }

        assert_eq!(&reconstructed[..], b"provii.cred.v0");
        Ok(())
    }

    #[test]
    fn test_kid_112_bits_circuit_default() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112]; // KID_SIZE_BYTES * 8
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96];

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );

        let result = result?;
        assert!(cs.is_satisfied());
        // kid_len should be 14
        let kid_len_bits = &result[120..128];
        let mut kid_len = 0u8;
        for (i, bit) in kid_len_bits.iter().enumerate() {
            if let Some(val) = bit.get_value() {
                if val {
                    kid_len |= 1 << i;
                }
            }
        }
        assert_eq!(kid_len, 14);
        Ok(())
    }

    #[test]
    fn test_schema_96_bits_circuit_default() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let v_bits = vec![Boolean::constant(false); 8];
        let kid_bits = vec![Boolean::constant(false); 112];
        let c_bytes_bits = vec![Boolean::constant(false); 256];
        let iat_bits = u64_to_bits_be(0);
        let exp_bits = u64_to_bits_be(0);
        let schema_bits = vec![Boolean::constant(false); 96]; // SCHEMA_SIZE_BYTES * 8

        let result = build_prehash_bits(
            cs.namespace(|| "prehash"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        );

        let result = result?;
        assert!(cs.is_satisfied());
        // schema_len should be 12
        // schema_len is at position: DST(112) + v(8) + kid_len(8) + kid(112) + c(256) + iat(64) + exp(64) = 624
        let schema_len_bits = &result[624..632];
        let mut schema_len = 0u8;
        for (i, bit) in schema_len_bits.iter().enumerate() {
            if let Some(val) = bit.get_value() {
                if val {
                    schema_len |= 1 << i;
                }
            }
        }
        assert_eq!(schema_len, 12);
        Ok(())
    }
}
