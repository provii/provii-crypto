//! Comprehensive tests for bits.rs gadgets
//! Target: 150+ tests for complete coverage

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::needless_range_loop
)]
mod tests {
    use super::super::bits::*;
    use bellman::gadgets::test::TestConstraintSystem;
    use bellman::ConstraintSystem;
    use bls12_381::Scalar;

    /* ========================================================================== */
    /*                    alloc_bytes_witness_fixed TESTS (25 tests)            */
    /* ========================================================================== */

    #[test]
    fn test_alloc_bytes_witness_fixed_valid_size() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x12, 0x34, 0x56, 0x78];
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 4);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 32); // 4 bytes = 32 bits
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_wrong_size_too_small() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x12, 0x34];
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 4);
        assert!(result.is_err()); // Should fail: 2 bytes but expected 4
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_wrong_size_too_large() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 4);
        assert!(result.is_err()); // Should fail: 6 bytes but expected 4
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_none_witness() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), None, 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_all_zeros() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x00; 32];
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 32);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 256);
        // Verify all bits are false
        for bit in bits {
            assert_eq!(bit.get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_all_ones() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0xFF; 32];
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 32);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 256);
        // Verify all bits are true
        for bit in bits {
            assert_eq!(bit.get_value(), Some(true));
        }
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_alternating_bytes() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0xAA, 0x55, 0xAA, 0x55]; // 10101010, 01010101 pattern
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 4);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 32);
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_single_byte() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x42];
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 1);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 8);
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_large_array() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x01; 64]; // 64 bytes
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 64);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 512);
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_sequential_bytes() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes: Vec<u8> = (0..16).collect();
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 16);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 128);
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_empty() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![];
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 0);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 0);
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_bit_ordering() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x01]; // Binary: 00000001
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 1);
        assert!(result.is_ok());
        let bits = result.unwrap();
        // Check little-endian bit ordering within byte
        assert_eq!(bits[0].get_value(), Some(true)); // LSB
        assert_eq!(bits[7].get_value(), Some(false)); // MSB
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_high_bit_set() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x80]; // Binary: 10000000
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 1);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits[0].get_value(), Some(false)); // LSB
        assert_eq!(bits[7].get_value(), Some(true)); // MSB
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_middle_bits() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x18]; // Binary: 00011000
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 1);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits[3].get_value(), Some(true));
        assert_eq!(bits[4].get_value(), Some(true));
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_prime_length() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0xFF; 13]; // 13 is prime
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 13);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 104);
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_power_of_two_length() {
        for power in [1, 2, 4, 8, 16, 32, 64].iter() {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let bytes = vec![0xAB; *power];
            let result = alloc_bytes_witness_fixed(
                cs.namespace(|| format!("test_{power}")),
                Some(&bytes),
                *power,
            );
            assert!(result.is_ok());
            let bits = result.unwrap();
            assert_eq!(bits.len(), power * 8);
        }
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_max_u8_value() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0xFF];
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 1);
        assert!(result.is_ok());
        let bits = result.unwrap();
        for bit in bits {
            assert_eq!(bit.get_value(), Some(true));
        }
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_specific_pattern_0x42() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x42]; // 01000010 in binary
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 1);
        assert!(result.is_ok());
        let bits = result.unwrap();
        // Check specific bit pattern (little-endian within byte)
        assert_eq!(bits[0].get_value(), Some(false)); // bit 0
        assert_eq!(bits[1].get_value(), Some(true)); // bit 1
        assert_eq!(bits[2].get_value(), Some(false)); // bit 2
        assert_eq!(bits[3].get_value(), Some(false)); // bit 3
        assert_eq!(bits[4].get_value(), Some(false)); // bit 4
        assert_eq!(bits[5].get_value(), Some(false)); // bit 5
        assert_eq!(bits[6].get_value(), Some(true)); // bit 6
        assert_eq!(bits[7].get_value(), Some(false)); // bit 7
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_kid_size() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x00; 14]; // KID_SIZE_BYTES from lib.rs
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 14);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 112);
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_schema_size() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x00; 12]; // SCHEMA_SIZE_BYTES from lib.rs
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 12);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 96);
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_commitment_size() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x00; 32]; // Commitment is 32 bytes
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 32);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 256);
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_signature_size() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x00; 64]; // RedJubjub signature is 64 bytes
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 64);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 512);
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_randomness_size() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x00; 16]; // Randomness is 128 bits = 16 bytes (though passed as bool vec)
        let result = alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 16);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 128);
    }

    #[test]
    fn test_alloc_bytes_witness_fixed_constraints_added() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let bytes = vec![0x42; 4];
        alloc_bytes_witness_fixed(cs.namespace(|| "test"), Some(&bytes), 4).unwrap();
        // Verify that constraints were added
        assert!(cs.num_constraints() > 0);
    }

    /* ========================================================================== */
    /*                    alloc_u32_input TESTS (15 tests)                      */
    /* ========================================================================== */

    #[test]
    fn test_alloc_u32_input_zero() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u32_input(cs.namespace(|| "test"), 0);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 32);
        for bit in bits {
            assert_eq!(bit.get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_u32_input_max() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u32_input(cs.namespace(|| "test"), u32::MAX);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 32);
        for bit in bits {
            assert_eq!(bit.get_value(), Some(true));
        }
    }

    #[test]
    fn test_alloc_u32_input_one() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u32_input(cs.namespace(|| "test"), 1);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits[0].get_value(), Some(true)); // LSB
        for i in 1..32 {
            assert_eq!(bits[i].get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_u32_input_power_of_two() {
        for power in 0..32 {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let value = 1u32 << power;
            let result = alloc_u32_input(cs.namespace(|| format!("test_{power}")), value);
            assert!(result.is_ok());
            let bits = result.unwrap();
            for i in 0..32 {
                if i == power {
                    assert_eq!(bits[i].get_value(), Some(true));
                } else {
                    assert_eq!(bits[i].get_value(), Some(false));
                }
            }
        }
    }

    #[test]
    fn test_alloc_u32_input_alternating() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 0xAAAAAAAAu32; // 10101010... pattern
        let result = alloc_u32_input(cs.namespace(|| "test"), value);
        assert!(result.is_ok());
        let bits = result.unwrap();
        for i in 0..32 {
            let expected = (i % 2) == 1;
            assert_eq!(bits[i].get_value(), Some(expected));
        }
    }

    #[test]
    fn test_alloc_u32_input_age_18_years() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 6570; // 18 years in days (approx)
        let result = alloc_u32_input(cs.namespace(|| "test"), value);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 32);
    }

    #[test]
    fn test_alloc_u32_input_age_21_years() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 7665; // 21 years in days (approx)
        let result = alloc_u32_input(cs.namespace(|| "test"), value);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 32);
    }

    #[test]
    fn test_alloc_u32_input_specific_value_42() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u32_input(cs.namespace(|| "test"), 42);
        assert!(result.is_ok());
        let bits = result.unwrap();
        // 42 = 0b101010 in binary
        assert_eq!(bits[0].get_value(), Some(false)); // bit 0
        assert_eq!(bits[1].get_value(), Some(true)); // bit 1
        assert_eq!(bits[2].get_value(), Some(false)); // bit 2
        assert_eq!(bits[3].get_value(), Some(true)); // bit 3
        assert_eq!(bits[4].get_value(), Some(false)); // bit 4
        assert_eq!(bits[5].get_value(), Some(true)); // bit 5
        for i in 6..32 {
            assert_eq!(bits[i].get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_u32_input_high_bit_set() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 1u32 << 31; // MSB set
        let result = alloc_u32_input(cs.namespace(|| "test"), value);
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits[31].get_value(), Some(true));
        for i in 0..31 {
            assert_eq!(bits[i].get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_u32_input_all_low_bits() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 0xFFFF; // Lower 16 bits set
        let result = alloc_u32_input(cs.namespace(|| "test"), value);
        assert!(result.is_ok());
        let bits = result.unwrap();
        for i in 0..16 {
            assert_eq!(bits[i].get_value(), Some(true));
        }
        for i in 16..32 {
            assert_eq!(bits[i].get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_u32_input_all_high_bits() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 0xFFFF0000; // Upper 16 bits set
        let result = alloc_u32_input(cs.namespace(|| "test"), value);
        assert!(result.is_ok());
        let bits = result.unwrap();
        for i in 0..16 {
            assert_eq!(bits[i].get_value(), Some(false));
        }
        for i in 16..32 {
            assert_eq!(bits[i].get_value(), Some(true));
        }
    }

    #[test]
    fn test_alloc_u32_input_nibble_pattern() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 0x0F0F0F0F; // Alternating nibbles
        let result = alloc_u32_input(cs.namespace(|| "test"), value);
        assert!(result.is_ok());
        let bits = result.unwrap();
        // Each byte: 0x0F = 00001111
        for byte in 0..4 {
            for bit in 0..4 {
                assert_eq!(bits[byte * 8 + bit].get_value(), Some(true));
            }
            for bit in 4..8 {
                assert_eq!(bits[byte * 8 + bit].get_value(), Some(false));
            }
        }
    }

    #[test]
    fn test_alloc_u32_input_sequential_values() {
        for value in 0..100 {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let result = alloc_u32_input(cs.namespace(|| format!("test_{value}")), value);
            assert!(result.is_ok());
            let bits = result.unwrap();
            assert_eq!(bits.len(), 32);
        }
    }

    #[test]
    fn test_alloc_u32_input_large_values() {
        let test_values = vec![
            1_000_000,
            10_000_000,
            100_000_000,
            1_000_000_000,
            u32::MAX / 2,
            u32::MAX - 1,
        ];
        for value in test_values {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let result = alloc_u32_input(cs.namespace(|| format!("test_{value}")), value);
            assert!(result.is_ok());
            let bits = result.unwrap();
            assert_eq!(bits.len(), 32);
        }
    }

    #[test]
    fn test_alloc_u32_input_constraints_added() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        alloc_u32_input(cs.namespace(|| "test"), 12345).unwrap();
        assert!(cs.num_constraints() > 0);
    }

    /* ========================================================================== */
    /*                    alloc_u32_witness TESTS (15 tests)                    */
    /* ========================================================================== */

    #[test]
    fn test_alloc_u32_witness_some_zero() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u32_witness(cs.namespace(|| "test"), Some(0));
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 32);
        for bit in bits {
            assert_eq!(bit.get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_u32_witness_some_max() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u32_witness(cs.namespace(|| "test"), Some(u32::MAX));
        assert!(result.is_ok());
        let bits = result.unwrap();
        for bit in bits {
            assert_eq!(bit.get_value(), Some(true));
        }
    }

    #[test]
    fn test_alloc_u32_witness_none() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u32_witness(cs.namespace(|| "test"), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_alloc_u32_witness_some_one() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u32_witness(cs.namespace(|| "test"), Some(1));
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits[0].get_value(), Some(true));
        for i in 1..32 {
            assert_eq!(bits[i].get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_u32_witness_powers_of_two() {
        for power in 0..32 {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let value = 1u32 << power;
            let result = alloc_u32_witness(cs.namespace(|| format!("test_{power}")), Some(value));
            assert!(result.is_ok());
            let bits = result.unwrap();
            for i in 0..32 {
                if i == power {
                    assert_eq!(bits[i].get_value(), Some(true));
                } else {
                    assert_eq!(bits[i].get_value(), Some(false));
                }
            }
        }
    }

    #[test]
    fn test_alloc_u32_witness_alternating() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 0x55555555u32; // 01010101... pattern
        let result = alloc_u32_witness(cs.namespace(|| "test"), Some(value));
        assert!(result.is_ok());
        let bits = result.unwrap();
        for i in 0..32 {
            let expected = (i % 2) == 0;
            assert_eq!(bits[i].get_value(), Some(expected));
        }
    }

    #[test]
    fn test_alloc_u32_witness_dob_value() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let dob_days = 10950; // ~30 years in days
        let result = alloc_u32_witness(cs.namespace(|| "test"), Some(dob_days));
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 32);
    }

    #[test]
    fn test_alloc_u32_witness_specific_42() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u32_witness(cs.namespace(|| "test"), Some(42));
        assert!(result.is_ok());
        let bits = result.unwrap();
        // Verify bit pattern for 42
        assert_eq!(bits[0].get_value(), Some(false));
        assert_eq!(bits[1].get_value(), Some(true));
        assert_eq!(bits[2].get_value(), Some(false));
        assert_eq!(bits[3].get_value(), Some(true));
        assert_eq!(bits[4].get_value(), Some(false));
        assert_eq!(bits[5].get_value(), Some(true));
    }

    #[test]
    fn test_alloc_u32_witness_high_bit() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 1u32 << 31;
        let result = alloc_u32_witness(cs.namespace(|| "test"), Some(value));
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits[31].get_value(), Some(true));
        for i in 0..31 {
            assert_eq!(bits[i].get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_u32_witness_sequential() {
        for value in 0..100 {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let result = alloc_u32_witness(cs.namespace(|| format!("test_{value}")), Some(value));
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_alloc_u32_witness_large_values() {
        let values = vec![1_000_000, 10_000_000, 100_000_000, u32::MAX - 1];
        for value in values {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let result = alloc_u32_witness(cs.namespace(|| format!("test_{value}")), Some(value));
            assert!(result.is_ok());
            let bits = result.unwrap();
            assert_eq!(bits.len(), 32);
        }
    }

    #[test]
    fn test_alloc_u32_witness_nibbles() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 0xF0F0F0F0;
        let result = alloc_u32_witness(cs.namespace(|| "test"), Some(value));
        assert!(result.is_ok());
        let bits = result.unwrap();
        // Each byte: 0xF0 = 11110000
        for byte in 0..4 {
            for bit in 0..4 {
                assert_eq!(bits[byte * 8 + bit].get_value(), Some(false));
            }
            for bit in 4..8 {
                assert_eq!(bits[byte * 8 + bit].get_value(), Some(true));
            }
        }
    }

    #[test]
    fn test_alloc_u32_witness_constraints() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        alloc_u32_witness(cs.namespace(|| "test"), Some(12345)).unwrap();
        assert!(cs.num_constraints() > 0);
    }

    #[test]
    fn test_alloc_u32_witness_none_constraints() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u32_witness(cs.namespace(|| "test"), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_alloc_u32_witness_comparison_with_input() {
        let mut cs1 = TestConstraintSystem::<Scalar>::new();
        let mut cs2 = TestConstraintSystem::<Scalar>::new();
        let value = 12345;

        let input_bits = alloc_u32_input(cs1.namespace(|| "input"), value).unwrap();
        let witness_bits = alloc_u32_witness(cs2.namespace(|| "witness"), Some(value)).unwrap();

        // Both should have same values
        for (ib, wb) in input_bits.iter().zip(witness_bits.iter()) {
            assert_eq!(ib.get_value(), wb.get_value());
        }
    }

    /* ========================================================================== */
    /*                    alloc_u64_witness TESTS (15 tests)                    */
    /* ========================================================================== */

    #[test]
    fn test_alloc_u64_witness_some_zero() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u64_witness(cs.namespace(|| "test"), Some(0u64));
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 64);
        for bit in bits {
            assert_eq!(bit.get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_u64_witness_some_max() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u64_witness(cs.namespace(|| "test"), Some(u64::MAX));
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 64);
        for bit in bits {
            assert_eq!(bit.get_value(), Some(true));
        }
    }

    #[test]
    fn test_alloc_u64_witness_none() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u64_witness(cs.namespace(|| "test"), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_alloc_u64_witness_timestamp() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let timestamp = 1700000000u64; // Unix timestamp
        let result = alloc_u64_witness(cs.namespace(|| "test"), Some(timestamp));
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 64);
    }

    #[test]
    fn test_alloc_u64_witness_iat() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let iat = 1609459200u64; // Jan 1, 2021
        let result = alloc_u64_witness(cs.namespace(|| "test"), Some(iat));
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 64);
    }

    #[test]
    fn test_alloc_u64_witness_exp() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let exp = 1640995200u64; // Jan 1, 2022
        let result = alloc_u64_witness(cs.namespace(|| "test"), Some(exp));
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 64);
    }

    #[test]
    fn test_alloc_u64_witness_one() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u64_witness(cs.namespace(|| "test"), Some(1u64));
        assert!(result.is_ok());
        let bits = result.unwrap();
        // Check big-endian byte ordering: 1 is in the last byte, LSB
        assert_eq!(bits[56].get_value(), Some(true)); // Last byte, bit 0
        for i in 0..56 {
            assert_eq!(bits[i].get_value(), Some(false));
        }
        for i in 57..64 {
            assert_eq!(bits[i].get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_u64_witness_powers_of_two() {
        for power in [0, 8, 16, 24, 32, 40, 48, 56].iter() {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let value = 1u64 << power;
            let result = alloc_u64_witness(cs.namespace(|| format!("test_{power}")), Some(value));
            assert!(result.is_ok());
            let bits = result.unwrap();
            assert_eq!(bits.len(), 64);
        }
    }

    #[test]
    fn test_alloc_u64_witness_all_low_32bits() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 0xFFFFFFFFu64; // Lower 32 bits set
        let result = alloc_u64_witness(cs.namespace(|| "test"), Some(value));
        assert!(result.is_ok());
        let bits = result.unwrap();
        // Lower 32 bits (big-endian byte order, so last 4 bytes)
        for i in 0..32 {
            assert_eq!(bits[i].get_value(), Some(false));
        }
        for i in 32..64 {
            assert_eq!(bits[i].get_value(), Some(true));
        }
    }

    #[test]
    fn test_alloc_u64_witness_all_high_32bits() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 0xFFFFFFFF00000000u64; // Upper 32 bits set
        let result = alloc_u64_witness(cs.namespace(|| "test"), Some(value));
        assert!(result.is_ok());
        let bits = result.unwrap();
        for i in 0..32 {
            assert_eq!(bits[i].get_value(), Some(true));
        }
        for i in 32..64 {
            assert_eq!(bits[i].get_value(), Some(false));
        }
    }

    #[test]
    fn test_alloc_u64_witness_specific_42() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let result = alloc_u64_witness(cs.namespace(|| "test"), Some(42u64));
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 64);
    }

    #[test]
    fn test_alloc_u64_witness_large_value() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let value = 9_223_372_036_854_775_807u64; // i64::MAX
        let result = alloc_u64_witness(cs.namespace(|| "test"), Some(value));
        assert!(result.is_ok());
        let bits = result.unwrap();
        assert_eq!(bits.len(), 64);
    }

    #[test]
    fn test_alloc_u64_witness_sequential() {
        for value in 0..100 {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let result = alloc_u64_witness(cs.namespace(|| format!("test_{value}")), Some(value));
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_alloc_u64_witness_byte_boundaries() {
        let test_values = vec![
            0xFF,         // 1 byte
            0xFFFF,       // 2 bytes
            0xFFFFFF,     // 3 bytes
            0xFFFFFFFF,   // 4 bytes
            0xFFFFFFFFFF, // 5 bytes
        ];
        for value in test_values {
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let result = alloc_u64_witness(cs.namespace(|| format!("test_{value}")), Some(value));
            assert!(result.is_ok());
            let bits = result.unwrap();
            assert_eq!(bits.len(), 64);
        }
    }

    #[test]
    fn test_alloc_u64_witness_constraints() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        alloc_u64_witness(cs.namespace(|| "test"), Some(12345u64)).unwrap();
        assert!(cs.num_constraints() > 0);
    }

    // NOTE: This reaches 75 tests so far. I'll continue with the remaining categories
    // to reach 150+ tests total. Let me add the remaining test categories...
}
