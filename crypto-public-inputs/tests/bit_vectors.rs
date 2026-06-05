//! Golden-vector tests for `bits_le_from_bytes`.
//!
//! These pin the exact bit-extraction logic against known inputs.
//! Any mutation to the shift, mask, or comparison operators will
//! cause at least one assertion to fail.

#[test]
fn bits_le_single_byte_0xa5() {
    // 0xA5 = 1010_0101 in big-endian binary.
    // Little-endian bit extraction (LSB first): [1,0,1,0,0,1,0,1]
    let bits = provii_crypto_public_inputs::bits_le_from_bytes(&[0xA5u8]);
    assert_eq!(
        bits,
        vec![true, false, true, false, false, true, false, true]
    );
}

#[test]
fn bits_le_single_byte_0x01() {
    // Only LSB set.
    let bits = provii_crypto_public_inputs::bits_le_from_bytes(&[0x01u8]);
    assert_eq!(
        bits,
        vec![true, false, false, false, false, false, false, false]
    );
}

#[test]
fn bits_le_single_byte_0x80() {
    // Only MSB set.
    let bits = provii_crypto_public_inputs::bits_le_from_bytes(&[0x80u8]);
    assert_eq!(
        bits,
        vec![false, false, false, false, false, false, false, true]
    );
}

#[test]
fn bits_le_two_bytes() {
    // 0x03 = 0000_0011 -> LE bits: [1,1,0,0,0,0,0,0]
    // 0xC0 = 1100_0000 -> LE bits: [0,0,0,0,0,0,1,1]
    let bits = provii_crypto_public_inputs::bits_le_from_bytes(&[0x03u8, 0xC0u8]);
    let expected = vec![
        true, true, false, false, false, false, false, false, // 0x03
        false, false, false, false, false, false, true, true, // 0xC0
    ];
    assert_eq!(bits, expected);
}

#[test]
fn bits_le_empty_input() {
    let bits = provii_crypto_public_inputs::bits_le_from_bytes(&[]);
    assert!(bits.is_empty());
}

#[test]
fn bits_le_length_invariant() {
    // Length must always equal input.len() * 8.
    for len in [1usize, 4, 16, 32] {
        let input = vec![0xFFu8; len];
        let bits = provii_crypto_public_inputs::bits_le_from_bytes(&input);
        assert_eq!(bits.len(), len * 8);
    }
}
