#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_public_inputs::{assemble_public_inputs_canonical, bits_le_from_bytes};

fuzz_target!(|data: &[u8]| {
    // We need at least 1 (direction) + 4 (cutoff) + 32 (rp_hash) + 32 (issuer_vk) + 32 (nullifier) = 101 bytes
    if data.len() < 101 {
        return;
    }

    // Parse fuzzer input
    let direction = data[0] & 1 == 1;
    let cutoff_days = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);

    let rp_hash = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[5..37]);
        arr
    };

    let issuer_vk_bytes = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[37..69]);
        arr
    };

    let cred_nullifier = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[69..101]);
        arr
    };

    // Test 1: Assemble public inputs with random data
    let public_inputs = match assemble_public_inputs_canonical(
        direction,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes,
        cred_nullifier,
    ) {
        Ok(pi) => pi,
        Err(_) => return,
    };

    // CRITICAL: Verify the output is always exactly 8 field elements
    assert_eq!(public_inputs.len(), 8, "Public inputs must always be 8 elements");

    // Test 2: Verify bit conversion for various byte patterns
    let bits_rp = bits_le_from_bytes(&rp_hash);
    assert_eq!(bits_rp.len(), 256, "Bits from 32 bytes must be 256");

    let bits_vk = bits_le_from_bytes(&issuer_vk_bytes);
    assert_eq!(bits_vk.len(), 256, "Bits from 32 bytes must be 256");

    let bits_nullifier = bits_le_from_bytes(&cred_nullifier);
    assert_eq!(bits_nullifier.len(), 256, "Bits from 32 bytes must be 256");

    // Test 3: Edge cases with both directions
    let _ = assemble_public_inputs_canonical(direction, 0, [0u8; 32], [0u8; 32], [0u8; 32]);
    let _ = assemble_public_inputs_canonical(!direction, i32::MAX, [0xFFu8; 32], [0xFFu8; 32], [0xFFu8; 32]);

    // Test 4: Single bit differences (test bit packing edge cases)
    if data.len() >= 102 {
        let bit_pos = data[101] as usize;

        // Flip a single bit in rp_hash
        let mut rp_hash_flip = rp_hash;
        let byte_idx = bit_pos % 32;
        let bit_idx = (bit_pos / 32) % 8;
        rp_hash_flip[byte_idx] ^= 1 << bit_idx;

        let inputs_original = match assemble_public_inputs_canonical(
            direction, cutoff_days, rp_hash, issuer_vk_bytes, cred_nullifier
        ) {
            Ok(r) => r,
            Err(_) => return,
        };
        let inputs_flipped = match assemble_public_inputs_canonical(
            direction, cutoff_days, rp_hash_flip, issuer_vk_bytes, cred_nullifier
        ) {
            Ok(r) => r,
            Err(_) => return,
        };

        // Verify that a single bit flip changes the output
        assert_ne!(inputs_original, inputs_flipped, "Single bit flip should change output");
    }

    // Test 5: Verify bit 254 handling (critical for the manual packing fix)
    let mut hash_with_254 = [0u8; 32];
    hash_with_254[31] = 0b01000000; // Set bit 254 (bit 6 of byte 31)

    if let Ok(inputs_254) = assemble_public_inputs_canonical(
        direction, 0, hash_with_254, [0u8; 32], [0u8; 32]
    ) {
        assert_eq!(inputs_254.len(), 8);
    }
});
