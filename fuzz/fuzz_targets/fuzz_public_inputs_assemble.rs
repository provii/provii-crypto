#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_public_inputs::assemble_public_inputs_canonical;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    direction: bool,
    cutoff_days: i32,
    rp_hash: [u8; 32],
    issuer_vk_bytes: [u8; 32],
    cred_nullifier: [u8; 32],
}

/// Fuzz assemble_public_inputs_canonical function
/// Tests:
/// - Various cutoff values (0, max, random)
/// - Various hash values
/// - Various VK values
/// - Various nullifier values
/// - Determinism
/// - Output is always exactly 8 elements
/// - Sensitivity to input changes
fuzz_target!(|input: FuzzInput| {
    let result = match assemble_public_inputs_canonical(
        input.direction,
        input.cutoff_days,
        input.rp_hash,
        input.issuer_vk_bytes,
        input.cred_nullifier,
    ) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Invariant: output is always exactly 8 field elements
    assert_eq!(result.len(), 8, "Must always produce exactly 8 field elements");

    // Invariant: determinism
    let result2 = match assemble_public_inputs_canonical(
        input.direction,
        input.cutoff_days,
        input.rp_hash,
        input.issuer_vk_bytes,
        input.cred_nullifier,
    ) {
        Ok(r) => r,
        Err(_) => return,
    };
    assert_eq!(result.len(), result2.len());
    for i in 0..8 {
        assert_eq!(result[i], result2[i],
            "Function must be deterministic at index {}", i);
    }

    // Invariant: different cutoffs produce different outputs
    let diff_cutoff = input.cutoff_days.wrapping_add(1);
    let result_diff = match assemble_public_inputs_canonical(
        input.direction,
        diff_cutoff,
        input.rp_hash,
        input.issuer_vk_bytes,
        input.cred_nullifier,
    ) {
        Ok(r) => r,
        Err(_) => return,
    };
    assert_ne!(result[1], result_diff[1],
        "Different cutoffs must produce different second elements");

    // Invariant: different RP hashes produce different outputs
    let mut diff_rp_hash = input.rp_hash;
    diff_rp_hash[0] = diff_rp_hash[0].wrapping_add(1);
    let result_diff_rp = match assemble_public_inputs_canonical(
        input.direction,
        input.cutoff_days,
        diff_rp_hash,
        input.issuer_vk_bytes,
        input.cred_nullifier,
    ) {
        Ok(r) => r,
        Err(_) => return,
    };
    assert!(result[2] != result_diff_rp[2] || result[3] != result_diff_rp[3],
        "Different RP hashes must affect indices 2-3");

    // Invariant: different issuer VKs produce different outputs
    let mut diff_issuer_vk = input.issuer_vk_bytes;
    diff_issuer_vk[0] = diff_issuer_vk[0].wrapping_add(1);
    let result_diff_issuer = match assemble_public_inputs_canonical(
        input.direction,
        input.cutoff_days,
        input.rp_hash,
        diff_issuer_vk,
        input.cred_nullifier,
    ) {
        Ok(r) => r,
        Err(_) => return,
    };
    assert!(result[4] != result_diff_issuer[4] || result[5] != result_diff_issuer[5],
        "Different issuer VKs must affect indices 4-5");

    // Invariant: different nullifiers produce different outputs
    let mut diff_nullifier = input.cred_nullifier;
    diff_nullifier[0] = diff_nullifier[0].wrapping_add(1);
    let result_diff_nullifier = match assemble_public_inputs_canonical(
        input.direction,
        input.cutoff_days,
        input.rp_hash,
        input.issuer_vk_bytes,
        diff_nullifier,
    ) {
        Ok(r) => r,
        Err(_) => return,
    };
    assert!(result[6] != result_diff_nullifier[6] || result[7] != result_diff_nullifier[7],
        "Different nullifiers must affect indices 6-7");

    // Test extreme values with both directions
    let _ = assemble_public_inputs_canonical(input.direction, 0, input.rp_hash, input.issuer_vk_bytes, input.cred_nullifier);
    let _ = assemble_public_inputs_canonical(input.direction, i32::MAX, input.rp_hash, input.issuer_vk_bytes, input.cred_nullifier);
    let _ = assemble_public_inputs_canonical(!input.direction, input.cutoff_days, input.rp_hash, input.issuer_vk_bytes, input.cred_nullifier);
});
