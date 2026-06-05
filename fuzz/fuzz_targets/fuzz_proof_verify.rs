#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_commons::Error;
use provii_crypto_verifier::{init_with_vk_bytes, verify_age_snark};
use std::sync::Once;

static VK_BYTES: &[u8] = include_bytes!("../../age_vk.914153247.bin");
static INIT: Once = Once::new();

fn ensure_vk_initialized() {
    INIT.call_once(|| {
        init_with_vk_bytes(VK_BYTES).expect("VK initialization must succeed for fuzzing");
    });
}

fuzz_target!(|data: &[u8]| {
    ensure_vk_initialized();
    // Groth16 proofs on BLS12-381 are 192 bytes (3 * 64 bytes for A, B, C points)
    // We need at least proof + cutoff (4) + rp_hash (32) + issuer_vk (32) + nullifier (32) = 292 bytes
    if data.len() < 292 {
        return;
    }

    // Parse fuzzer input
    let proof_bytes = &data[0..192];

    let cutoff_days = i32::from_le_bytes([data[192], data[193], data[194], data[195]]);

    let rp_hash = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[196..228]);
        arr
    };

    let issuer_vk_bytes = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[228..260]);
        arr
    };

    let cred_nullifier = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[260..292]);
        arr
    };

    // Test 1: Verify with random proof (should reject gracefully)
    let result = verify_age_snark(
        proof_bytes,
        true,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes,
        cred_nullifier,
        0,
    );
    if let Err(ref e) = result {
        assert!(
            !matches!(e, Error::VerifierNotInitialized),
            "VK registry must be initialized before fuzzing"
        );
    }

    // Test 2: Edge case - zero proof
    let zero_proof = [0u8; 192];
    let _ = verify_age_snark(
        &zero_proof,
        true,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes,
        cred_nullifier,
        0,
    );

    // Test 3: Edge case - max proof
    let max_proof = [0xFFu8; 192];
    let _ = verify_age_snark(
        &max_proof,
        true,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes,
        cred_nullifier,
        0,
    );

    // Test 4: Edge case - all zero public inputs
    let _ = verify_age_snark(
        proof_bytes,
        true,
        0,
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
        0,
    );

    // Test 5: Edge case - all max public inputs
    let _ = verify_age_snark(
        proof_bytes,
        true,
        i32::MAX,
        [0xFFu8; 32],
        [0xFFu8; 32],
        [0xFFu8; 32],
        0,
    );

    // Test 6: Proof malleability - flip bits in different sections
    if data.len() >= 293 {
        let section = data[292] % 3; // Choose which point to tamper with
        let mut tampered_proof = proof_bytes.to_vec();

        let offset = (section as usize) * 64;
        if offset < tampered_proof.len() {
            tampered_proof[offset] ^= 0xFF;
        }

        let _ = verify_age_snark(
            &tampered_proof,
            true,
            cutoff_days,
            rp_hash,
            issuer_vk_bytes,
            cred_nullifier,
            0,
        );
    }

    // Test 7: Public input malleability - single bit flips
    if data.len() >= 294 {
        let input_selector = data[293] % 4; // Which input to tamper with

        match input_selector {
            0 => {
                // Tamper with cutoff
                let tampered_cutoff = cutoff_days.wrapping_add(1);
                let _ = verify_age_snark(
                    proof_bytes,
                    true,
                    tampered_cutoff,
                    rp_hash,
                    issuer_vk_bytes,
                    cred_nullifier,
                    0,
                );
            }
            1 => {
                // Tamper with rp_hash
                let mut tampered_rp = rp_hash;
                tampered_rp[0] ^= 1;
                let _ = verify_age_snark(
                    proof_bytes,
                    true,
                    cutoff_days,
                    tampered_rp,
                    issuer_vk_bytes,
                    cred_nullifier,
                    0,
                );
            }
            2 => {
                // Tamper with issuer_vk
                let mut tampered_vk = issuer_vk_bytes;
                tampered_vk[0] ^= 1;
                let _ = verify_age_snark(
                    proof_bytes,
                    true,
                    cutoff_days,
                    rp_hash,
                    tampered_vk,
                    cred_nullifier,
                    0,
                );
            }
            3 => {
                // Tamper with nullifier
                let mut tampered_nullifier = cred_nullifier;
                tampered_nullifier[0] ^= 1;
                let _ = verify_age_snark(
                    proof_bytes,
                    true,
                    cutoff_days,
                    rp_hash,
                    issuer_vk_bytes,
                    tampered_nullifier,
                    0,
                );
            }
            _ => unreachable!(),
        }
    }

    // Test 8: Truncated proofs (various lengths to test deserialization)
    for truncate_at in [0, 32, 64, 96, 128, 160, 191].iter() {
        if *truncate_at < proof_bytes.len() {
            let truncated = &proof_bytes[0..*truncate_at];
            let _ = verify_age_snark(
                truncated,
                true,
                cutoff_days,
                rp_hash,
                issuer_vk_bytes,
                cred_nullifier,
                0,
            );
        }
    }
});
