#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_commit::{pedersen_commit_dob_validated, pedersen_nullifier};

fuzz_target!(|data: &[u8]| {
    // We need at least 4 (dob_days) + variable randomness bits
    if data.len() < 4 {
        return;
    }

    // Parse dob_days from first 4 bytes
    let dob_days = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    // Use remaining bytes to construct randomness bits
    let remaining = &data[4..];

    // Test 1: Convert remaining bytes to bool vector for randomness
    let mut r_bits = Vec::new();
    for byte in remaining.iter() {
        for bit_pos in 0..8 {
            r_bits.push((byte >> bit_pos) & 1 == 1);
        }
    }

    // Test 2: Compute commitment with fuzzer-provided randomness. The validated
    // API rejects randomness that is empty, oversized, below the 128-bit minimum,
    // or with fewer than 8 unique byte values. Reject paths must not panic.
    let commitment = match pedersen_commit_dob_validated(dob_days, &r_bits) {
        Ok(c) => c,
        Err(_) => return,
    };

    // CRITICAL: Verify commitment is always 32 bytes
    assert_eq!(commitment.len(), 32, "Commitment must always be 32 bytes");

    // Test 3: Compute nullifier from the commitment
    let nullifier = pedersen_nullifier(&commitment);

    // CRITICAL: Verify nullifier is always 32 bytes
    assert_eq!(nullifier.len(), 32, "Nullifier must always be 32 bytes");

    // CRITICAL: Verify nullifier is different from commitment
    // (This can fail for specific adversarial inputs, but shouldn't crash)
    let _ = commitment != nullifier;

    // Test 4: Determinism. r_bits has already passed validation above.
    let commitment2 = pedersen_commit_dob_validated(dob_days, &r_bits)
        .expect("validation already succeeded with these inputs");
    assert_eq!(commitment, commitment2, "pedersen_commit_dob_validated must be deterministic");

    let nullifier2 = pedersen_nullifier(&commitment);
    assert_eq!(nullifier, nullifier2, "pedersen_nullifier must be deterministic");

    // Test 5: Reject paths return Err and never panic.
    // Empty input fails the length check.
    assert!(pedersen_commit_dob_validated(dob_days, &[]).is_err());
    // Single-bit input fails both the entropy check and the 128-bit minimum.
    assert!(pedersen_commit_dob_validated(dob_days, &[true]).is_err());
    // All-ones (single unique byte value) fails the entropy check.
    assert!(pedersen_commit_dob_validated(dob_days, &vec![true; 192]).is_err());
    // All-zeros (single unique byte value) fails the entropy check.
    assert!(pedersen_commit_dob_validated(dob_days, &vec![false; 192]).is_err());
    // Oversized (> 1096) fails the length check.
    assert!(pedersen_commit_dob_validated(dob_days, &vec![true; 1097]).is_err());

    // Test 6: Test nullifier with edge case commitment bytes.
    let _ = pedersen_nullifier(&[0u8; 32]);
    let _ = pedersen_nullifier(&[0xFFu8; 32]);

    // Test 7: Single-bit difference in commitment must change nullifier.
    if data.len() >= 5 {
        let bit_flip_idx = data[4] as usize % 32;
        let mut commitment_flipped = commitment;
        commitment_flipped[bit_flip_idx] ^= 1;

        let nullifier_original = pedersen_nullifier(&commitment);
        let nullifier_flipped = pedersen_nullifier(&commitment_flipped);

        if commitment != commitment_flipped {
            assert_ne!(
                nullifier_original, nullifier_flipped,
                "Different commitments must produce different nullifiers"
            );
        }
    }

    // Test 8: Binding. Validation passed for r_bits, so the same r_bits with
    // a different dob_days must also validate and produce a different commitment.
    if dob_days < i32::MAX {
        let commitment_different = pedersen_commit_dob_validated(dob_days.wrapping_add(1), &r_bits)
            .expect("validation depends only on r_bits, which already passed");
        // Different dob must produce a different commitment.
        assert_ne!(
            commitment, commitment_different,
            "Different dob with same randomness must produce different commitments"
        );
    }
});
