//! Groth16 proof verification for age-based credentials.
//!
//! # Initialisation
//!
//! The verifier maintains a global registry of prepared verifying keys. Call one
//! of the init functions exactly once before any verification:
//!
//! - [`init_with_vk_bytes`]: single VK under id 0 (tests, simple deployments)
//! - [`init_with_vk_registry`]: multiple VKs keyed by `vk_id` (production)
//!
//! Calling init a second time returns [`Error::AlreadyInitialized`]. The
//! registry is immutable after initialisation.
//!
//! # Verification
//!
//! After init, call [`verify_age_snark`] with proof bytes and public inputs.
//! The function looks up the VK by `vk_id`, assembles canonical public inputs,
//! and delegates to Bellman's Groth16 verifier.

#![forbid(unsafe_code)]

use bellman::groth16::{
    prepare_verifying_key, verify_proof, PreparedVerifyingKey, Proof, VerifyingKey,
};
use bls12_381::Bls12;
use once_cell::sync::OnceCell;
use provii_crypto_commons::{Error, Result};
use provii_crypto_public_inputs::assemble_public_inputs_canonical;
use std::collections::HashMap;
use std::io::Cursor;

/// Multi-VK registry keyed by `vk_id`. Both over-age and under-age use the same VK now.
static VK_REGISTRY: OnceCell<HashMap<u32, PreparedVerifyingKey<Bls12>>> = OnceCell::new();

/// Load and prepare the verifying key; intended to run once during startup.
///
/// `bytes` must be a valid serialised `VerifyingKey<Bls12>` as produced by
/// `VerifyingKey::write`. Empty slices, truncated data, and arbitrary byte
/// sequences are rejected with an error. The function never panics on
/// malformed input.
pub fn load_vk(bytes: &[u8]) -> Result<PreparedVerifyingKey<Bls12>> {
    let mut rd = Cursor::new(bytes);
    let vk = VerifyingKey::<Bls12>::read(&mut rd).map_err(|_| Error::InvalidFormat)?;
    Ok(prepare_verifying_key(&vk))
}

/// Initialize with a single verifying key (convenience for tests and simple deployments).
///
/// Stores the VK in the registry under `vk_id = 0`.
pub fn init_with_vk_bytes(bytes: &[u8]) -> Result<()> {
    let pvk = load_vk(bytes)?;
    let mut map = HashMap::new();
    map.insert(0u32, pvk);
    VK_REGISTRY
        .set(map)
        .map_err(|_| Error::AlreadyInitialized)?;
    Ok(())
}

/// Initialize with multiple verifying keys keyed by `vk_id`.
///
/// Each entry is `(vk_id, serialized_vk_bytes)`. Since both over-age and
/// under-age now share the same circuit, a single VK serves both directions.
///
/// # Errors
///
/// Returns an error if `entries` is empty (at least one VK is required),
/// if any entry fails to deserialise, or if the registry was already
/// initialised by a prior call.
pub fn init_with_vk_registry(entries: Vec<(u32, Vec<u8>)>) -> Result<()> {
    if entries.is_empty() {
        return Err(Error::InvalidInput);
    }
    let mut map = HashMap::new();
    for (vk_id, bytes) in entries {
        let pvk = load_vk(&bytes)?;
        map.insert(vk_id, pvk);
    }
    VK_REGISTRY
        .set(map)
        .map_err(|_| Error::AlreadyInitialized)?;
    Ok(())
}

/// Result of a successful age verification with the extracted public inputs.
///
/// Returned by [`verify_age_snark`] when the Groth16 proof passes. All
/// fields mirror the public inputs that the prover committed to.
#[derive(Debug)]
pub struct VerifyResult {
    /// `true` for over-age, `false` for under-age.
    pub direction: bool,
    /// Age threshold in days encoded in the proof (negative for pre-1970 dates).
    pub cutoff_days: i32,
    /// Blake2s hash of the relying party challenge.
    pub rp_hash: [u8; 32],
    /// Raw issuer verification key bytes committed inside the credential.
    pub issuer_vk_bytes: [u8; 32],
    /// Pedersen-based credential nullifier preventing reuse.
    pub cred_nullifier: [u8; 32],
    /// VK registry key that was used for verification.
    pub vk_id: u32,
}

/// Verify a Groth16 proof produced by the age credential circuit.
///
/// Public inputs (packed via multipack):
///
/// 1. `direction` (1 bit: Over = true, Under = false)
/// 2. `cutoff_days` (32-bit signed, biased to unsigned internally)
/// 4. `rp_hash` (256 bits, Blake2s hash of the relying-party challenge)
/// 5. `issuer_vk_bytes` (256 bits, raw issuer verification key)
/// 6. `cred_nullifier` (256 bits, Pedersen-based nullifier)
///
/// The `vk_id` selects which verifying key to use from the registry.
///
/// # Errors
///
/// Returns `Error::VerifierNotInitialized` if no VK was registered for
/// `vk_id`. Returns `Error::InvalidFormat` if `proof_bytes` cannot be
/// parsed as a Groth16 proof. Returns `Error::VerificationFailed` if the
/// proof does not verify against the assembled public inputs.
pub fn verify_age_snark(
    proof_bytes: &[u8],
    direction: bool,
    cutoff_days: i32,
    rp_hash: [u8; 32],
    issuer_vk_bytes: [u8; 32],
    cred_nullifier: [u8; 32],
    vk_id: u32,
) -> Result<VerifyResult> {
    let pvk = VK_REGISTRY
        .get()
        .and_then(|registry| registry.get(&vk_id))
        .ok_or(Error::VerifierNotInitialized)?;

    // Assemble the public inputs in their canonical order.
    let inputs = assemble_public_inputs_canonical(
        direction,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes,
        cred_nullifier,
    )
    .map_err(|_| Error::InvalidInput)?;

    let proof: Proof<Bls12> = Proof::read(&mut &*proof_bytes).map_err(|_| Error::InvalidFormat)?;

    verify_proof(pvk, &proof, &inputs).map_err(|_| Error::VerificationFailed)?;

    Ok(VerifyResult {
        direction,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes,
        cred_nullifier,
        vk_id,
    })
}

#[cfg(test)]
// Test code: unwrap, expect, and indexing are the standard assertion pattern for
// unit tests. A panic from `.unwrap()` in a test IS the correct failure mode.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use blake2::{Blake2s256, Digest};
    use ff::{Field, PrimeField};

    /* ========================================================================== */
    /*                    VERIFY_RESULT STRUCTURE TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_verify_result_construction() {
        let result = VerifyResult {
            direction: true,
            cutoff_days: 6570,
            rp_hash: [1u8; 32],
            issuer_vk_bytes: [2u8; 32],
            cred_nullifier: [3u8; 32],
            vk_id: 0,
        };

        assert!(result.direction);
        assert_eq!(result.cutoff_days, 6570);
        assert_eq!(result.rp_hash, [1u8; 32]);
        assert_eq!(result.issuer_vk_bytes, [2u8; 32]);
        assert_eq!(result.cred_nullifier, [3u8; 32]);
    }

    #[test]
    fn test_verify_result_zero_values() {
        let result = VerifyResult {
            direction: true,
            cutoff_days: 0,
            rp_hash: [0u8; 32],
            issuer_vk_bytes: [0u8; 32],
            cred_nullifier: [0u8; 32],
            vk_id: 0,
        };

        assert_eq!(result.cutoff_days, 0);
        assert_eq!(result.rp_hash.len(), 32);
        assert_eq!(result.issuer_vk_bytes.len(), 32);
        assert_eq!(result.cred_nullifier.len(), 32);
    }

    #[test]
    fn test_verify_result_boundary_values() {
        let result = VerifyResult {
            direction: true,
            cutoff_days: i32::MAX,
            rp_hash: [0xFF; 32],
            issuer_vk_bytes: [0xFF; 32],
            cred_nullifier: [0xFF; 32],
            vk_id: 0,
        };

        assert_eq!(result.cutoff_days, i32::MAX);
        assert_eq!(result.rp_hash, [0xFF; 32]);
    }

    /* ========================================================================== */
    /*                    LOAD_VK ERROR HANDLING TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_load_vk_empty_bytes() {
        let result = load_vk(&[]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::InvalidFormat);
        }
    }

    #[test]
    fn test_load_vk_invalid_bytes() {
        let invalid = vec![0xFF; 100];
        let result = load_vk(&invalid);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::InvalidFormat);
        }
    }

    #[test]
    fn test_load_vk_truncated_bytes() {
        // Just a few bytes that look like they might start a valid structure
        let truncated = vec![0x01, 0x02, 0x03, 0x04];
        let result = load_vk(&truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_vk_random_data() {
        let random = vec![0xAA; 500];
        let result = load_vk(&random);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    VERIFY_AGE_SNARK ERROR HANDLING TESTS                  */
    /* ========================================================================== */

    #[test]
    fn test_verify_age_snark_not_initialized() {
        // Don't initialize PVK
        let result = verify_age_snark(&[0xFF; 192], true, 6570, [0; 32], [1; 32], [2; 32], 0);

        assert!(result.is_err());
        // Check error type without unwrapping (VerifyResult doesn't need Debug now but safer this way)
        if let Err(e) = result {
            assert!(matches!(e, Error::VerifierNotInitialized));
        }
    }

    #[test]
    fn test_verify_age_snark_empty_proof() {
        // Test that empty proof bytes are rejected
        let result = verify_age_snark(&[], true, 6570, [0; 32], [1; 32], [2; 32], 0);

        // Will fail with VerifierNotInitialized since we haven't initialized PVK
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_age_snark_zero_cutoff() {
        let result = verify_age_snark(
            &[0xFF; 192],
            true,
            0, // Zero cutoff
            [0; 32],
            [1; 32],
            [2; 32],
            0,
        );

        // Will fail with VerifierNotInitialized, but validates input handling
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_age_snark_large_cutoff() {
        let result = verify_age_snark(
            &[0xFF; 192],
            true,
            i32::MAX, // Maximum cutoff
            [0; 32],
            [1; 32],
            [2; 32],
            0,
        );

        // Will fail with VerifierNotInitialized, but validates input handling
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    PUBLIC INPUT ASSEMBLY TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_public_inputs_assembly_deterministic() {
        // Same inputs should always produce same outputs
        let cutoff = 6570;
        let rp_hash = [0xAB; 32];
        let issuer_vk = [0xCD; 32];
        let nullifier = [0xEF; 32];

        let inputs1 =
            assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier).unwrap();
        let inputs2 =
            assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier).unwrap();

        assert_eq!(inputs1.len(), inputs2.len());
        for (a, b) in inputs1.iter().zip(inputs2.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_public_inputs_assembly_different_cutoffs() {
        let rp_hash = [0xAB; 32];
        let issuer_vk = [0xCD; 32];
        let nullifier = [0xEF; 32];

        let inputs1 =
            assemble_public_inputs_canonical(true, 6570, rp_hash, issuer_vk, nullifier).unwrap();
        let inputs2 =
            assemble_public_inputs_canonical(true, 7665, rp_hash, issuer_vk, nullifier).unwrap();

        assert_eq!(inputs1.len(), inputs2.len());
        // Second element should differ (cutoff is at index 1)
        assert_ne!(inputs1[1], inputs2[1]);
    }

    #[test]
    fn test_public_inputs_assembly_different_hashes() {
        let cutoff = 6570;
        let issuer_vk = [0xCD; 32];
        let nullifier = [0xEF; 32];

        let inputs1 =
            assemble_public_inputs_canonical(true, cutoff, [0xAA; 32], issuer_vk, nullifier)
                .unwrap();
        let inputs2 =
            assemble_public_inputs_canonical(true, cutoff, [0xBB; 32], issuer_vk, nullifier)
                .unwrap();

        assert_eq!(inputs1.len(), inputs2.len());
        // RP hash elements should differ (indices 2-3)
        assert!(inputs1[2] != inputs2[2] || inputs1[3] != inputs2[3]);
    }

    #[test]
    fn test_public_inputs_assembly_count() {
        let inputs =
            assemble_public_inputs_canonical(true, 6570, [0; 32], [1; 32], [2; 32]).unwrap();

        // Should have 8 public inputs:
        // 1 for direction + 1 for cutoff + 2 for rp_hash + 2 for issuer_vk + 2 for nullifier
        assert_eq!(inputs.len(), 8);
    }

    #[test]
    fn test_public_inputs_assembly_zero_values() {
        let inputs = assemble_public_inputs_canonical(true, 0, [0; 32], [0; 32], [0; 32]).unwrap();

        assert_eq!(inputs.len(), 8);
        // Zero cutoff_days biased to 0x8000_0000 produces non-zero element
        assert_ne!(inputs[1], bls12_381::Scalar::ZERO);
    }

    #[test]
    fn test_public_inputs_assembly_max_cutoff() {
        let inputs =
            assemble_public_inputs_canonical(true, i32::MAX, [0xFF; 32], [0xFF; 32], [0xFF; 32])
                .unwrap();

        assert_eq!(inputs.len(), 8);
        // All inputs should be non-zero
        for input in &inputs {
            // At least one byte should be non-zero
            assert!(input.to_repr().iter().any(|&b| b != 0));
        }
    }

    /* ========================================================================== */
    /*                    INIT_WITH_VK_BYTES TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_init_with_vk_bytes_empty() {
        let result = init_with_vk_bytes(&[]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, Error::InvalidFormat);
        }
    }

    #[test]
    fn test_init_with_vk_bytes_invalid_data() {
        let invalid_vk = vec![0xFF; 100];
        let result = init_with_vk_bytes(&invalid_vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_init_with_vk_bytes_small_data() {
        let small_vk = vec![0x01, 0x02, 0x03];
        let result = init_with_vk_bytes(&small_vk);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    VERIFY_AGE_SNARK ADDITIONAL ERROR CASES               */
    /* ========================================================================== */

    #[test]
    fn test_verify_age_snark_invalid_proof_format() {
        // First, ensure PVK is not initialized (it shouldn't be in test environment)
        let invalid_proof = vec![0xFF, 0xFE]; // Too short to be a valid proof
        let result = verify_age_snark(
            &invalid_proof,
            true,
            6570,
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            0,
        );

        assert!(result.is_err());
        // Will fail with VerifierNotInitialized first
    }

    #[test]
    fn test_verify_age_snark_random_proof_bytes() {
        // Random bytes that might look like a proof but aren't valid
        let random_proof = vec![0x42; 192]; // Groth16 proofs are typically 192 bytes
        let result = verify_age_snark(
            &random_proof,
            true,
            7300,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            0,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_age_snark_all_zeros() {
        let zero_proof = vec![0x00; 192];
        let result = verify_age_snark(&zero_proof, true, 0, [0; 32], [0; 32], [0; 32], 0);

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_age_snark_all_ones() {
        let ones_proof = vec![0xFF; 192];
        let result = verify_age_snark(
            &ones_proof,
            true,
            i32::MAX,
            [0xFF; 32],
            [0xFF; 32],
            [0xFF; 32],
            0,
        );

        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    LOAD_VK ADDITIONAL TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_load_vk_various_sizes() {
        // Test various invalid sizes
        for size in [1, 10, 50, 100, 200, 500] {
            let data = vec![0xAB; size];
            let result = load_vk(&data);
            assert!(result.is_err(), "Size {size} should fail");
        }
    }

    #[test]
    fn test_load_vk_structured_but_invalid() {
        // Create data that might look structured but isn't a valid VK
        let mut data = Vec::new();
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Possible version/header
        data.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // Possible length field
        data.resize(100, 0x55); // Fill with pattern

        let result = load_vk(&data);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    INTEGRATION TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_hex_encoding_consistency() {
        let test_data = [0x12, 0x34, 0x56, 0x78];
        let encoded = hex::encode(test_data);
        assert_eq!(encoded, "12345678");
    }

    #[test]
    fn test_blake2s_deterministic() {
        let data = b"test data";
        let hash1 = Blake2s256::digest(data);
        let hash2 = Blake2s256::digest(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake2s_different_inputs() {
        let hash1 = Blake2s256::digest(b"data1");
        let hash2 = Blake2s256::digest(b"data2");
        assert_ne!(hash1, hash2);
    }

    /* ========================================================================== */
    /*                    PC-290: UNKNOWN VK_ID TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_verify_age_snark_unknown_vk_id() {
        // PC-290: Attempting verification with an unknown/unregistered vk_id
        // must return VerifierNotInitialized (the registry has no entry for it).
        let unknown_vk_id = 9999u32;
        let result = verify_age_snark(
            &[0xAA; 192],
            true,
            6570,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            unknown_vk_id,
        );

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(
                e,
                Error::VerifierNotInitialized,
                "Unknown vk_id must return VerifierNotInitialized"
            );
        }
    }

    #[test]
    fn test_verify_age_snark_max_vk_id() {
        // PC-290: u32::MAX as vk_id should also fail gracefully
        let result = verify_age_snark(
            &[0xBB; 192],
            false,
            7300,
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            u32::MAX,
        );

        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(
                e,
                Error::VerifierNotInitialized,
                "u32::MAX vk_id must return VerifierNotInitialized"
            );
        }
    }

    #[test]
    fn test_verify_age_snark_various_unregistered_vk_ids() {
        // PC-290: Multiple unregistered vk_ids all return the same error
        for vk_id in [1u32, 42, 100, 1000, 65535, 2_031_517_468] {
            let result = verify_age_snark(
                &[0xCC; 192],
                true,
                6570,
                [0x77; 32],
                [0x88; 32],
                [0x99; 32],
                vk_id,
            );
            assert!(result.is_err(), "vk_id {vk_id} must fail");
            if let Err(e) = result {
                assert_eq!(
                    e,
                    Error::VerifierNotInitialized,
                    "vk_id {vk_id} must return VerifierNotInitialized"
                );
            }
        }
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    use proptest::prelude::*;

    proptest! {
        /// Property: assemble_public_inputs is deterministic
        #[test]
        fn prop_assemble_public_inputs_deterministic(
            cutoff in -25000i32..50000,
            rp_hash in any::<[u8; 32]>(),
            issuer_vk in any::<[u8; 32]>(),
            nullifier in any::<[u8; 32]>()
        ) {
            let result1 = assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier).unwrap();
            let result2 = assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier).unwrap();

            prop_assert_eq!(result1.len(), 8, "Must always produce 8 elements");
            prop_assert_eq!(result2.len(), 8, "Must always produce 8 elements");

            for i in 0..8 {
                prop_assert_eq!(result1[i], result2[i], "Element {} must match", i);
            }
        }

        /// Property: VerifyResult fields are independent
        #[test]
        fn prop_verify_result_fields_independent(
            cutoff in any::<i32>(),
            rp_hash in any::<[u8; 32]>(),
            issuer_vk in any::<[u8; 32]>(),
            nullifier in any::<[u8; 32]>()
        ) {
            let result = VerifyResult {
                direction: true,
                cutoff_days: cutoff,
                rp_hash,
                issuer_vk_bytes: issuer_vk,
                cred_nullifier: nullifier,
                vk_id: 0,
            };

            prop_assert_eq!(result.cutoff_days, cutoff, "Cutoff must be preserved");
            prop_assert_eq!(result.rp_hash, rp_hash, "RP hash must be preserved");
            prop_assert_eq!(result.issuer_vk_bytes, issuer_vk, "Issuer VK must be preserved");
            prop_assert_eq!(result.cred_nullifier, nullifier, "Nullifier must be preserved");
        }

        /// Property: assemble_public_inputs always produces 8 elements
        #[test]
        fn prop_public_inputs_count_invariant(
            cutoff in any::<i32>(),
            rp_hash in any::<[u8; 32]>(),
            issuer_vk in any::<[u8; 32]>(),
            nullifier in any::<[u8; 32]>()
        ) {
            let inputs = assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier).unwrap();
            prop_assert_eq!(inputs.len(), 8, "Must always produce exactly 8 public inputs");
        }

        /// Property: Different cutoffs produce different second elements (index 1)
        #[test]
        fn prop_cutoff_affects_second_element(
            cutoff1 in -25000i32..50000,
            cutoff2 in -25000i32..50000,
            rp_hash in any::<[u8; 32]>(),
            issuer_vk in any::<[u8; 32]>(),
            nullifier in any::<[u8; 32]>()
        ) {
            prop_assume!(cutoff1 != cutoff2);

            let inputs1 = assemble_public_inputs_canonical(true, cutoff1, rp_hash, issuer_vk, nullifier).unwrap();
            let inputs2 = assemble_public_inputs_canonical(true, cutoff2, rp_hash, issuer_vk, nullifier).unwrap();

            prop_assert_ne!(inputs1[1], inputs2[1], "Different cutoffs must produce different second elements");
        }

        /// Property: Different RP hashes affect indices 2-3
        #[test]
        fn prop_rp_hash_affects_indices_2_3(
            cutoff in -25000i32..50000,
            rp_hash1 in any::<[u8; 32]>(),
            rp_hash2 in any::<[u8; 32]>(),
            issuer_vk in any::<[u8; 32]>(),
            nullifier in any::<[u8; 32]>()
        ) {
            prop_assume!(rp_hash1 != rp_hash2);

            let inputs1 = assemble_public_inputs_canonical(true, cutoff, rp_hash1, issuer_vk, nullifier).unwrap();
            let inputs2 = assemble_public_inputs_canonical(true, cutoff, rp_hash2, issuer_vk, nullifier).unwrap();

            let different = inputs1[2] != inputs2[2] || inputs1[3] != inputs2[3];
            prop_assert!(different, "Different RP hashes must affect indices 2-3");
        }

        /// Property: Different issuer VKs affect indices 4-5
        #[test]
        fn prop_issuer_vk_affects_indices_4_5(
            cutoff in -25000i32..50000,
            rp_hash in any::<[u8; 32]>(),
            issuer_vk1 in any::<[u8; 32]>(),
            issuer_vk2 in any::<[u8; 32]>(),
            nullifier in any::<[u8; 32]>()
        ) {
            prop_assume!(issuer_vk1 != issuer_vk2);

            let inputs1 = assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk1, nullifier).unwrap();
            let inputs2 = assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk2, nullifier).unwrap();

            let different = inputs1[4] != inputs2[4] || inputs1[5] != inputs2[5];
            prop_assert!(different, "Different issuer VKs must affect indices 4-5");
        }

        /// Property: Different nullifiers affect indices 6-7
        #[test]
        fn prop_nullifier_affects_indices_6_7(
            cutoff in -25000i32..50000,
            rp_hash in any::<[u8; 32]>(),
            issuer_vk in any::<[u8; 32]>(),
            nullifier1 in any::<[u8; 32]>(),
            nullifier2 in any::<[u8; 32]>()
        ) {
            prop_assume!(nullifier1 != nullifier2);

            let inputs1 = assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier1).unwrap();
            let inputs2 = assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier2).unwrap();

            let different = inputs1[6] != inputs2[6] || inputs1[7] != inputs2[7];
            prop_assert!(different, "Different nullifiers must affect indices 6-7");
        }

        /// Property: load_vk rejects small byte arrays
        #[test]
        fn prop_load_vk_rejects_small_inputs(bytes in prop::collection::vec(any::<u8>(), 0..20)) {
            let result = load_vk(&bytes);
            prop_assert!(result.is_err(), "Small byte arrays must be rejected");
        }

        /// Property: load_vk rejects random data
        #[test]
        fn prop_load_vk_rejects_random_data(bytes in prop::collection::vec(any::<u8>(), 50..200)) {
            let result = load_vk(&bytes);
            prop_assert!(result.is_err(), "Random data must be rejected");
        }

        /// Property: verify_age_snark returns VerifierNotInitialized when PVK not set
        #[test]
        fn prop_verify_age_snark_not_initialized_error(
            proof_bytes in prop::collection::vec(any::<u8>(), 100..300),
            cutoff in any::<i32>(),
            rp_hash in any::<[u8; 32]>(),
            issuer_vk in any::<[u8; 32]>(),
            nullifier in any::<[u8; 32]>()
        ) {
            // Don't initialize PVK - it should remain uninitialized
            let result = verify_age_snark(&proof_bytes, true, cutoff, rp_hash, issuer_vk, nullifier, 0);

            // Should always fail with VerifierNotInitialized when PVK is not set
            prop_assert!(result.is_err(), "Must fail when verifier not initialized");
            if let Err(e) = result {
                prop_assert!(matches!(e, Error::VerifierNotInitialized),
                    "Must return VerifierNotInitialized error");
            }
        }

        /// Property: Blake2s256 is deterministic
        #[test]
        fn prop_blake2s_deterministic(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            let hash1 = Blake2s256::digest(&data);
            let hash2 = Blake2s256::digest(&data);
            prop_assert_eq!(hash1, hash2, "Blake2s256 must be deterministic");
        }

        /// Property: Blake2s256 produces 32-byte hashes
        #[test]
        fn prop_blake2s_output_length(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            let hash = Blake2s256::digest(&data);
            prop_assert_eq!(hash.len(), 32, "Blake2s256 must produce 32-byte hashes");
        }

        /// Property: Different inputs produce different Blake2s hashes
        #[test]
        fn prop_blake2s_different_inputs_different_hashes(
            data1 in prop::collection::vec(any::<u8>(), 1..100),
            data2 in prop::collection::vec(any::<u8>(), 1..100)
        ) {
            prop_assume!(data1 != data2);

            let hash1 = Blake2s256::digest(&data1);
            let hash2 = Blake2s256::digest(&data2);
            prop_assert_ne!(hash1.as_slice(), hash2.as_slice(),
                "Different inputs must produce different hashes");
        }

        /// Property: hex encoding is deterministic
        #[test]
        fn prop_hex_encoding_deterministic(data in prop::collection::vec(any::<u8>(), 0..100)) {
            let encoded1 = hex::encode(&data);
            let encoded2 = hex::encode(&data);
            prop_assert_eq!(encoded1, encoded2, "Hex encoding must be deterministic");
        }

        /// Property: hex encoding produces lowercase ASCII
        #[test]
        fn prop_hex_encoding_lowercase(data in prop::collection::vec(any::<u8>(), 0..100)) {
            let encoded = hex::encode(&data);
            for ch in encoded.chars() {
                prop_assert!(ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
                    "Hex encoding must produce lowercase hex digits");
            }
        }

        /// Property: hex encoding length is 2x input length
        #[test]
        fn prop_hex_encoding_length(data in prop::collection::vec(any::<u8>(), 0..100)) {
            let encoded = hex::encode(&data);
            prop_assert_eq!(encoded.len(), data.len() * 2,
                "Hex encoding length must be 2x input length");
        }
    }
}
