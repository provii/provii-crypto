// Circuit constraint code: arithmetic on Scalar field elements is inherent
// to the ZK constraint system and cannot overflow at runtime.
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

//! RedJubjub verification gadget (fixed, byte-faithful hashing)
//!
//! CRITICAL FIX: Ensure scalar field handling matches off-circuit exactly
//! This version includes comprehensive debugging to catch any remaining issues

use bellman::gadgets::boolean::Boolean;
use bellman::{ConstraintSystem, SynthesisError};
use bls12_381::Scalar;
use group::Group;
use jubjub;

// Import Edwards point impl from sapling_ecc
use super::sapling_ecc::EdwardsPoint;

// ===== Types =====

/// RedJubjub verification key - a point on the Jubjub curve
#[derive(Clone)]
pub struct RJVerificationKey {
    point: EdwardsPoint,
    // Raw 32-byte compressed encoding (Y with sign(X) in MSB), kept as constant bits
    vk_bytes_bits: Vec<Boolean>,
}

/// RedJubjub signature - R (point) and s (scalar bits)
#[derive(Clone)]
pub struct RJSignature {
    r_point: EdwardsPoint,
    s_bytes_bits: Vec<Boolean>,
    // Raw 32-byte compressed encoding of R, kept as constant bits
    r_bytes_bits: Vec<Boolean>,
}

/// Get VK bytes as bits for hashing (original raw encoding)
pub fn get_vk_bytes_bits<CS: ConstraintSystem<Scalar>>(
    _cs: CS,
    vk: &RJVerificationKey,
) -> Result<Vec<Boolean>, SynthesisError> {
    Ok(vk.vk_bytes_bits.clone())
}

// ===== Public API =====

pub fn alloc_vk<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    vk_bytes32: Option<&[u8; 32]>,
) -> Result<RJVerificationKey, SynthesisError> {
    use jubjub::{AffinePoint, ExtendedPoint};

    let (point, vk_bits_raw) = if let Some(bytes) = vk_bytes32 {
        // Parse and validate the point
        let affine: AffinePoint =
            Option::from(AffinePoint::from_bytes(*bytes)).ok_or(SynthesisError::Unsatisfiable)?;

        let p = EdwardsPoint::witness(
            cs.namespace(|| "allocate_vk_point"),
            Some(ExtendedPoint::from(affine)),
        )?;

        // Not small order
        p.assert_not_small_order(cs.namespace(|| "vk_not_small_order"))?;

        // Raw bits as WITNESS BITS (not constants) - THIS IS THE FIX
        let raw_bits = super::bits::alloc_bytes_witness_fixed(
            cs.namespace(|| "vk_original_encoding_bits"),
            Some(bytes),
            32,
        )?;

        (p, raw_bits)
    } else {
        // Param-gen: witness variables without assignments for the bytes
        let p = EdwardsPoint::witness(
            cs.namespace(|| "allocate_vk_point"),
            Some(ExtendedPoint::generator()),
        )?;
        p.assert_not_small_order(cs.namespace(|| "vk_not_small_order"))?;

        // Allocate witness bits WITHOUT values for param gen - THIS IS THE FIX
        let raw_bits = super::bits::alloc_bytes_witness_fixed(
            cs.namespace(|| "vk_original_encoding_bits"),
            None,
            32,
        )?;
        (p, raw_bits)
    };

    // Constrain point encoding to match the allocated byte bits
    let repr_bits = point.repr(cs.namespace(|| "vk_encoding_repr"))?;
    super::bits::enforce_bits_equal(
        cs.namespace(|| "vk_encoding_constraint"),
        &repr_bits,
        &vk_bits_raw,
    )?;

    Ok(RJVerificationKey {
        point,
        vk_bytes_bits: vk_bits_raw,
    })
}

/// Allocate a RedJubjub signature (R,s) with validation
pub fn alloc_sig<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    sig_bytes64: Option<&[u8; 64]>,
) -> Result<RJSignature, SynthesisError> {
    use jubjub::{AffinePoint, ExtendedPoint, Fr};

    let (r_point, s_bits_raw, r_bits_raw) = if let Some(bytes) = sig_bytes64 {
        // R (first 32), s (last 32)
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&bytes[0..32]);
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);

        let r_affine_val: AffinePoint =
            Option::from(AffinePoint::from_bytes(r_bytes)).ok_or(SynthesisError::Unsatisfiable)?;
        // Validate s_fr is a valid scalar (discard value; only bytes are used as witness bits)
        let _s_fr: Fr =
            Option::from(Fr::from_bytes(&s_bytes)).ok_or(SynthesisError::Unsatisfiable)?;

        let r_point = EdwardsPoint::witness(
            cs.namespace(|| "allocate_sig_r"),
            Some(ExtendedPoint::from(r_affine_val)),
        )?;

        // Not small order
        r_point.assert_not_small_order(cs.namespace(|| "r_not_small_order"))?;

        // Keep raw R bytes as WITNESS BITS
        let r_bits_raw = super::bits::alloc_bytes_witness_fixed(
            cs.namespace(|| "r_original_encoding_bits"),
            Some(&r_bytes),
            32,
        )?;

        // Allocate s as witness bits (constrained by alloc)
        let s_bits_raw = super::bits::alloc_bytes_witness_fixed(
            cs.namespace(|| "s_original_encoding_bits"),
            Some(&s_bytes),
            32,
        )?;

        (r_point, s_bits_raw, r_bits_raw)
    } else {
        // Param-gen: witness vars without assignments for R bytes
        let r_point = EdwardsPoint::witness(
            cs.namespace(|| "allocate_sig_r"),
            Some(ExtendedPoint::generator()),
        )?;
        r_point.assert_not_small_order(cs.namespace(|| "r_not_small_order"))?;

        // Allocate witness bits WITHOUT values for param gen
        let r_bits_raw = super::bits::alloc_bytes_witness_fixed(
            cs.namespace(|| "r_original_encoding_bits"),
            None,
            32,
        )?;

        let s_bits_raw = super::bits::alloc_bytes_witness_fixed(
            cs.namespace(|| "s_original_encoding_bits"),
            None,
            32,
        )?;

        (r_point, s_bits_raw, r_bits_raw)
    };

    // Constrain R point encoding to match the allocated byte bits
    let r_repr_bits = r_point.repr(cs.namespace(|| "r_encoding_repr"))?;
    super::bits::enforce_bits_equal(
        cs.namespace(|| "r_encoding_constraint"),
        &r_repr_bits,
        &r_bits_raw,
    )?;

    Ok(RJSignature {
        r_point,
        s_bytes_bits: s_bits_raw,
        r_bytes_bits: r_bits_raw,
    })
}

/// Verify a RedJubjub signature with Provii domain separation
pub fn verify<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    vk: &RJVerificationKey,
    sig: &RJSignature,
    prehash_bits256: &[Boolean],
) -> Result<(), SynthesisError> {
    verify_with_personalization(
        cs,
        vk,
        sig,
        prehash_bits256,
        provii_crypto_commons::REDJUBJUB_PERSONALIZATION,
    )
}

/// Verify with custom 8-byte personalization
pub fn verify_with_personalization<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    vk: &RJVerificationKey,
    sig: &RJSignature,
    prehash_bits256: &[Boolean],
    personalization: &[u8; 8],
) -> Result<(), SynthesisError> {
    if prehash_bits256.len() != 256 {
        return Err(SynthesisError::Unsatisfiable);
    }

    // === 1) Build challenge preimage from RAW encodings: R || VK || prehash ===
    let mut challenge_preimage: Vec<Boolean> = Vec::with_capacity(32 * 8 * 2 + 256);

    // R (raw input bytes)
    challenge_preimage.extend_from_slice(&sig.r_bytes_bits);
    // VK (raw input bytes)
    challenge_preimage.extend_from_slice(&vk.vk_bytes_bits);
    // Message prehash (256 bits)
    challenge_preimage.extend_from_slice(prehash_bits256);

    // === 2) Hash with Blake2s (gadget applies personalization) ===
    let challenge_bits = bellman::gadgets::blake2s::blake2s(
        cs.namespace(|| "compute_challenge"),
        &challenge_preimage,
        personalization,
    )?;

    // === 3) Compute [s]B and [c]VK using constrained bit multiplication ===
    // All inputs are constrained: s_bytes_bits from alloc, challenge_bits from Blake2s
    let base_point = get_generator_point(cs.namespace(|| "get_base_point"))?;

    let s_times_b = base_point.mul(cs.namespace(|| "s_times_base"), &sig.s_bytes_bits)?;

    let c_times_vk = vk
        .point
        .mul(cs.namespace(|| "c_times_vk"), &challenge_bits)?;

    let r_plus_c_vk = sig
        .r_point
        .add(cs.namespace(|| "r_plus_c_vk"), &c_times_vk)?;

    // === 5) Enforce equality ===
    enforce_points_equal(cs.namespace(|| "verify_equation"), &s_times_b, &r_plus_c_vk)?;

    Ok(())
}

/// Get the RedJubjub spend base point (matches off-circuit signing)
fn get_generator_point<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
) -> Result<EdwardsPoint, SynthesisError> {
    // These are the exact bytes the off-circuit code uses
    const SPENDING_KEY_GEN_BYTES: [u8; 32] = [
        0x30, 0xb5, 0xf2, 0xaa, 0xad, 0x32, 0x56, 0x30, 0xbc, 0xdd, 0xdb, 0xce, 0x4d, 0x67, 0x65,
        0x6d, 0x05, 0xfd, 0x1c, 0xc2, 0xd0, 0x37, 0xbb, 0x53, 0x75, 0xb6, 0xe9, 0x6d, 0x9e, 0x01,
        0xa1, 0x57,
    ];

    // Parse the point from bytes
    use jubjub::{AffinePoint, ExtendedPoint};
    // SAFETY: SPENDING_KEY_GEN_BYTES is the Sapling spending key generator,
    // a known-valid AffinePoint on the Jubjub curve (from Zcash spec).
    #[allow(clippy::expect_used)]
    let affine: AffinePoint = Option::from(AffinePoint::from_bytes(SPENDING_KEY_GEN_BYTES))
        .expect("BUG: mathematically guaranteed generator point");

    // Allocate as a constant point in the circuit
    let generator = EdwardsPoint::witness(
        cs.namespace(|| "generator_point"),
        Some(ExtendedPoint::from(affine)),
    )?;

    // Pin generator coordinates to known constants
    let expected_u = affine.get_u();
    let expected_v = affine.get_v();
    cs.enforce(
        || "generator_u_is_constant",
        |lc| lc + generator.get_u().get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + (expected_u, CS::one()),
    );
    cs.enforce(
        || "generator_v_is_constant",
        |lc| lc + generator.get_v().get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + (expected_v, CS::one()),
    );

    Ok(generator)
}

/// Enforce equality of two Edwards points by matching (u,v) coordinates
fn enforce_points_equal<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    p1: &EdwardsPoint,
    p2: &EdwardsPoint,
) -> Result<(), SynthesisError> {
    // u equality
    cs.enforce(
        || "u_equality",
        |lc| lc + p1.get_u().get_variable() - p2.get_u().get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );

    // v equality
    cs.enforce(
        || "v_equality",
        |lc| lc + p1.get_v().get_variable() - p2.get_v().get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellman::gadgets::test::TestConstraintSystem;
    use proptest::prelude::*;

    // ========================================================================
    // HELPER FUNCTIONS FOR TEST SETUP
    // ========================================================================

    /// Generate a valid keypair using crypto-sig-redjubjub
    fn generate_test_keypair() -> ([u8; 32], [u8; 32]) {
        use provii_crypto_sig_redjubjub::generate_keypair;
        let (sk, vk) = generate_keypair();
        (*sk, vk)
    }

    /// Sign a credential and return (signature, message_hash_that_was_signed)
    /// The message hash is what should be passed to the circuit as prehash_bits256
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn sign_and_get_hash(c: &[u8; 32], sk_bytes: &[u8; 32]) -> ([u8; 64], [u8; 32]) {
        use blake2::Digest;
        use provii_crypto_commons::{cred_v2_prehash_bytes, CredMsgV2};
        use provii_crypto_sig_redjubjub::sign_cred_v2;

        // Create a test credential
        let cred = CredMsgV2 {
            v: 2,
            kid: "test-circuit-key".to_string(),
            c: *c,
            iat: 1700000000,
            exp: 1800000000,
            schema: "test-schema".to_string(),
        };

        // Compute the hash that will be signed (same as sign_cred_v2 does internally)
        let prehash =
            cred_v2_prehash_bytes(cred.v, &cred.kid, &cred.c, cred.iat, cred.exp, &cred.schema)
                .expect("test credential fields are within 255-byte limit");

        let mut h = blake2::Blake2s256::new();
        h.update(&prehash);
        let hash_bytes: [u8; 32] = h.finalize().into();

        // Sign the credential
        let sig = sign_cred_v2(&cred, sk_bytes).unwrap();

        (sig, hash_bytes)
    }

    /// Convert message bytes to bit vector (little-endian)
    fn bytes_to_bits_le(bytes: &[u8]) -> Vec<Boolean> {
        let mut bits = Vec::with_capacity(bytes.len() * 8);
        for byte in bytes {
            for i in 0..8 {
                let bit = (byte >> i) & 1 == 1;
                bits.push(Boolean::constant(bit));
            }
        }
        bits
    }

    /// Small scalar in canonical form (for edge cases)
    fn small_scalar_bytes(val: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        let mut x = val;
        for byte in b.iter_mut().take(8) {
            *byte = (x & 0xff) as u8;
            x >>= 8;
        }
        b
    }

    // ========================================================================
    // VK ALLOCATION TESTS (alloc_vk)
    // ========================================================================

    #[test]
    fn test_alloc_vk_valid_key() -> Result<(), Box<dyn std::error::Error>> {
        let (_, vk_bytes) = generate_test_keypair();

        let mut cs = TestConstraintSystem::new();
        let result = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes));

        assert!(result.is_ok(), "Valid VK should allocate successfully");
        assert!(cs.is_satisfied(), "Constraints should be satisfied");
        Ok(())
    }

    #[test]
    fn test_alloc_vk_preserves_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (_, vk_bytes) = generate_test_keypair();

        let mut cs = TestConstraintSystem::new();
        let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;

        // Verify that the raw bytes are preserved
        assert_eq!(vk.vk_bytes_bits.len(), 32 * 8, "Should have 256 bits");

        // Reconstruct bytes from bits
        let mut reconstructed = [0u8; 32];
        for (i, bit) in vk.vk_bytes_bits.iter().enumerate() {
            if bit.get_value() == Some(true) {
                reconstructed[i / 8] |= 1 << (i % 8);
            }
        }

        assert_eq!(reconstructed, vk_bytes, "Raw bytes should be preserved");
        Ok(())
    }

    #[test]
    fn test_alloc_vk_none_witness() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let result = alloc_vk(cs.namespace(|| "vk"), None);

        // TestConstraintSystem requires witness values for bits allocation
        // In real param gen, None would work, but TestCS needs values
        // So this will fail with TestConstraintSystem
        assert!(
            result.is_err() || !cs.is_satisfied(),
            "TestCS requires witness values, so None should fail or be unsatisfied"
        );
        Ok(())
    }

    #[test]
    fn test_alloc_vk_invalid_point_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let invalid_vk = [0u8; 32];

        let mut cs = TestConstraintSystem::new();
        let result = alloc_vk(cs.namespace(|| "vk"), Some(&invalid_vk));

        assert!(result.is_err(), "All zeros is not a valid point");
        Ok(())
    }

    #[test]
    fn test_alloc_vk_invalid_point_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        let invalid_vk = [0xFF; 32];

        let mut cs = TestConstraintSystem::new();
        let result = alloc_vk(cs.namespace(|| "vk"), Some(&invalid_vk));

        assert!(result.is_err(), "All ones is not a valid point");
        Ok(())
    }

    #[test]
    fn test_alloc_vk_multiple_valid_keys() -> Result<(), Box<dyn std::error::Error>> {
        // Test with different valid keys
        for _ in 0..5 {
            let (_, vk_bytes) = generate_test_keypair();

            let mut cs = TestConstraintSystem::new();
            let result = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes));

            assert!(result.is_ok());
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    #[test]
    fn test_alloc_vk_deterministic_with_same_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (_, vk_bytes) = generate_test_keypair();

        let mut cs1 = TestConstraintSystem::new();
        let vk1 = alloc_vk(cs1.namespace(|| "vk"), Some(&vk_bytes))?;

        let mut cs2 = TestConstraintSystem::new();
        let vk2 = alloc_vk(cs2.namespace(|| "vk"), Some(&vk_bytes))?;

        // Points should have same values
        assert_eq!(vk1.point.get_u().get_value(), vk2.point.get_u().get_value());
        assert_eq!(vk1.point.get_v().get_value(), vk2.point.get_v().get_value());
        Ok(())
    }

    #[test]
    fn test_alloc_vk_different_keys_different_points() -> Result<(), Box<dyn std::error::Error>> {
        let (_, vk1_bytes) = generate_test_keypair();
        let (_, vk2_bytes) = generate_test_keypair();

        let mut cs1 = TestConstraintSystem::new();
        let vk1 = alloc_vk(cs1.namespace(|| "vk"), Some(&vk1_bytes))?;

        let mut cs2 = TestConstraintSystem::new();
        let vk2 = alloc_vk(cs2.namespace(|| "vk"), Some(&vk2_bytes))?;

        // Points should be different
        assert_ne!(vk1.point.get_u().get_value(), vk2.point.get_u().get_value());
        Ok(())
    }

    #[test]
    fn test_alloc_vk_point_on_curve() -> Result<(), Box<dyn std::error::Error>> {
        let (_, vk_bytes) = generate_test_keypair();

        let mut cs = TestConstraintSystem::new();
        let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;

        // If allocation succeeds and constraints are satisfied, point is on curve
        assert!(cs.is_satisfied());

        // The point should have valid coordinates
        assert!(vk.point.get_u().get_value().is_some());
        assert!(vk.point.get_v().get_value().is_some());
        Ok(())
    }

    // ========================================================================
    // SIGNATURE ALLOCATION TESTS (alloc_sig)
    // ========================================================================

    #[test]
    fn test_alloc_sig_valid_signature() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_test_keypair();
        let commitment = [42u8; 32];
        let (sig_bytes, _) = sign_and_get_hash(&commitment, &sk_bytes);

        let mut cs = TestConstraintSystem::new();
        let result = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes));

        assert!(
            result.is_ok(),
            "Valid signature should allocate successfully"
        );
        assert!(cs.is_satisfied(), "Constraints should be satisfied");
        Ok(())
    }

    #[test]
    fn test_alloc_sig_preserves_r_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_test_keypair();
        let commitment = [123u8; 32];
        let (sig_bytes, _) = sign_and_get_hash(&commitment, &sk_bytes);

        let mut cs = TestConstraintSystem::new();
        let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes))?;

        // Verify R bytes are preserved
        assert_eq!(sig.r_bytes_bits.len(), 32 * 8, "Should have 256 bits for R");

        // Reconstruct R bytes
        let mut reconstructed_r = [0u8; 32];
        for (i, bit) in sig.r_bytes_bits.iter().enumerate() {
            if bit.get_value() == Some(true) {
                reconstructed_r[i / 8] |= 1 << (i % 8);
            }
        }

        let expected_r = &sig_bytes[0..32];
        assert_eq!(&reconstructed_r, expected_r, "R bytes should be preserved");
        Ok(())
    }

    #[test]
    fn test_alloc_sig_s_bytes_bits_correct() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_test_keypair();
        let commitment = [77u8; 32];
        let (sig_bytes, _) = sign_and_get_hash(&commitment, &sk_bytes);

        let mut cs = TestConstraintSystem::new();
        let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes))?;

        // s_bytes_bits should have 256 bits (32 bytes)
        assert_eq!(sig.s_bytes_bits.len(), 256);
        // All bits should have values
        assert!(sig.s_bytes_bits.iter().all(|b| b.get_value().is_some()));
        Ok(())
    }

    #[test]
    fn test_alloc_sig_none_witness() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let result = alloc_sig(cs.namespace(|| "sig"), None);

        // TestConstraintSystem requires witness values for bits allocation
        // In real param gen, None would work, but TestCS needs values
        // So this will fail with TestConstraintSystem
        assert!(
            result.is_err() || !cs.is_satisfied(),
            "TestCS requires witness values, so None should fail or be unsatisfied"
        );
        Ok(())
    }

    #[test]
    fn test_alloc_sig_invalid_r_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let mut invalid_sig = [0u8; 64];
        // R is all zeros (invalid), s is valid small scalar
        invalid_sig[32..].copy_from_slice(&small_scalar_bytes(1));

        let mut cs = TestConstraintSystem::new();
        let result = alloc_sig(cs.namespace(|| "sig"), Some(&invalid_sig));

        assert!(result.is_err(), "Invalid R should fail");
        Ok(())
    }

    #[test]
    fn test_alloc_sig_invalid_r_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        let invalid_sig = [0xFF; 64];

        let mut cs = TestConstraintSystem::new();
        let result = alloc_sig(cs.namespace(|| "sig"), Some(&invalid_sig));

        assert!(result.is_err(), "Invalid R (all ones) should fail");
        Ok(())
    }

    #[test]
    fn test_alloc_sig_invalid_s_non_canonical() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_test_keypair();
        let commitment = [99u8; 32];
        let (mut sig_bytes, _) = sign_and_get_hash(&commitment, &sk_bytes);

        // Corrupt s to be non-canonical
        sig_bytes[32..].copy_from_slice(&[0xFF; 32]);

        let mut cs = TestConstraintSystem::new();
        let result = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes));

        assert!(result.is_err(), "Non-canonical s should fail");
        Ok(())
    }

    #[test]
    fn test_alloc_sig_multiple_valid_signatures() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_test_keypair();

        for i in 0..5 {
            let mut commitment = [0u8; 32];
            commitment[0] = i;

            let (sig_bytes, _) = sign_and_get_hash(&commitment, &sk_bytes);

            let mut cs = TestConstraintSystem::new();
            let result = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes));

            assert!(result.is_ok());
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    #[test]
    fn test_alloc_sig_deterministic_with_same_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_test_keypair();
        let commitment = [111u8; 32];
        let (sig_bytes, _) = sign_and_get_hash(&commitment, &sk_bytes);

        let mut cs1 = TestConstraintSystem::new();
        let sig1 = alloc_sig(cs1.namespace(|| "sig"), Some(&sig_bytes))?;

        let mut cs2 = TestConstraintSystem::new();
        let sig2 = alloc_sig(cs2.namespace(|| "sig"), Some(&sig_bytes))?;

        // R points should match
        assert_eq!(
            sig1.r_point.get_u().get_value(),
            sig2.r_point.get_u().get_value()
        );
        assert_eq!(
            sig1.r_point.get_v().get_value(),
            sig2.r_point.get_v().get_value()
        );

        // s_bytes_bits should match
        for (b1, b2) in sig1.s_bytes_bits.iter().zip(sig2.s_bytes_bits.iter()) {
            assert_eq!(b1.get_value(), b2.get_value());
        }
        Ok(())
    }

    // ========================================================================
    // VK BYTES EXTRACTION TESTS (get_vk_bytes_bits)
    // ========================================================================

    #[test]
    fn test_get_vk_bytes_bits_returns_correct_length() -> Result<(), Box<dyn std::error::Error>> {
        let (_, vk_bytes) = generate_test_keypair();

        let mut cs = TestConstraintSystem::new();
        let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;

        let bits = get_vk_bytes_bits(cs.namespace(|| "get_bits"), &vk)?;

        assert_eq!(bits.len(), 256, "Should return 256 bits");
        Ok(())
    }

    #[test]
    fn test_get_vk_bytes_bits_preserves_original_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (_, vk_bytes) = generate_test_keypair();

        let mut cs = TestConstraintSystem::new();
        let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;

        let bits = get_vk_bytes_bits(cs.namespace(|| "get_bits"), &vk)?;

        // Reconstruct bytes
        let mut reconstructed = [0u8; 32];
        for (i, bit) in bits.iter().enumerate() {
            if bit.get_value() == Some(true) {
                reconstructed[i / 8] |= 1 << (i % 8);
            }
        }

        assert_eq!(reconstructed, vk_bytes);
        Ok(())
    }

    #[test]
    fn test_get_vk_bytes_bits_multiple_keys() -> Result<(), Box<dyn std::error::Error>> {
        for _ in 0..5 {
            let (_, vk_bytes) = generate_test_keypair();

            let mut cs = TestConstraintSystem::new();
            let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;

            let bits = get_vk_bytes_bits(cs.namespace(|| "get_bits"), &vk)?;

            assert_eq!(bits.len(), 256);
        }
        Ok(())
    }

    // ========================================================================
    // SIGNATURE VERIFICATION TESTS (verify & verify_with_personalization)
    // ========================================================================

    #[test]
    fn test_verify_valid_signature_passes() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_test_keypair();
        let commitment = [42u8; 32];
        let (sig_bytes, msg_hash) = sign_and_get_hash(&commitment, &sk_bytes);

        let mut cs = TestConstraintSystem::new();
        let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;
        let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes))?;
        let msg_bits = bytes_to_bits_le(&msg_hash);

        let result = verify(cs.namespace(|| "verify"), &vk, &sig, &msg_bits);

        assert!(result.is_ok(), "Valid signature should verify");
        assert!(cs.is_satisfied(), "Constraints should be satisfied");
        Ok(())
    }

    #[test]
    fn test_verify_invalid_signature_fails() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_test_keypair();
        let commitment = [42u8; 32];
        let (sig_bytes, msg_hash) = sign_and_get_hash(&commitment, &sk_bytes);

        // Corrupt s component (bytes 32..64) while keeping R intact
        let mut bad_sig = sig_bytes;
        bad_sig[40] ^= 0xFF;

        let mut cs = TestConstraintSystem::new();
        let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;
        let msg_bits = bytes_to_bits_le(&msg_hash);

        match alloc_sig(cs.namespace(|| "sig"), Some(&bad_sig)) {
            Ok(sig) => {
                let result = verify(cs.namespace(|| "verify"), &vk, &sig, &msg_bits);
                assert!(result.is_ok());
                assert!(
                    !cs.is_satisfied(),
                    "Corrupted signature should fail constraints"
                );
            }
            Err(_) => {
                // Non-canonical scalar rejected at allocation, also a valid failure mode
            }
        }
        Ok(())
    }

    #[test]
    fn test_verify_wrong_message_fails() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_test_keypair();
        let commitment1 = [42u8; 32];
        let commitment2 = [99u8; 32];

        // Sign commitment1, try to verify with commitment2's hash
        let (sig_bytes, _) = sign_and_get_hash(&commitment1, &sk_bytes);
        let (_, msg_hash2) = sign_and_get_hash(&commitment2, &sk_bytes);

        let mut cs = TestConstraintSystem::new();
        let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;
        let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes))?;
        let msg2_bits = bytes_to_bits_le(&msg_hash2);

        let result = verify(cs.namespace(|| "verify"), &vk, &sig, &msg2_bits);

        // Verification will succeed but constraints won't be satisfied
        assert!(result.is_ok());
        assert!(!cs.is_satisfied(), "Wrong message should fail constraints");
        Ok(())
    }

    #[test]
    fn test_verify_wrong_vk_fails() -> Result<(), Box<dyn std::error::Error>> {
        let (sk1_bytes, _vk1_bytes) = generate_test_keypair();
        let (_sk2_bytes, vk2_bytes) = generate_test_keypair();

        let commitment = [42u8; 32];

        // Sign with sk1, verify with vk2
        let (sig_bytes, msg_hash) = sign_and_get_hash(&commitment, &sk1_bytes);

        let mut cs = TestConstraintSystem::new();
        let vk2 = alloc_vk(cs.namespace(|| "vk"), Some(&vk2_bytes))?;
        let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes))?;
        let msg_bits = bytes_to_bits_le(&msg_hash);

        let result = verify(cs.namespace(|| "verify"), &vk2, &sig, &msg_bits);

        assert!(result.is_ok());
        assert!(!cs.is_satisfied(), "Wrong VK should fail constraints");
        Ok(())
    }

    #[test]
    fn test_verify_with_personalization_default() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_test_keypair();
        let commitment = [77u8; 32];
        let (sig_bytes, msg_hash) = sign_and_get_hash(&commitment, &sk_bytes);

        let mut cs = TestConstraintSystem::new();
        let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;
        let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes))?;
        let msg_bits = bytes_to_bits_le(&msg_hash);

        let result = verify_with_personalization(
            cs.namespace(|| "verify"),
            &vk,
            &sig,
            &msg_bits,
            b"ProviiRJ",
        );

        assert!(result.is_ok());
        assert!(cs.is_satisfied());
        Ok(())
    }

    #[test]
    fn test_verify_multiple_valid_signatures() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_test_keypair();

        for i in 0..5 {
            let mut commitment = [0u8; 32];
            commitment[0] = i;

            let (sig_bytes, msg_hash) = sign_and_get_hash(&commitment, &sk_bytes);

            let mut cs = TestConstraintSystem::new();
            let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;
            let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes))?;
            let msg_bits = bytes_to_bits_le(&msg_hash);

            let result = verify(cs.namespace(|| "verify"), &vk, &sig, &msg_bits);

            assert!(result.is_ok());
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    #[test]
    fn test_verify_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_test_keypair();
        let commitment = [123u8; 32];
        let (sig_bytes, msg_hash) = sign_and_get_hash(&commitment, &sk_bytes);

        // Verify twice with same inputs
        for _ in 0..2 {
            let mut cs = TestConstraintSystem::new();
            let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;
            let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes))?;
            let msg_bits = bytes_to_bits_le(&msg_hash);

            let result = verify(cs.namespace(|| "verify"), &vk, &sig, &msg_bits);

            assert!(result.is_ok());
            assert!(cs.is_satisfied());
        }
        Ok(())
    }

    // ========================================================================
    // GENERATOR POINT TESTS (get_generator_point)
    // ========================================================================

    #[test]
    fn test_get_generator_point_on_curve() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let gen = get_generator_point(cs.namespace(|| "gen"))?;

        assert!(cs.is_satisfied());
        assert!(gen.get_u().get_value().is_some());
        assert!(gen.get_v().get_value().is_some());
        Ok(())
    }

    #[test]
    fn test_get_generator_point_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs1 = TestConstraintSystem::new();
        let gen1 = get_generator_point(cs1.namespace(|| "gen"))?;

        let mut cs2 = TestConstraintSystem::new();
        let gen2 = get_generator_point(cs2.namespace(|| "gen"))?;

        // Generator should be the same
        assert_eq!(gen1.get_u().get_value(), gen2.get_u().get_value());
        assert_eq!(gen1.get_v().get_value(), gen2.get_v().get_value());
        Ok(())
    }

    #[test]
    fn test_get_generator_point_correct_value() -> Result<(), Box<dyn std::error::Error>> {
        let mut cs = TestConstraintSystem::new();
        let gen = get_generator_point(cs.namespace(|| "gen"))?;

        // Verify the generator is the expected SPENDING_KEY_GENERATOR
        use jubjub::AffinePoint;

        const SPENDING_KEY_GEN_BYTES: [u8; 32] = [
            0x30, 0xb5, 0xf2, 0xaa, 0xad, 0x32, 0x56, 0x30, 0xbc, 0xdd, 0xdb, 0xce, 0x4d, 0x67,
            0x65, 0x6d, 0x05, 0xfd, 0x1c, 0xc2, 0xd0, 0x37, 0xbb, 0x53, 0x75, 0xb6, 0xe9, 0x6d,
            0x9e, 0x01, 0xa1, 0x57,
        ];

        let expected_affine: AffinePoint =
            Option::from(AffinePoint::from_bytes(SPENDING_KEY_GEN_BYTES))
                .ok_or("invalid generator point")?;
        let expected_u = expected_affine.get_u();
        let expected_v = expected_affine.get_v();

        assert_eq!(gen.get_u().get_value(), Some(expected_u));
        assert_eq!(gen.get_v().get_value(), Some(expected_v));
        Ok(())
    }

    // ========================================================================
    // PERSONALIZATION VARIATION TESTS (PC-102)
    // ========================================================================

    #[test]
    fn test_verify_with_different_personalization_synthesises(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // PC-102: Verify that verify_with_personalization works with a different
        // 8-byte personalization tag. The circuit should synthesise without error,
        // but constraints will NOT be satisfied because the off-circuit signing
        // used "ProviiRJ" while the circuit uses a different tag.
        let (sk_bytes, vk_bytes) = generate_test_keypair();
        let commitment = [55u8; 32];
        let (sig_bytes, msg_hash) = sign_and_get_hash(&commitment, &sk_bytes);

        let alt_personalization: &[u8; 8] = b"\x00\x00\x00\x00\x00\x00\x00\x00"; // all zeros

        let mut cs = TestConstraintSystem::new();
        let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;
        let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes))?;
        let msg_bits = bytes_to_bits_le(&msg_hash);

        // Circuit synthesises without error (no SynthesisError)
        let result = verify_with_personalization(
            cs.namespace(|| "verify"),
            &vk,
            &sig,
            &msg_bits,
            alt_personalization,
        );
        assert!(
            result.is_ok(),
            "Synthesis must succeed even with different personalization"
        );

        // But constraints should NOT be satisfied because the challenge hash
        // differs from what the off-circuit signer produced with "ProviiRJ"
        assert!(
            !cs.is_satisfied(),
            "Different personalization must produce unsatisfied constraints"
        );
        Ok(())
    }

    #[test]
    fn test_verify_with_personalization_another_valid_tag() -> Result<(), Box<dyn std::error::Error>>
    {
        // PC-102: A second distinct personalization tag to confirm the circuit
        // handles arbitrary 8-byte tags without synthesis errors.
        let (sk_bytes, vk_bytes) = generate_test_keypair();
        let commitment = [88u8; 32];
        let (sig_bytes, msg_hash) = sign_and_get_hash(&commitment, &sk_bytes);

        let alt_personalization: &[u8; 8] = b"TestTag!";

        let mut cs = TestConstraintSystem::new();
        let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes))?;
        let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes))?;
        let msg_bits = bytes_to_bits_le(&msg_hash);

        let result = verify_with_personalization(
            cs.namespace(|| "verify"),
            &vk,
            &sig,
            &msg_bits,
            alt_personalization,
        );
        assert!(
            result.is_ok(),
            "Synthesis must succeed with 'TestTag!' personalization"
        );
        assert!(
            !cs.is_satisfied(),
            "Mismatched personalization must fail constraint satisfaction"
        );
        Ok(())
    }

    // ========================================================================
    // PROPERTY-BASED TESTS
    // ========================================================================

    proptest! {
        /// Property: VK allocation is deterministic
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_alloc_vk_deterministic(_seed in any::<u64>()) {
            let (_, vk_bytes) = generate_test_keypair();

            let mut cs1 = TestConstraintSystem::new();
            let vk1 = alloc_vk(cs1.namespace(|| "vk"), Some(&vk_bytes));

            let mut cs2 = TestConstraintSystem::new();
            let vk2 = alloc_vk(cs2.namespace(|| "vk"), Some(&vk_bytes));

            prop_assert!(vk1.is_ok() && vk2.is_ok());

            let vk1 = vk1.unwrap();
            let vk2 = vk2.unwrap();

            prop_assert_eq!(vk1.point.get_u().get_value(), vk2.point.get_u().get_value());
            prop_assert_eq!(vk1.point.get_v().get_value(), vk2.point.get_v().get_value());
        }

        /// Property: Signature allocation is deterministic
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_alloc_sig_deterministic(_seed in any::<u64>(), commitment in any::<[u8; 32]>()) {
            let (sk_bytes, _) = generate_test_keypair();
            let (sig_bytes, _) = sign_and_get_hash(&commitment, &sk_bytes);

            let mut cs1 = TestConstraintSystem::new();
            let sig1 = alloc_sig(cs1.namespace(|| "sig"), Some(&sig_bytes));

            let mut cs2 = TestConstraintSystem::new();
            let sig2 = alloc_sig(cs2.namespace(|| "sig"), Some(&sig_bytes));

            prop_assert!(sig1.is_ok() && sig2.is_ok());

            let sig1 = sig1.unwrap();
            let sig2 = sig2.unwrap();

            prop_assert_eq!(sig1.r_point.get_u().get_value(), sig2.r_point.get_u().get_value());
            for (b1, b2) in sig1.s_bytes_bits.iter().zip(sig2.s_bytes_bits.iter()) {
                prop_assert_eq!(b1.get_value(), b2.get_value());
            }
        }

        /// Property: Valid signatures always verify
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_valid_signature_verifies(_seed in any::<u64>(), commitment in any::<[u8; 32]>()) {
            let (sk_bytes, vk_bytes) = generate_test_keypair();
            let (sig_bytes, msg_hash) = sign_and_get_hash(&commitment, &sk_bytes);

            let mut cs = TestConstraintSystem::new();
            let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes));
            prop_assert!(vk.is_ok());

            let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes));
            prop_assert!(sig.is_ok());

            let msg_bits = bytes_to_bits_le(&msg_hash);

            let result = verify(
                cs.namespace(|| "verify"),
                &vk.unwrap(),
                &sig.unwrap(),
                &msg_bits
            );

            prop_assert!(result.is_ok());
            prop_assert!(cs.is_satisfied(), "Valid signature must satisfy constraints");
        }

        /// Property: Different commitments produce different signatures
        #[test]
        fn prop_different_commitments_different_sigs(
            c1 in any::<[u8; 32]>(),
            c2 in any::<[u8; 32]>()
        ) {
            prop_assume!(c1 != c2);

            let (sk_bytes, _) = generate_test_keypair();

            let (sig1, _) = sign_and_get_hash(&c1, &sk_bytes);
            let (sig2, _) = sign_and_get_hash(&c2, &sk_bytes);

            prop_assert_ne!(sig1, sig2, "Different commitments must produce different signatures");
        }

        /// Property: Generator point is always the same
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_generator_deterministic(_seed in any::<u64>()) {
            let mut cs1 = TestConstraintSystem::new();
            let gen1 = get_generator_point(cs1.namespace(|| "gen"));

            let mut cs2 = TestConstraintSystem::new();
            let gen2 = get_generator_point(cs2.namespace(|| "gen"));

            prop_assert!(gen1.is_ok() && gen2.is_ok());

            let gen1 = gen1.unwrap();
            let gen2 = gen2.unwrap();

            prop_assert_eq!(gen1.get_u().get_value(), gen2.get_u().get_value());
            prop_assert_eq!(gen1.get_v().get_value(), gen2.get_v().get_value());
        }

        /// Property: VK bytes extraction preserves original bytes
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_vk_bytes_extraction_preserves_bytes(_seed in any::<u64>()) {
            let (_, vk_bytes) = generate_test_keypair();

            let mut cs = TestConstraintSystem::new();
            let vk = alloc_vk(cs.namespace(|| "vk"), Some(&vk_bytes));
            prop_assert!(vk.is_ok());

            let vk = vk.unwrap();
            let bits = get_vk_bytes_bits(cs.namespace(|| "get_bits"), &vk);
            prop_assert!(bits.is_ok());

            let bits = bits.unwrap();

            // Reconstruct bytes
            let mut reconstructed = [0u8; 32];
            for (i, bit) in bits.iter().enumerate() {
                if bit.get_value() == Some(true) {
                    reconstructed[i / 8] |= 1 << (i % 8);
                }
            }

            prop_assert_eq!(reconstructed, vk_bytes);
        }

        /// Property: Wrong VK fails verification
        #[test]
        #[allow(clippy::unwrap_used)]
        fn prop_wrong_vk_fails_verification(commitment in any::<[u8; 32]>()) {
            let (sk1_bytes, _) = generate_test_keypair();
            let (_, vk2_bytes) = generate_test_keypair();

            let (sig_bytes, msg_hash) = sign_and_get_hash(&commitment, &sk1_bytes);

            let mut cs = TestConstraintSystem::new();
            let vk2 = alloc_vk(cs.namespace(|| "vk"), Some(&vk2_bytes));
            let sig = alloc_sig(cs.namespace(|| "sig"), Some(&sig_bytes));

            prop_assert!(vk2.is_ok() && sig.is_ok());

            let msg_bits = bytes_to_bits_le(&msg_hash);

            let result = verify(
                cs.namespace(|| "verify"),
                &vk2.unwrap(),
                &sig.unwrap(),
                &msg_bits
            );

            prop_assert!(result.is_ok());
            prop_assert!(!cs.is_satisfied(), "Wrong VK must fail constraints");
        }
    }
}
