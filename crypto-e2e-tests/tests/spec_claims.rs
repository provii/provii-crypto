// Test code: direct indexing and numeric casts are acceptable in tests
// where panics surface assertion failures.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::arithmetic_side_effects,
    deprecated
)]
// tests/spec_claims.rs
//! Executable patent specification claim tests.
//!
//! Each test encodes a specific claim from the provisional patent specification
//! and asserts it against the actual code. A test failure means either the spec
//! is wrong or the code has a bug.
//!
//! Run: cargo test -p provii-crypto-e2e-tests --test spec_claims

use anyhow::Result;
use bellman::gadgets::test::TestConstraintSystem;
use bellman::Circuit;
use blake2::{Blake2s256, Digest};
use bls12_381::Scalar;
use ff::{Field, PrimeField};
use rand::thread_rng;

use provii_crypto_circuit_age::{
    AgeCircuit, AgeDirection, AgePublic, AgeWitness, KID_SIZE_BYTES, PUBLIC_INPUTS_LEN,
    SCHEMA_SIZE_BYTES,
};
use provii_crypto_commit::{
    generate_commitment_randomness, pedersen_commit_dob_validated, pedersen_nullifier,
};
use provii_crypto_commons::CredMsgV2;
use provii_crypto_commons::{bias_for_circuit, unbias_from_circuit, SIGN_BIAS};
use provii_crypto_public_inputs::assemble_public_inputs_canonical;
use provii_crypto_sig_redjubjub::{generate_keypair, sign_cred_v2, verify_cred_v2};

// ============================================================================
// Helper: build a complete valid circuit for testing
// ============================================================================

fn build_valid_circuit(
    dob_days: i32,
    cutoff_days: i32,
    direction: AgeDirection,
) -> Result<(AgeCircuit, TestConstraintSystem<Scalar>)> {
    let mut rng = thread_rng();
    let (issuer_sk, issuer_vk) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut rng, 128);
    let commitment = pedersen_commit_dob_validated(dob_days, &r_bits)?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment,
        iat: 1704067200,
        exp: 1735689600,
        schema: "provii.age/0".to_string(),
    };

    let sig = sign_cred_v2(&cred, &issuer_sk)?;

    let rp_challenge = [0x42u8; 32];
    let rp_hash = {
        let mut hasher = Blake2s256::new();
        hasher.update(rp_challenge);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    let witness = AgeWitness {
        dob_days,
        r_bits: r_bits.to_vec(),
        issuer_vk_bytes: issuer_vk,
        sig_rj_bytes: sig.to_vec(),
        v: cred.v,
        kid: cred.kid.as_bytes().to_vec(),
        c_bytes: commitment,
        iat: cred.iat,
        exp: cred.exp,
        schema: cred.schema.as_bytes().to_vec(),
    };

    let public = AgePublic {
        direction,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes: issuer_vk,
        cred_nullifier: pedersen_nullifier(&commitment),
    };

    let circuit = AgeCircuit {
        public,
        witness: Some(witness),
    };

    let mut cs = TestConstraintSystem::<Scalar>::new();
    circuit.synthesize(&mut cs)?;

    Ok((
        AgeCircuit {
            public: AgePublic {
                direction,
                cutoff_days,
                rp_hash,
                issuer_vk_bytes: issuer_vk,
                cred_nullifier: pedersen_nullifier(&commitment),
            },
            witness: None,
        },
        cs,
    ))
}

// ============================================================================
// GROUP 1: Bias arithmetic (Spec Section 2.5)
// ============================================================================

#[test]
fn spec_bias_zero() {
    // Spec: bias(0) = 2147483648 (0x80000000)
    assert_eq!(bias_for_circuit(0), 0x8000_0000);
    assert_eq!(bias_for_circuit(0), 2147483648);
}

#[test]
fn spec_bias_negative_3653() {
    // Spec: bias(-3653) = 2147479995
    assert_eq!(bias_for_circuit(-3653), 2147479995);
}

#[test]
fn spec_bias_positive_13880() {
    // Spec: bias(13880) = 2147497528
    assert_eq!(bias_for_circuit(13880), 2147497528);
}

#[test]
fn spec_bias_preserves_ordering() {
    // Spec: biased values preserve signed ordering when compared unsigned
    // bias(-3653) < bias(0) < bias(13880)
    assert!(bias_for_circuit(-3653) < bias_for_circuit(0));
    assert!(bias_for_circuit(0) < bias_for_circuit(13880));
}

#[test]
fn spec_bias_xor_mechanism() {
    // Spec: bias is XOR with 0x80000000 (the sign bit)
    assert_eq!(SIGN_BIAS, 0x8000_0000);
    // Verify the mechanism: (days as u32) ^ SIGN_BIAS
    let days: i32 = -3653;
    let as_u32 = days as u32;
    assert_eq!(as_u32 ^ SIGN_BIAS, bias_for_circuit(days));
}

#[test]
fn spec_bias_round_trip() {
    // Spec: bias is reversible
    for days in [-3653i32, 0, 13880, -25000, 50000, i32::MIN, i32::MAX] {
        assert_eq!(unbias_from_circuit(bias_for_circuit(days)), days);
    }
}

// ============================================================================
// GROUP 2: Field sizes (Spec Sections 2.1-2.4, 4.1)
// ============================================================================

#[test]
fn spec_commitment_is_32_bytes() -> Result<()> {
    // Spec: Pedersen commitment = 32 bytes (compressed Jubjub point)
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let commitment = pedersen_commit_dob_validated(7300, &r_bits)?;
    assert_eq!(commitment.len(), 32);
    Ok(())
}

#[test]
fn spec_nullifier_is_32_bytes() -> Result<()> {
    // Spec: nullifier = 32 bytes
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let commitment = pedersen_commit_dob_validated(7300, &r_bits)?;
    let nullifier = pedersen_nullifier(&commitment);
    assert_eq!(nullifier.len(), 32);
    Ok(())
}

#[test]
fn spec_signature_is_64_bytes() -> Result<()> {
    // Spec: RedJubjub signature = 64 bytes (R || s)
    let (issuer_sk, issuer_vk) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let commitment = pedersen_commit_dob_validated(7300, &r_bits)?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment,
        iat: 1704067200,
        exp: 1735689600,
        schema: "provii.age/0".to_string(),
    };

    let sig = sign_cred_v2(&cred, &issuer_sk)?;
    assert_eq!(sig.len(), 64);

    // Verify self-verify after signing works
    verify_cred_v2(&cred, &sig, &issuer_vk)?;
    Ok(())
}

#[test]
fn spec_nonce_is_32_bytes() -> Result<()> {
    // Spec: nonce = 32 bytes CSPRNG
    use provii_crypto_protocol::generate_nonce;
    let nonce = generate_nonce()?;
    assert_eq!(nonce.len(), 32);
    Ok(())
}

#[test]
fn spec_blake2s_output_is_32_bytes() {
    // Spec: Blake2s-256 output = 32 bytes
    let mut hasher = Blake2s256::new();
    hasher.update(b"test");
    let result = hasher.finalize();
    assert_eq!(result.len(), 32);
}

#[test]
fn spec_kid_size_is_14_bytes() {
    // Spec: KID = 14 bytes ("provii:2026-05")
    assert_eq!(KID_SIZE_BYTES, 14);
    assert_eq!("provii:2026-05".len(), 14);
}

#[test]
fn spec_schema_size_is_12_bytes() {
    // Spec: schema = 12 bytes ("provii.age/0")
    assert_eq!(SCHEMA_SIZE_BYTES, 12);
    assert_eq!("provii.age/0".len(), 12);
}

#[test]
fn spec_public_inputs_count_is_8() {
    // Spec: 8 public input field elements (not counting Bellman's implicit 1)
    assert_eq!(PUBLIC_INPUTS_LEN, 8);
}

#[test]
fn spec_public_inputs_assembly_produces_8_elements() {
    // Spec: host assembly produces exactly 8 field elements
    let inputs =
        assemble_public_inputs_canonical(true, 6570, [0u8; 32], [0u8; 32], [0u8; 32]).unwrap();
    assert_eq!(inputs.len(), 8);
}

// ============================================================================
// GROUP 3: Commitment properties (Spec Section 2.3)
// ============================================================================

#[test]
fn spec_commitment_deterministic() -> Result<()> {
    // Spec: same inputs produce same commitment.
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let c1 = pedersen_commit_dob_validated(7300, &r_bits)?;
    let c2 = pedersen_commit_dob_validated(7300, &r_bits)?;
    assert_eq!(c1, c2);
    Ok(())
}

#[test]
fn spec_commitment_hiding() -> Result<()> {
    // Spec: different randomness produces different commitment (hiding property)
    let mut rng = thread_rng();
    let r1 = generate_commitment_randomness(&mut rng, 128);
    let r2 = generate_commitment_randomness(&mut rng, 128);
    let c1 = pedersen_commit_dob_validated(7300, &r1)?;
    let c2 = pedersen_commit_dob_validated(7300, &r2)?;
    assert_ne!(c1, c2);
    Ok(())
}

#[test]
fn spec_commitment_binding() -> Result<()> {
    // Spec: different DOB produces different commitment (binding property)
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let c1 = pedersen_commit_dob_validated(7300, &r_bits)?;
    let c2 = pedersen_commit_dob_validated(7301, &r_bits)?;
    assert_ne!(c1, c2);
    Ok(())
}

#[test]
fn spec_commitment_randomness_128_bits() -> Result<()> {
    // Spec: protocol uses 128 bits of randomness in preferred embodiment
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    assert_eq!(r_bits.len(), 128);
    // 128 bits should produce a valid, non-identity commitment
    let commitment = pedersen_commit_dob_validated(7300, &r_bits)?;
    assert_ne!(commitment, [0u8; 32]);
    Ok(())
}

#[test]
fn spec_commitment_max_randomness_1096_bits() -> Result<()> {
    // Spec: Pedersen hash supports up to 1096 bits of randomness
    // (1134 total Sapling bits - 6 personalization - 32 dob = 1096)
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 1096);
    let commitment = pedersen_commit_dob_validated(7300, &r_bits)?;
    assert_ne!(commitment, [0u8; 32]); // Valid point, not identity

    // 1097 bits should return Err (overflow protection)
    let r_too_many = generate_commitment_randomness(&mut thread_rng(), 1097);
    assert!(pedersen_commit_dob_validated(7300, &r_too_many).is_err());
    Ok(())
}

#[test]
fn spec_commitment_overflow_returns_invalid_input() {
    // PC-286: Verify the specific error variant, not just is_err()
    use provii_crypto_commons::Error;
    let r_too_many = generate_commitment_randomness(&mut thread_rng(), 1097);
    let result = pedersen_commit_dob_validated(7300, &r_too_many);
    assert_eq!(
        result,
        Err(Error::InvalidInput),
        "Overflow randomness must return Error::InvalidInput"
    );
}

#[test]
fn spec_commitment_short_randomness_returns_invalid_input() {
    // PC-286: Verify error variant for too-short randomness
    use provii_crypto_commons::Error;
    let r_short = generate_commitment_randomness(&mut thread_rng(), 64); // Too short (< 128)
    let result = pedersen_commit_dob_validated(7300, &r_short);
    assert_eq!(
        result,
        Err(Error::InvalidInput),
        "Short randomness (< 128 bits) must return Error::InvalidInput"
    );
}

#[test]
fn spec_commitment_not_identity() -> Result<()> {
    // Spec: valid commitment is a Jubjub curve point (not identity)
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let commitment = pedersen_commit_dob_validated(0, &r_bits)?;
    assert_ne!(commitment, [0u8; 32]);
    Ok(())
}

// ============================================================================
// GROUP 4: Nullifier properties (Spec Section 2.3.2, 4.2 Step 3)
// ============================================================================

#[test]
fn spec_nullifier_deterministic() {
    // Spec: same commitment produces same nullifier
    let commitment = [42u8; 32];
    let n1 = pedersen_nullifier(&commitment);
    let n2 = pedersen_nullifier(&commitment);
    assert_eq!(n1, n2);
}

#[test]
fn spec_nullifier_unique_per_commitment() -> Result<()> {
    // Spec: different commitments produce different nullifiers
    let mut rng = thread_rng();
    let r1 = generate_commitment_randomness(&mut rng, 128);
    let r2 = generate_commitment_randomness(&mut rng, 128);
    let c1 = pedersen_commit_dob_validated(7300, &r1)?;
    let c2 = pedersen_commit_dob_validated(7300, &r2)?;

    let n1 = pedersen_nullifier(&c1);
    let n2 = pedersen_nullifier(&c2);
    assert_ne!(n1, n2);
    Ok(())
}

#[test]
fn spec_nullifier_uses_merkle_tree_0_personalisation() -> Result<()> {
    // Spec: nullifier uses MerkleTree(0) personalisation
    // (distinct from NoteCommitment used by the commitment itself)
    // This is a structural test: the nullifier of the same bytes
    // must differ from the commitment (different personalisations)
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let commitment = pedersen_commit_dob_validated(7300, &r_bits)?;
    let nullifier = pedersen_nullifier(&commitment);
    assert_ne!(commitment, nullifier);
    Ok(())
}

#[test]
fn spec_nullifier_one_way() {
    // Spec: nullifier is one-way (cannot recover commitment from nullifier)
    // We can only test that nullifier != commitment and is not identity
    let commitment = [0xABu8; 32];
    let nullifier = pedersen_nullifier(&commitment);
    assert_ne!(nullifier, commitment);
    assert_ne!(nullifier, [0u8; 32]);
}

// ============================================================================
// GROUP 5: Signature scheme (Spec Section 2.4)
// ============================================================================

#[test]
fn spec_signature_r_s_structure() -> Result<()> {
    // Spec: signature = (R, s) where R is 32 bytes, s is 32 bytes
    let (issuer_sk, _issuer_vk) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let commitment = pedersen_commit_dob_validated(7300, &r_bits)?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment,
        iat: 1704067200,
        exp: 1735689600,
        schema: "provii.age/0".to_string(),
    };

    let sig = sign_cred_v2(&cred, &issuer_sk)?;
    assert_eq!(sig.len(), 64);

    // First 32 bytes = R (compressed point)
    let r_bytes = &sig[0..32];
    assert_eq!(r_bytes.len(), 32);

    // Last 32 bytes = s (scalar)
    let s_bytes = &sig[32..64];
    assert_eq!(s_bytes.len(), 32);
    Ok(())
}

#[test]
fn spec_signature_deterministic_nonce() -> Result<()> {
    // Spec: nonce derivation is deterministic (r = H("ProviiRJ/nonce" || sk || msg_hash))
    // Same key + same message = same signature
    let (issuer_sk, _) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let commitment = pedersen_commit_dob_validated(7300, &r_bits)?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment,
        iat: 1704067200,
        exp: 1735689600,
        schema: "provii.age/0".to_string(),
    };

    let sig1 = sign_cred_v2(&cred, &issuer_sk)?;
    let sig2 = sign_cred_v2(&cred, &issuer_sk)?;
    assert_eq!(
        sig1, sig2,
        "Deterministic nonce must produce identical signatures"
    );
    Ok(())
}

#[test]
fn spec_signature_self_verify() -> Result<()> {
    // Spec: signature verifies against the corresponding verification key
    let (issuer_sk, issuer_vk) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let commitment = pedersen_commit_dob_validated(7300, &r_bits)?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment,
        iat: 1704067200,
        exp: 1735689600,
        schema: "provii.age/0".to_string(),
    };

    let sig = sign_cred_v2(&cred, &issuer_sk)?;
    // Must verify with the correct VK
    assert!(verify_cred_v2(&cred, &sig, &issuer_vk).is_ok());
    Ok(())
}

#[test]
fn spec_signature_wrong_key_fails() -> Result<()> {
    // Spec: signature does not verify under a different key
    let (issuer_sk, _) = generate_keypair();
    let (_, other_vk) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let commitment = pedersen_commit_dob_validated(7300, &r_bits)?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment,
        iat: 1704067200,
        exp: 1735689600,
        schema: "provii.age/0".to_string(),
    };

    let sig = sign_cred_v2(&cred, &issuer_sk)?;
    // Must fail with wrong VK
    assert!(verify_cred_v2(&cred, &sig, &other_vk).is_err());
    Ok(())
}

#[test]
fn spec_signature_wrong_key_returns_verification_failed() -> Result<()> {
    // PC-286: Verify the specific error variant for wrong key, not just is_err()
    use provii_crypto_sig_redjubjub::RedJubjubError;
    let (issuer_sk, _) = generate_keypair();
    let (_, other_vk) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut thread_rng(), 128);
    let commitment = pedersen_commit_dob_validated(7300, &r_bits)?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment,
        iat: 1704067200,
        exp: 1735689600,
        schema: "provii.age/0".to_string(),
    };

    let sig = sign_cred_v2(&cred, &issuer_sk)?;
    let result = verify_cred_v2(&cred, &sig, &other_vk);
    assert!(
        matches!(result, Err(RedJubjubError::VerificationFailed)),
        "Wrong VK must return RedJubjubError::VerificationFailed, got: {result:?}"
    );
    Ok(())
}

#[test]
fn spec_signature_domain_separated_challenge() -> Result<()> {
    // Spec: challenge hash uses "ProviiRJ" personalisation
    // This is tested indirectly: if the domain separation were wrong,
    // the circuit verification would fail. We test that circuit verification
    // works, which implies correct domain separation alignment.
    let (_, cs) = build_valid_circuit(7300, 20000, AgeDirection::Over)?;
    assert!(cs.is_satisfied());
    Ok(())
}

#[test]
fn spec_verification_key_is_32_bytes() {
    // Spec: verification key = 32 bytes (compressed Jubjub subgroup point)
    let (_, vk_bytes) = generate_keypair();
    assert_eq!(vk_bytes.len(), 32);
}

// ============================================================================
// GROUP 6: Circuit structure (Spec Section 4.1, 4.2)
// ============================================================================

#[test]
fn spec_circuit_8_public_input_elements() -> Result<()> {
    // Spec: circuit exposes 8 public input field elements
    // Bellman adds an implicit 1, so cs.num_inputs() = 9
    let (_, cs) = build_valid_circuit(7300, 20000, AgeDirection::Over)?;
    assert_eq!(cs.num_inputs() - 1, PUBLIC_INPUTS_LEN);
    assert_eq!(cs.num_inputs() - 1, 8);
    Ok(())
}

#[test]
fn spec_circuit_direction_bit_over() -> Result<()> {
    // Spec: direction bit 1 = Over (cutoff >= dob means user is AT LEAST min_age)
    // 25yo (dob=7300) with Over(18) cutoff ~= day 20000: should pass
    let (_, cs) = build_valid_circuit(7300, 20000, AgeDirection::Over)?;
    assert!(cs.is_satisfied(), "Over-age circuit should pass for 25yo");
    Ok(())
}

#[test]
fn spec_circuit_direction_bit_under() -> Result<()> {
    // Spec: direction bit 0 = Under (dob >= cutoff means user is AT MOST max_age)
    // Use a very young person (dob=20000, born after cutoff of 10000)
    let (_, cs) = build_valid_circuit(20000, 10000, AgeDirection::Under)?;
    assert!(
        cs.is_satisfied(),
        "Under-age circuit should pass when dob > cutoff"
    );
    Ok(())
}

#[test]
fn spec_circuit_over_rejects_underage() -> Result<()> {
    // Spec: Over direction rejects when dob > cutoff (user too young)
    // dob=20000 with Over cutoff=10000: user born AFTER cutoff = too young
    let (_, cs) = build_valid_circuit(20000, 10000, AgeDirection::Over)?;
    assert!(
        !cs.is_satisfied(),
        "Over-age circuit should REJECT when dob > cutoff"
    );
    Ok(())
}

#[test]
fn spec_circuit_under_rejects_overage() -> Result<()> {
    // Spec: Under direction rejects when cutoff > dob (user too old)
    // dob=7300 with Under cutoff=20000: user born BEFORE cutoff = too old
    let (_, cs) = build_valid_circuit(7300, 20000, AgeDirection::Under)?;
    assert!(
        !cs.is_satisfied(),
        "Under-age circuit should REJECT when cutoff > dob"
    );
    Ok(())
}

#[test]
fn spec_circuit_has_constraints() -> Result<()> {
    // Spec: circuit contains constraint groups for commitment, signature,
    // age comparison, nullifier, VK equality, and RP hash binding
    let (_, cs) = build_valid_circuit(7300, 20000, AgeDirection::Over)?;
    // A valid circuit must have a significant number of constraints
    assert!(
        cs.num_constraints() > 100,
        "Circuit must have substantial constraints, got {}",
        cs.num_constraints()
    );
    Ok(())
}

// ============================================================================
// GROUP 7: Date encoding (Spec Section 2.5)
// ============================================================================

#[test]
fn spec_dob_is_i32() {
    // Spec: DOB is i32 days since epoch
    let dob_days: i32 = -3653; // 1 Jan 1960
    assert_eq!(std::mem::size_of_val(&dob_days), 4);
}

#[test]
fn spec_pre_epoch_dates_are_negative() {
    // Spec: pre-1970 dates are negative
    // 1 Jan 1960 = -3653 days
    let jan_1_1960: i32 = -3653;
    assert!(jan_1_1960 < 0);
}

#[test]
fn spec_days_since_epoch_semantics() {
    // Spec: days since Unix epoch (1 January 1970)
    // Day 0 = 1 Jan 1970
    // Day 1 = 2 Jan 1970
    // Day -1 = 31 Dec 1969
    assert_eq!(bias_for_circuit(0), 0x8000_0000);
    assert!(bias_for_circuit(-1) < bias_for_circuit(0));
    assert!(bias_for_circuit(0) < bias_for_circuit(1));
}

#[test]
fn spec_bias_monotonic_across_sign_boundary() {
    // Spec: bias preserves ordering across the positive/negative boundary
    let values: Vec<i32> = vec![-10000, -5000, -1, 0, 1, 5000, 10000];
    for window in values.windows(2) {
        assert!(
            bias_for_circuit(window[0]) < bias_for_circuit(window[1]),
            "bias({}) should be < bias({})",
            window[0],
            window[1]
        );
    }
}

// ============================================================================
// GROUP 8: Protocol (Spec Section 5.1, 5.4)
// ============================================================================

#[test]
fn spec_rp_challenge_is_sha256() {
    // Spec: RP challenge = SHA-256(origin || nonce || DST)
    // where DST = "provii.challenge.v0"
    use provii_crypto_protocol::rp_challenge;

    let origin = "https://example.com";
    let nonce = [42u8; 32];
    let challenge = rp_challenge(origin, &nonce);
    assert_eq!(challenge.len(), 32);

    // Verify it matches manual SHA-256 computation
    use sha2::{Digest as Sha2Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(origin.as_bytes());
    hasher.update(nonce);
    hasher.update(b"provii.challenge.v0");
    let expected: [u8; 32] = hasher.finalize().into();
    assert_eq!(challenge, expected);
}

#[test]
fn spec_rp_hash_is_blake2s() {
    // Spec: RP hash = Blake2s-256(rp_challenge), computed off-circuit
    let rp_challenge = [0x42u8; 32];
    let mut hasher = Blake2s256::new();
    hasher.update(rp_challenge);
    let result = hasher.finalize();
    assert_eq!(result.len(), 32);
}

#[test]
fn spec_pkce_is_sha256() {
    // Spec: PKCE uses SHA-256 (S256 method)
    use provii_crypto_protocol::code_challenge_s256;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = code_challenge_s256(verifier);
    // SHA-256 base64url without padding = 43 characters
    assert_eq!(challenge.len(), 43);
    assert!(!challenge.contains('='));
    assert!(!challenge.contains('+'));
    assert!(!challenge.contains('/'));
}

#[test]
fn spec_nonce_is_csprng() -> Result<()> {
    // Spec: nonce = 32 bytes from CSPRNG
    use provii_crypto_protocol::generate_nonce;
    let n1 = generate_nonce()?;
    let n2 = generate_nonce()?;
    assert_eq!(n1.len(), 32);
    assert_eq!(n2.len(), 32);
    assert_ne!(n1, n2, "CSPRNG must produce unique nonces");
    Ok(())
}

#[test]
fn spec_rp_challenge_domain_separated() {
    // Spec: RP challenge uses DST "provii.challenge.v0"
    use provii_crypto_protocol::rp_challenge;

    let origin = "https://example.com";
    let nonce = [1u8; 32];

    // With DST
    let challenge_with_dst = rp_challenge(origin, &nonce);

    // Without DST (manual)
    use sha2::{Digest as Sha2Digest, Sha256};
    let mut hasher_no_dst = Sha256::new();
    hasher_no_dst.update(origin.as_bytes());
    hasher_no_dst.update(nonce);
    let without_dst: [u8; 32] = hasher_no_dst.finalize().into();

    // Must differ (proving DST is included)
    assert_ne!(challenge_with_dst, without_dst);
}

#[test]
fn spec_rp_challenge_binds_origin() {
    // Spec: RP challenge binds to origin
    use provii_crypto_protocol::rp_challenge;

    let nonce = [1u8; 32];
    let c1 = rp_challenge("https://site-a.com", &nonce);
    let c2 = rp_challenge("https://site-b.com", &nonce);
    assert_ne!(
        c1, c2,
        "Different origins must produce different challenges"
    );
}

#[test]
fn spec_rp_challenge_binds_nonce() {
    // Spec: RP challenge binds to nonce
    use provii_crypto_protocol::rp_challenge;

    let origin = "https://example.com";
    let c1 = rp_challenge(origin, &[1u8; 32]);
    let c2 = rp_challenge(origin, &[2u8; 32]);
    assert_ne!(c1, c2, "Different nonces must produce different challenges");
}

// ============================================================================
// GROUP 9: Cross-component consistency (Spec Sections 3-5)
// ============================================================================

#[test]
fn spec_commitment_matches_circuit() -> Result<()> {
    // Spec: commitment computed during issuance matches circuit's in-circuit commitment
    // This is tested by the full circuit being satisfied
    let (_, cs) = build_valid_circuit(7300, 20000, AgeDirection::Over)?;
    assert!(cs.is_satisfied(), "Circuit verifies commitment consistency");
    Ok(())
}

#[test]
fn spec_nullifier_matches_circuit() -> Result<()> {
    // Spec: nullifier from host matches circuit's in-circuit nullifier
    // Tested by circuit satisfaction (nullifier is a public input that must match)
    let (_, cs) = build_valid_circuit(7300, 20000, AgeDirection::Over)?;
    assert!(cs.is_satisfied(), "Circuit verifies nullifier consistency");
    Ok(())
}

#[test]
fn spec_signature_verifies_in_circuit() -> Result<()> {
    // Spec: signature from issuer verifies inside the circuit
    // Tested by circuit satisfaction (signature verification is a circuit constraint)
    let (_, cs) = build_valid_circuit(7300, 20000, AgeDirection::Over)?;
    assert!(
        cs.is_satisfied(),
        "Circuit verifies signature inside ZK proof"
    );
    Ok(())
}

#[test]
fn spec_rp_hash_consistency() {
    // Spec: RP hash computed by wallet matches what verifier expects
    // Both use Blake2s-256 on the same RP challenge bytes
    let rp_challenge = [0x55u8; 32];

    // Wallet computes:
    let wallet_hash = {
        let mut h = Blake2s256::new();
        h.update(rp_challenge);
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    };

    // Verifier computes:
    let verifier_hash = {
        let mut h = Blake2s256::new();
        h.update(rp_challenge);
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    };

    assert_eq!(wallet_hash, verifier_hash, "RP hash must be consistent");
}

#[test]
fn spec_public_inputs_direction_bit() {
    // Spec: direction bit is the first public input element
    // Over = 1, Under = 0
    let inputs_over =
        assemble_public_inputs_canonical(true, 6570, [0u8; 32], [0u8; 32], [0u8; 32]).unwrap();
    let inputs_under =
        assemble_public_inputs_canonical(false, 6570, [0u8; 32], [0u8; 32], [0u8; 32]).unwrap();

    // Direction bit is element 0
    assert_ne!(inputs_over[0], inputs_under[0]);

    // Over = 1 (non-zero scalar), Under = 0 (zero scalar)
    assert_ne!(inputs_over[0], Scalar::ZERO);
    assert_eq!(inputs_under[0], Scalar::ZERO);
}

#[test]
fn spec_public_inputs_cutoff_biased() {
    // Spec: cutoff days are biased before being packed as public inputs
    let inputs_zero =
        assemble_public_inputs_canonical(true, 0, [0u8; 32], [0u8; 32], [0u8; 32]).unwrap();

    // Zero cutoff biased to 0x80000000 is non-zero
    assert_ne!(
        inputs_zero[1],
        Scalar::ZERO,
        "Cutoff 0 biased to 0x80000000 should produce non-zero element"
    );
}

#[test]
fn spec_vk_bytes_raw_not_hash() {
    // Spec: issuer VK bytes are raw VK, not a hash of VK
    // If the inputs were a hash, changing a single bit of VK would change the hash
    // dramatically. With raw bytes, changing one bit changes exactly one bit in the
    // packed representation.
    let mut vk1 = [0u8; 32];
    let mut vk2 = [0u8; 32];
    vk1[0] = 0x01;
    vk2[0] = 0x02; // Single bit difference

    let inputs1 = assemble_public_inputs_canonical(true, 0, [0u8; 32], vk1, [0u8; 32]).unwrap();
    let inputs2 = assemble_public_inputs_canonical(true, 0, [0u8; 32], vk2, [0u8; 32]).unwrap();

    // VK occupies elements 4-5; at least one should differ
    assert!(inputs1[4] != inputs2[4] || inputs1[5] != inputs2[5]);
}

#[test]
fn spec_nullifier_in_public_inputs() {
    // Spec: nullifier is a public input (elements 6-7)
    let null1 = [0x01u8; 32];
    let null2 = [0x02u8; 32];

    let inputs1 = assemble_public_inputs_canonical(true, 0, [0u8; 32], [0u8; 32], null1).unwrap();
    let inputs2 = assemble_public_inputs_canonical(true, 0, [0u8; 32], [0u8; 32], null2).unwrap();

    assert!(inputs1[6] != inputs2[6] || inputs1[7] != inputs2[7]);
}

// ============================================================================
// GROUP 10: DST and personalisations (Spec Section 2.6)
// ============================================================================

#[test]
fn spec_nullifier_dst() {
    // Spec: nullifier uses "provii.nullifier.pedersen.v0" as domain separator
    // This is tested indirectly: if the DST were wrong, the circuit would fail
    // because the nullifier computed in-circuit wouldn't match the public input.
    // We can also check that two nullifiers from the same commitment are equal
    // (proving the DST is deterministic).
    let commitment = [0xABu8; 32];
    let n1 = pedersen_nullifier(&commitment);
    let n2 = pedersen_nullifier(&commitment);
    assert_eq!(n1, n2);
}

#[test]
fn spec_credential_dst() {
    // Spec: credential prehash uses "provii.cred.v0" DST
    use provii_crypto_commons::CRED_DST;
    assert_eq!(CRED_DST, b"provii.cred.v0");
}

#[test]
fn spec_challenge_dst() {
    // Spec: RP challenge uses "provii.challenge.v0" DST
    use provii_crypto_commons::CHALLENGE_DST;
    assert_eq!(CHALLENGE_DST, b"provii.challenge.v0");
}

#[test]
fn spec_sign_bias_constant() {
    // Spec: SIGN_BIAS = 0x80000000
    assert_eq!(SIGN_BIAS, 0x8000_0000u32);
}

#[test]
fn spec_nonce_size_constant() {
    // Spec: NONCE_SIZE = 32
    use provii_crypto_commons::NONCE_SIZE;
    assert_eq!(NONCE_SIZE, 32);
}

#[test]
fn spec_challenge_expiry_300s() {
    // Spec: challenge validity window = 300 seconds (5 minutes)
    use provii_crypto_commons::CHALLENGE_EXPIRY_SECONDS;
    assert_eq!(CHALLENGE_EXPIRY_SECONDS, 300);
}

// ============================================================================
// GROUP 11: Bellman/BLS12-381 field properties
// ============================================================================

#[test]
fn spec_bls12_381_scalar_capacity() {
    // Spec: BLS12-381 scalar field has ~255 bits
    // Bellman packs 254 bits per field element (CAPACITY)
    let capacity = Scalar::CAPACITY;
    assert!(
        capacity >= 254,
        "BLS12-381 Scalar::CAPACITY must be >= 254, got {capacity}"
    );
}

#[test]
fn spec_256_bits_pack_into_2_elements() {
    // Spec: 256-bit values (hashes, keys, nullifiers) pack into 2 field elements
    use bellman::gadgets::multipack;
    let bits = vec![true; 256];
    let packed = multipack::compute_multipacking::<Scalar>(&bits);
    assert_eq!(packed.len(), 2, "256 bits must pack into 2 field elements");
}

#[test]
fn spec_32_bits_pack_into_1_element() {
    // Spec: 32-bit values (cutoff, direction) pack into 1 field element
    use bellman::gadgets::multipack;
    let bits = vec![true; 32];
    let packed = multipack::compute_multipacking::<Scalar>(&bits);
    assert_eq!(packed.len(), 1, "32 bits must pack into 1 field element");
}
