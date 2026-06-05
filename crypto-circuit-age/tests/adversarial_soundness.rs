#![allow(deprecated)]

//! Adversarial soundness property-based tests for the age circuit.
//!
//! Uses proptest to generate random valid circuits and verify that:
//! - Honest provers always satisfy the circuit
//! - Tampered witnesses always fail
//! - Boundary conditions are handled correctly

use bellman::gadgets::test::TestConstraintSystem;
use bellman::Circuit;
use bls12_381::Scalar;

use provii_crypto_circuit_age::{AgeCircuit, AgeDirection, AgePublic, AgeWitness};
use provii_crypto_commit::{
    generate_commitment_randomness, pedersen_commit_dob_validated, pedersen_nullifier,
};
use provii_crypto_commons::CredMsgV2;
use provii_crypto_sig_redjubjub::{generate_keypair_with_rng, sign_cred_v2};

use proptest::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

const TEST_KID: &str = "abcdefghijklmn";
const TEST_SCHEMA: &str = "schemaschema";

/// Create valid test fixtures from a deterministic seed with specified parameters.
fn make_valid_fixtures_from_seed(
    seed: u64,
    dob_days: i32,
    cutoff_days: i32,
    direction: AgeDirection,
) -> Result<(AgeWitness, AgePublic), TestCaseError> {
    let mut rng = StdRng::seed_from_u64(seed);
    let (sk, vk) = generate_keypair_with_rng(&mut rng);
    let r_bits = generate_commitment_randomness(&mut rng, 128);
    let commitment = pedersen_commit_dob_validated(dob_days, &r_bits)
        .map_err(|e| TestCaseError::fail(format!("pedersen_commit_dob_validated failed: {e:?}")))?;

    let cred = CredMsgV2 {
        v: 2,
        kid: TEST_KID.to_string(),
        c: commitment,
        iat: 1000000,
        exp: 2000000,
        schema: TEST_SCHEMA.to_string(),
    };

    let sig = sign_cred_v2(&cred, &sk)
        .map_err(|e| TestCaseError::fail(format!("sign_cred_v2 failed: {e:?}")))?;
    let nullifier = pedersen_nullifier(&commitment);

    let witness = AgeWitness {
        dob_days,
        r_bits: r_bits.to_vec(),
        issuer_vk_bytes: vk,
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
        rp_hash: [0u8; 32],
        issuer_vk_bytes: vk,
        cred_nullifier: nullifier,
    };

    Ok((witness, public))
}

fn synthesize_and_check(
    witness: AgeWitness,
    public: AgePublic,
) -> (bool, TestConstraintSystem<Scalar>) {
    let circuit = AgeCircuit {
        public,
        witness: Some(witness),
    };
    let mut cs = TestConstraintSystem::new();
    let result = circuit.synthesize(&mut cs);
    assert!(result.is_ok(), "Synthesis must not error");
    (cs.is_satisfied(), cs)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn proptest_valid_circuit_satisfies_for_any_dob(
        dob in -25000i32..50000,
        seed in 1u64..100000,
    ) {
        // Valid circuit with dob <= cutoff (Over direction) should always satisfy
        let cutoff = dob; // boundary: exactly old enough
        let (witness, public) = make_valid_fixtures_from_seed(seed, dob, cutoff, AgeDirection::Over)?;
        let (satisfied, _) = synthesize_and_check(witness, public);
        prop_assert!(satisfied, "Valid circuit must satisfy for dob={}, seed={}", dob, seed);
    }

    #[test]
    fn proptest_tampered_dob_always_fails(
        dob in 1i32..50000,
        seed in 1u64..100000,
    ) {
        // Create valid circuit, then tamper dob
        let cutoff = dob;
        let (mut witness, public) = make_valid_fixtures_from_seed(seed, dob, cutoff, AgeDirection::Over)?;
        // Set dob to a different value (subtract 1, guaranteed different since dob >= 1)
        #[allow(clippy::arithmetic_side_effects)]
        { witness.dob_days = dob - 1; }
        let (satisfied, _) = synthesize_and_check(witness, public);
        prop_assert!(!satisfied, "Tampered dob must fail for dob={}, seed={}", dob, seed);
    }

    #[test]
    fn proptest_valid_circuit_satisfies_for_any_r_bits(
        seed in 1u64..100000,
        r_seed in 1u64..100000,
    ) {
        // The randomness is generated from r_seed, creating diverse r_bits
        let dob = 6570i32;
        let mut rng = StdRng::seed_from_u64(r_seed);
        let r_bits = generate_commitment_randomness(&mut rng, 128);

        // Now build everything else with the main seed
        let mut main_rng = StdRng::seed_from_u64(seed);
        let (sk, vk) = generate_keypair_with_rng(&mut main_rng);
        let commitment = pedersen_commit_dob_validated(dob, &r_bits)
            .map_err(|e| TestCaseError::fail(format!("pedersen_commit_dob_validated failed: {e:?}")))?;

        let cred = CredMsgV2 {
            v: 2,
            kid: TEST_KID.to_string(),
            c: commitment,
            iat: 1000000,
            exp: 2000000,
            schema: TEST_SCHEMA.to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk)
            .map_err(|e| TestCaseError::fail(format!("sign_cred_v2 failed: {e:?}")))?;
        let nullifier = pedersen_nullifier(&commitment);

        let witness = AgeWitness {
            dob_days: dob,
            r_bits: r_bits.to_vec(),
            issuer_vk_bytes: vk,
            sig_rj_bytes: sig.to_vec(),
            v: cred.v,
            kid: cred.kid.as_bytes().to_vec(),
            c_bytes: commitment,
            iat: cred.iat,
            exp: cred.exp,
            schema: cred.schema.as_bytes().to_vec(),
        };

        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: dob,
            rp_hash: [0u8; 32],
            issuer_vk_bytes: vk,
            cred_nullifier: nullifier,
        };

        let (satisfied, _) = synthesize_and_check(witness, public);
        prop_assert!(satisfied, "Valid circuit must satisfy for any r_bits");
    }

    #[test]
    fn proptest_cutoff_boundary_over_satisfies(
        dob in -25000i32..40000,
        extra in 0i32..10000,
        seed in 1u64..100000,
    ) {
        // dob <= cutoff with Over direction should always satisfy
        #[allow(clippy::arithmetic_side_effects)]
        let cutoff = dob + extra; // cutoff >= dob
        let (witness, public) = make_valid_fixtures_from_seed(seed, dob, cutoff, AgeDirection::Over)?;
        let (satisfied, _) = synthesize_and_check(witness, public);
        prop_assert!(satisfied, "dob={} <= cutoff={} must satisfy Over", dob, cutoff);
    }

    #[test]
    fn proptest_cutoff_boundary_over_fails(
        dob in 1i32..50000,
        delta in 1i32..1000,
        seed in 1u64..100000,
    ) {
        // dob > cutoff with Over direction should always fail
        let cutoff = dob.saturating_sub(delta);
        // Only test when cutoff < dob (person too young)
        prop_assume!(cutoff < dob);
        let (witness, public) = make_valid_fixtures_from_seed(seed, dob, cutoff, AgeDirection::Over)?;
        let (satisfied, _) = synthesize_and_check(witness, public);
        prop_assert!(!satisfied, "dob={} > cutoff={} must fail Over", dob, cutoff);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn proptest_valid_under_circuit_satisfies_for_any_dob(
        dob in -25000i32..50000,
        seed in 1u64..100000,
    ) {
        // Valid circuit with dob >= cutoff (Under direction) should always satisfy.
        // Boundary case: dob == cutoff (exactly young enough).
        let cutoff = dob;
        let (witness, public) = make_valid_fixtures_from_seed(seed, dob, cutoff, AgeDirection::Under)?;
        let (satisfied, _) = synthesize_and_check(witness, public);
        prop_assert!(satisfied, "Valid Under circuit must satisfy for dob={}, seed={}", dob, seed);
    }

    #[test]
    fn proptest_tampered_dob_rejects_under(
        dob in 1i32..50000,
        seed in 1u64..100000,
    ) {
        // Create valid Under fixture, then tamper the dob. Commitment mismatch must reject.
        let cutoff = dob;
        let (mut witness, public) = make_valid_fixtures_from_seed(seed, dob, cutoff, AgeDirection::Under)?;
        // Subtract 1 so the committed dob no longer matches witness.dob_days.
        #[allow(clippy::arithmetic_side_effects)]
        { witness.dob_days = dob - 1; }
        let (satisfied, _) = synthesize_and_check(witness, public);
        prop_assert!(!satisfied, "Tampered dob must fail Under for dob={}, seed={}", dob, seed);
    }

    #[test]
    fn proptest_cutoff_boundary_under_satisfies(
        dob in -25000i32..40000,
        extra in 0i32..10000,
        seed in 1u64..100000,
    ) {
        // dob >= cutoff with Under direction should always satisfy.
        let cutoff = dob.saturating_sub(extra); // cutoff <= dob
        prop_assume!(cutoff <= dob);
        let (witness, public) = make_valid_fixtures_from_seed(seed, dob, cutoff, AgeDirection::Under)?;
        let (satisfied, _) = synthesize_and_check(witness, public);
        prop_assert!(satisfied, "dob={} >= cutoff={} must satisfy Under", dob, cutoff);
    }

    #[test]
    fn proptest_cutoff_boundary_under_fails(
        dob in -25000i32..49000,
        delta in 1i32..1000,
        seed in 1u64..100000,
    ) {
        // dob < cutoff with Under direction should always fail (person too old).
        #[allow(clippy::arithmetic_side_effects)]
        let cutoff = dob + delta; // cutoff > dob
        prop_assume!(cutoff > dob);
        let (witness, public) = make_valid_fixtures_from_seed(seed, dob, cutoff, AgeDirection::Under)?;
        let (satisfied, _) = synthesize_and_check(witness, public);
        prop_assert!(!satisfied, "dob={} < cutoff={} must fail Under", dob, cutoff);
    }

    #[test]
    fn proptest_direction_mismatch_over_as_under_fails(
        dob in 1i32..50000,
        delta in 1i32..1000,
        seed in 1u64..100000,
    ) {
        // Build a valid Over fixture where dob < cutoff (so Over would satisfy).
        // Then flip direction to Under. dob < cutoff violates the Under constraint,
        // so the circuit must fail.
        #[allow(clippy::arithmetic_side_effects)]
        let cutoff = dob + delta; // cutoff > dob: valid for Over, invalid for Under
        prop_assume!(cutoff > dob);
        let (witness, mut public) = make_valid_fixtures_from_seed(seed, dob, cutoff, AgeDirection::Over)?;
        // Flip the direction bit after fixture creation.
        public.direction = AgeDirection::Under;
        let (satisfied, _) = synthesize_and_check(witness, public);
        prop_assert!(!satisfied, "Over fixture with direction flipped to Under must fail: dob={}, cutoff={}", dob, cutoff);
    }
}
