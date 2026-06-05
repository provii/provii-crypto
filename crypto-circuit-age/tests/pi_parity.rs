#![allow(deprecated, clippy::indexing_slicing)]

//! Public input parity tests.
//!
//! Verifies that the multipack order used inside the circuit matches the order
//! produced by `assemble_public_inputs_canonical` on the host. Any drift
//! would cause every Groth16 verification to fail in production without
//! triggering a compile error.

use bellman::gadgets::test::TestConstraintSystem;
use bellman::Circuit;
use bls12_381::Scalar;

use provii_crypto_circuit_age::{AgeCircuit, AgeDirection, AgePublic, AgeWitness};
use provii_crypto_commit::{
    generate_commitment_randomness, pedersen_commit_dob_validated, pedersen_nullifier,
};
use provii_crypto_commons::CredMsgV2;
use provii_crypto_public_inputs::assemble_public_inputs_canonical;
use provii_crypto_sig_redjubjub::{generate_keypair_with_rng, sign_cred_v2};
use rand::{rngs::StdRng, SeedableRng};

const TEST_KID: &str = "abcdefghijklmn"; // exactly 14 bytes
const TEST_SCHEMA: &str = "schemaschema"; // exactly 12 bytes

/// Build a satisfiable set of circuit fixtures from a deterministic seed.
///
/// Returns `(witness, public, direction_bool)` where `direction_bool` is the
/// boolean form of the direction flag suitable for `assemble_public_inputs_canonical`.
fn build_satisfiable_fixtures(
    seed: u64,
    direction: AgeDirection,
    rp_hash: [u8; 32],
) -> Result<(AgeWitness, AgePublic), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(seed);
    let (sk, vk) = generate_keypair_with_rng(&mut rng);
    let r_bits = generate_commitment_randomness(&mut rng, 128);

    let dob_days = 7300i32; // well within any cutoff used in tests

    let commitment =
        pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| format!("{e:?}"))?;

    let cred = CredMsgV2 {
        v: 2,
        kid: TEST_KID.to_string(),
        c: commitment,
        iat: 1_000_000,
        exp: 2_000_000,
        schema: TEST_SCHEMA.to_string(),
    };

    let sig = sign_cred_v2(&cred, &sk)?;
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

    let cutoff_days = dob_days; // boundary: exactly old enough

    let public = AgePublic {
        direction,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes: vk,
        cred_nullifier: nullifier,
    };

    Ok((witness, public))
}

// ---------------------------------------------------------------------------
// Test 1: Over direction, circuit PI matches host assembly
// ---------------------------------------------------------------------------

#[test]
fn pi_parity_circuit_inputs_match_host_assembly() -> Result<(), Box<dyn std::error::Error>> {
    let rp_hash = [0x11u8; 32];
    let (witness, public) =
        build_satisfiable_fixtures(0xDEAD_BEEF_0001, AgeDirection::Over, rp_hash)?;

    let issuer_vk = public.issuer_vk_bytes;
    let nullifier = public.cred_nullifier;
    let cutoff = public.cutoff_days;

    let circuit = AgeCircuit {
        public,
        witness: Some(witness),
    };

    let mut cs = TestConstraintSystem::<Scalar>::new();
    circuit.synthesize(&mut cs)?;

    assert!(
        cs.is_satisfied(),
        "circuit must be satisfied with honest witness"
    );

    let host_pi = assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier)?;

    assert_eq!(
        host_pi.len(),
        8,
        "host must assemble exactly 8 field elements"
    );
    assert!(
        cs.verify(&host_pi),
        "circuit public inputs must match host assembly exactly"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Test 2: Under direction, circuit PI matches host assembly
// ---------------------------------------------------------------------------

#[test]
fn pi_parity_under_direction() -> Result<(), Box<dyn std::error::Error>> {
    // For Under, dob must be >= cutoff. build_satisfiable_fixtures sets
    // dob == cutoff so the constraint holds for both directions.
    let rp_hash = [0x22u8; 32];
    let (witness, public) =
        build_satisfiable_fixtures(0xDEAD_BEEF_0002, AgeDirection::Under, rp_hash)?;

    let issuer_vk = public.issuer_vk_bytes;
    let nullifier = public.cred_nullifier;
    let cutoff = public.cutoff_days;

    let circuit = AgeCircuit {
        public,
        witness: Some(witness),
    };

    let mut cs = TestConstraintSystem::<Scalar>::new();
    circuit.synthesize(&mut cs)?;

    assert!(
        cs.is_satisfied(),
        "Under-direction circuit must be satisfied"
    );

    let host_pi = assemble_public_inputs_canonical(false, cutoff, rp_hash, issuer_vk, nullifier)?;

    assert_eq!(
        host_pi.len(),
        8,
        "host must assemble exactly 8 field elements"
    );
    assert!(
        cs.verify(&host_pi),
        "Under-direction circuit public inputs must match host assembly"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Test 3: Two circuits same seed, different rp_hash. PI at RP hash slots differ
// ---------------------------------------------------------------------------

#[test]
fn pi_parity_different_rp_hashes() -> Result<(), Box<dyn std::error::Error>> {
    let rp_hash_a = [0x33u8; 32];
    let rp_hash_b = [0x44u8; 32];

    let (witness_a, public_a) =
        build_satisfiable_fixtures(0xDEAD_BEEF_0003, AgeDirection::Over, rp_hash_a)?;
    let (witness_b, public_b) =
        build_satisfiable_fixtures(0xDEAD_BEEF_0003, AgeDirection::Over, rp_hash_b)?;

    // Both circuits share the same seed so issuer VK and nullifier are identical;
    // only rp_hash differs.
    let cutoff = public_a.cutoff_days;
    let issuer_vk = public_a.issuer_vk_bytes;
    let nullifier = public_a.cred_nullifier;

    // Synthesize circuit A
    let mut cs_a = TestConstraintSystem::<Scalar>::new();
    AgeCircuit {
        public: public_a,
        witness: Some(witness_a),
    }
    .synthesize(&mut cs_a)?;
    assert!(cs_a.is_satisfied());

    // Synthesize circuit B
    let mut cs_b = TestConstraintSystem::<Scalar>::new();
    AgeCircuit {
        public: public_b,
        witness: Some(witness_b),
    }
    .synthesize(&mut cs_b)?;
    assert!(cs_b.is_satisfied());

    // Assemble host PI for each RP hash
    let host_pi_a =
        assemble_public_inputs_canonical(true, cutoff, rp_hash_a, issuer_vk, nullifier)?;
    let host_pi_b =
        assemble_public_inputs_canonical(true, cutoff, rp_hash_b, issuer_vk, nullifier)?;

    // Both must match their own circuit
    assert!(
        cs_a.verify(&host_pi_a),
        "circuit A must verify against host PI A"
    );
    assert!(
        cs_b.verify(&host_pi_b),
        "circuit B must verify against host PI B"
    );

    // Cross-verify must fail: RP hash is at slots 2 and 3 (0-indexed in the 8-element vector)
    assert_ne!(
        host_pi_a[2], host_pi_b[2],
        "RP hash element [2] must differ across the two circuits"
    );

    // Circuit A should not verify against circuit B's PI
    assert!(
        !cs_a.verify(&host_pi_b),
        "circuit A must not verify against host PI B"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Test 4: Swap issuer VK and nullifier in host assembly. Verify returns false
// ---------------------------------------------------------------------------

#[test]
fn pi_parity_rejects_swapped_fields() -> Result<(), Box<dyn std::error::Error>> {
    let rp_hash = [0x55u8; 32];
    let (witness, public) =
        build_satisfiable_fixtures(0xDEAD_BEEF_0004, AgeDirection::Over, rp_hash)?;

    let issuer_vk = public.issuer_vk_bytes;
    let nullifier = public.cred_nullifier;
    let cutoff = public.cutoff_days;

    let circuit = AgeCircuit {
        public,
        witness: Some(witness),
    };

    let mut cs = TestConstraintSystem::<Scalar>::new();
    circuit.synthesize(&mut cs)?;

    assert!(cs.is_satisfied(), "circuit must be satisfied before swap");

    // Correct assembly must verify
    let correct_pi = assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier)?;
    assert!(cs.verify(&correct_pi), "correct assembly must verify");

    // Swapped assembly: pass nullifier where issuer_vk is expected and vice versa
    let swapped_pi = assemble_public_inputs_canonical(true, cutoff, rp_hash, nullifier, issuer_vk)?;

    assert!(
        !cs.verify(&swapped_pi),
        "swapped issuer VK and nullifier must not verify"
    );

    Ok(())
}
