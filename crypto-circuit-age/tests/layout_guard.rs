#![allow(deprecated)]

//! Layout guard tests.
//!
//! These tests assert that the circuit's public input count and slot ordering
//! remain stable. A change to the multipack layout without a corresponding
//! change here is a regression. It would silently break all proof
//! verification without a compile error.

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

/// Build a satisfiable circuit and return the synthesised constraint system
/// along with the matching host public inputs.
fn synthesise_valid_circuit(
    seed: u64,
    rp_hash: [u8; 32],
) -> Result<(TestConstraintSystem<Scalar>, Vec<Scalar>), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(seed);
    let (sk, vk) = generate_keypair_with_rng(&mut rng);
    let r_bits = generate_commitment_randomness(&mut rng, 128);

    let dob_days = 7300i32;

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

    let cutoff_days = dob_days;

    let public = AgePublic {
        direction: AgeDirection::Over,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes: vk,
        cred_nullifier: nullifier,
    };

    let host_pi = assemble_public_inputs_canonical(true, cutoff_days, rp_hash, vk, nullifier)?;

    let circuit = AgeCircuit {
        public,
        witness: Some(witness),
    };

    let mut cs = TestConstraintSystem::<Scalar>::new();
    circuit.synthesize(&mut cs)?;

    Ok((cs, host_pi))
}

// ---------------------------------------------------------------------------
// Test 1: satisfied + verify + input count
// ---------------------------------------------------------------------------

#[test]
fn layout_guard_matches_public_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let rp_hash = [0xA5u8; 32];
    let (cs, host_pi) = synthesise_valid_circuit(0xCAFE_BABE_0001, rp_hash)?;

    // Circuit must be satisfiable with the real witness
    assert!(cs.is_satisfied(), "circuit must be satisfied");

    // Host PI must contain exactly 8 field elements
    assert_eq!(
        host_pi.len(),
        8,
        "host must assemble exactly 8 field elements"
    );

    // Bellman adds one implicit ONE input at index 0; the circuit allocates 8 more
    assert_eq!(
        cs.num_inputs(),
        9,
        "circuit must expose exactly 9 inputs (ONE + 8 public)"
    );

    // Bit layout of the 8 elements (from assemble_public_inputs_canonical):
    //   [0] direction  (32 LE bits packed into 1 element)
    //   [1] cutoff     (32 LE bits packed into 1 element)
    //   [2] rp_hash lo (254 LE bits)
    //   [3] rp_hash hi (2 LE bits)
    //   [4] issuer_vk lo
    //   [5] issuer_vk hi
    //   [6] nullifier lo
    //   [7] nullifier hi
    assert!(
        cs.verify(&host_pi),
        "circuit public inputs must match host assembly exactly"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Test 2: structural count stability
// ---------------------------------------------------------------------------

#[test]
fn layout_guard_input_count_stability() -> Result<(), Box<dyn std::error::Error>> {
    // Run with two distinct seeds to confirm num_inputs is invariant to witness values.
    let (cs_a, _) = synthesise_valid_circuit(0xCAFE_BABE_0002, [0x11u8; 32])?;
    let (cs_b, _) = synthesise_valid_circuit(0xCAFE_BABE_0003, [0x22u8; 32])?;

    assert_eq!(
        cs_a.num_inputs(),
        9,
        "seed A: circuit must expose exactly 9 inputs"
    );
    assert_eq!(
        cs_b.num_inputs(),
        9,
        "seed B: circuit must expose exactly 9 inputs"
    );
    assert_eq!(
        cs_a.num_inputs(),
        cs_b.num_inputs(),
        "input count must be invariant across different seeds"
    );

    Ok(())
}
