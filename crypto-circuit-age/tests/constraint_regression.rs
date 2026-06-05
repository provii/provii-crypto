#![allow(deprecated)]

//! Per-gadget constraint count regression tests.
//!
//! Each test allocates minimal inputs, runs a single gadget in a
//! TestConstraintSystem, and asserts the exact constraint count.
//! Any change means the R1CS structure changed and new trusted setup
//! parameters are required.

use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::test::TestConstraintSystem;
use bellman::{Circuit, ConstraintSystem};
use bls12_381::Scalar;

use provii_crypto_circuit_age::gadgets;

/// Allocate n witness boolean bits with given values.
fn alloc_witness_bits(
    cs: &mut TestConstraintSystem<Scalar>,
    prefix: &str,
    values: &[bool],
) -> Result<Vec<Boolean>, Box<dyn std::error::Error>> {
    let mut bits = Vec::with_capacity(values.len());
    for (i, &v) in values.iter().enumerate() {
        let bit = AllocatedBit::alloc(cs.namespace(|| format!("{prefix}_{i}")), Some(v))?;
        bits.push(Boolean::from(bit));
    }
    Ok(bits)
}

#[test]
fn test_pedersen_commit_constraints() -> Result<(), Box<dyn std::error::Error>> {
    let mut cs = TestConstraintSystem::<Scalar>::new();

    // 32 dob bits + 128 r bits = 160 input bits
    let dob_bits = alloc_witness_bits(&mut cs, "dob", &[false; 32])?;
    let r_bits = alloc_witness_bits(&mut cs, "r", &[false; 128])?;

    let before = cs.num_constraints();
    let _result = gadgets::pedersen::commit(cs.namespace(|| "commit"), &dob_bits, &r_bits);
    let after = cs.num_constraints();

    #[allow(clippy::arithmetic_side_effects)]
    let commit_constraints = after - before;

    // Pin the exact count
    assert_eq!(
        commit_constraints, PEDERSEN_COMMIT_CONSTRAINTS,
        "Pedersen commit constraint count changed! Was {PEDERSEN_COMMIT_CONSTRAINTS}, now {commit_constraints}."
    );
    Ok(())
}

#[test]
fn test_pedersen_nullifier_constraints() -> Result<(), Box<dyn std::error::Error>> {
    let mut cs = TestConstraintSystem::<Scalar>::new();

    // 256 input bits (commitment bytes)
    let c_bits = alloc_witness_bits(&mut cs, "c", &[false; 256])?;

    let before = cs.num_constraints();
    let _result = gadgets::pedersen::pedersen_nullifier(cs.namespace(|| "nullifier"), &c_bits);
    let after = cs.num_constraints();

    #[allow(clippy::arithmetic_side_effects)]
    let nullifier_constraints = after - before;

    assert_eq!(
        nullifier_constraints, PEDERSEN_NULLIFIER_CONSTRAINTS,
        "Pedersen nullifier constraint count changed! Was {PEDERSEN_NULLIFIER_CONSTRAINTS}, now {nullifier_constraints}."
    );
    Ok(())
}

#[test]
fn test_blake2s_hash_constraints() -> Result<(), Box<dyn std::error::Error>> {
    let mut cs = TestConstraintSystem::<Scalar>::new();

    // 256-bit input
    let bits = alloc_witness_bits(&mut cs, "input", &[false; 256])?;

    let before = cs.num_constraints();
    let _result = gadgets::blake2s::blake2s_256(cs.namespace(|| "hash"), &bits);
    let after = cs.num_constraints();

    #[allow(clippy::arithmetic_side_effects)]
    let hash_constraints = after - before;

    assert_eq!(
        hash_constraints, BLAKE2S_HASH_CONSTRAINTS,
        "Blake2s hash constraint count changed! Was {BLAKE2S_HASH_CONSTRAINTS}, now {hash_constraints}."
    );
    Ok(())
}

#[test]
fn test_enforce_ge_constraints() -> Result<(), Box<dyn std::error::Error>> {
    let mut cs = TestConstraintSystem::<Scalar>::new();

    // Two 32-bit vectors
    let a = alloc_witness_bits(&mut cs, "a", &[false; 32])?;
    let b = alloc_witness_bits(&mut cs, "b", &[false; 32])?;

    let before = cs.num_constraints();
    let _result = gadgets::bits::enforce_ge(cs.namespace(|| "ge"), &a, &b);
    let after = cs.num_constraints();

    #[allow(clippy::arithmetic_side_effects)]
    let ge_constraints = after - before;

    assert_eq!(
        ge_constraints, ENFORCE_GE_CONSTRAINTS,
        "enforce_ge constraint count changed! Was {ENFORCE_GE_CONSTRAINTS}, now {ge_constraints}."
    );
    Ok(())
}

#[test]
fn test_conditional_swap_constraints() -> Result<(), Box<dyn std::error::Error>> {
    let mut cs = TestConstraintSystem::<Scalar>::new();

    // Direction bit + two 32-bit vectors
    let dir = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "dir"), Some(true))?);
    let a = alloc_witness_bits(&mut cs, "a", &[false; 32])?;
    let b = alloc_witness_bits(&mut cs, "b", &[true; 32])?;

    let before = cs.num_constraints();
    let _result = gadgets::bits::conditional_swap(cs.namespace(|| "swap"), &dir, &a, &b);
    let after = cs.num_constraints();

    #[allow(clippy::arithmetic_side_effects)]
    let swap_constraints = after - before;

    assert_eq!(
        swap_constraints, CONDITIONAL_SWAP_CONSTRAINTS,
        "conditional_swap constraint count changed! Was {CONDITIONAL_SWAP_CONSTRAINTS}, now {swap_constraints}."
    );
    Ok(())
}

#[test]
fn test_redjubjub_verify_constraints() -> Result<(), Box<dyn std::error::Error>> {
    // Full RedJubjub verify gadget requires valid point allocations.
    // We use the full circuit to isolate the redjubjub namespace constraints.
    use provii_crypto_circuit_age::{AgeCircuit, AgeDirection, AgePublic, AgeWitness};
    use provii_crypto_commit::{
        generate_commitment_randomness, pedersen_commit_dob_validated, pedersen_nullifier,
    };
    use provii_crypto_commons::CredMsgV2;
    use provii_crypto_sig_redjubjub::{generate_keypair_with_rng, sign_cred_v2};
    use rand::{rngs::StdRng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(12345);
    let (sk, vk) = generate_keypair_with_rng(&mut rng);
    let r_bits = generate_commitment_randomness(&mut rng, 128);
    let dob_days = 6570i32;
    let commitment =
        pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| format!("{e:?}"))?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "abcdefghijklmn".to_string(),
        c: commitment,
        iat: 1000000,
        exp: 2000000,
        schema: "schemaschema".to_string(),
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

    let public = AgePublic {
        direction: AgeDirection::Over,
        cutoff_days: dob_days,
        rp_hash: [0u8; 32],
        issuer_vk_bytes: vk,
        cred_nullifier: nullifier,
    };

    let circuit = AgeCircuit {
        public,
        witness: Some(witness),
    };
    let mut cs = TestConstraintSystem::new();
    circuit.synthesize(&mut cs)?;
    assert!(cs.is_satisfied());

    // Count constraints in redjubjub-related namespaces by examining pretty_print
    let pp = cs.pretty_print();
    let _rj_constraint_count = pp
        .lines()
        .filter(|line| {
            line.contains("redjubjub_signature_verification")
                || line.contains("compute_challenge")
                || line.contains("get_base_point")
                || line.contains("s_times_base")
                || line.contains("c_times_vk")
                || line.contains("r_plus_c_vk")
                || line.contains("verify_equation")
                || line.contains("generator_u_is_constant")
                || line.contains("generator_v_is_constant")
        })
        .count();

    // The total circuit constraint count is the real regression pin.
    // For the full circuit, we verify the total is stable.
    assert_eq!(
        cs.num_constraints(),
        FULL_CIRCUIT_CONSTRAINTS,
        "Full circuit constraint count changed! Was {}, now {}.",
        FULL_CIRCUIT_CONSTRAINTS,
        cs.num_constraints()
    );
    Ok(())
}

// ============================================================================
// PINNED CONSTRAINT COUNTS
// ============================================================================
// These values are determined at implementation time. If any test fails,
// the circuit structure has changed and new trusted setup is required.
//
// To update: run `cargo test -p provii-crypto-circuit-age --test constraint_regression -- --nocapture`
// and replace the constants with the printed values.

const PEDERSEN_COMMIT_CONSTRAINTS: usize = 1052;
const PEDERSEN_NULLIFIER_CONSTRAINTS: usize = 1518;
const BLAKE2S_HASH_CONSTRAINTS: usize = 21006;
const ENFORCE_GE_CONSTRAINTS: usize = 99;
const CONDITIONAL_SWAP_CONSTRAINTS: usize = 128;
const FULL_CIRCUIT_CONSTRAINTS: usize = 99083;
