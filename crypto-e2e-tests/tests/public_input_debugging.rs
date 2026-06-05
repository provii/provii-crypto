// Test code: diagnostic output, direct indexing, unwrap, and arithmetic
// are acceptable in tests where panics surface assertion failures.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::string_slice,
    deprecated
)]

use anyhow::Result;
use bellman::gadgets::test::TestConstraintSystem;
use bellman::Circuit; // ADD THIS IMPORT
use bls12_381::Scalar;
use ff::PrimeField;
use provii_crypto_circuit_age::{AgeCircuit, AgeDirection, AgePublic, AgeWitness};
use provii_crypto_public_inputs::assemble_public_inputs_canonical; // FIXED: correct crate name

#[test]
#[ignore]
fn debug_public_input_mismatch() -> Result<()> {
    println!("\n🔍 DEBUGGING PUBLIC INPUT MISMATCH");
    println!("{}", "=".repeat(50)); // FIXED: proper string repeat syntax

    // Use exact values from your failing proof
    let cutoff_days: i32 = 13771;
    let rp_hash: [u8; 32] =
        hex::decode("a7389774365451db3093af40be307d73ed93917c2dda443da397c1ced51ba677")?
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("wrong length: {}", v.len()))?;
    let issuer_key_hash: [u8; 32] =
        hex::decode("02820bdb8c81bb4824b8b7be488765e819b84ff495d5ae334a10197fd97ddd25")?
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("wrong length: {}", v.len()))?;
    let cred_nullifier: [u8; 32] =
        hex::decode("7d62fb3981e0081371f15e0f3e8a4991dd6651cffb1da1ed5c31e5f34a961f9b")?
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("wrong length: {}", v.len()))?;

    // Test 1: Verify canonical assembly
    println!("\n1. Testing canonical assembly:");
    let canonical_pi = assemble_public_inputs_canonical(
        true,
        cutoff_days,
        rp_hash,
        issuer_key_hash,
        cred_nullifier,
    )?;

    println!("   Canonical PI count: {}", canonical_pi.len());
    for (i, scalar) in canonical_pi.iter().enumerate() {
        println!("   pi[{}] = {}", i, hex::encode(scalar.to_repr()));
    }

    // Test 2: Check bit ordering differences
    println!("\n2. Testing bit ordering impact:");
    test_bit_ordering_impact(&rp_hash);

    // Test 3: Check limb ordering
    println!("\n3. Testing limb ordering:");
    test_limb_ordering(&canonical_pi);

    // Test 4: Circuit synthesis with real values
    println!("\n4. Testing circuit synthesis:");
    test_circuit_synthesis_with_values(cutoff_days, rp_hash, issuer_key_hash, cred_nullifier)?;

    Ok(())
}

fn test_bit_ordering_impact(bytes: &[u8; 32]) {
    use bellman::gadgets::multipack;

    // Method 1: LE bits (LSB first)
    let mut le_bits = Vec::new();
    for &b in bytes {
        for i in 0..8 {
            le_bits.push(((b >> i) & 1) == 1);
        }
    }

    // Method 2: BE bits (MSB first)
    let mut be_bits = Vec::new();
    for &b in bytes {
        for i in (0..8).rev() {
            be_bits.push(((b >> i) & 1) == 1);
        }
    }

    let le_packed = multipack::compute_multipacking::<Scalar>(&le_bits);
    let be_packed = multipack::compute_multipacking::<Scalar>(&be_bits);

    println!("   LE packing (2 limbs):");
    for (i, s) in le_packed.iter().enumerate() {
        println!("     [{}] = {}", i, hex::encode(s.to_repr()));
    }

    println!("   BE packing (2 limbs):");
    for (i, s) in be_packed.iter().enumerate() {
        println!("     [{}] = {}", i, hex::encode(s.to_repr()));
    }

    if le_packed != be_packed {
        println!("   ⚠️  Different bit orderings produce different results!");
    }
}

fn test_limb_ordering(canonical_pi: &[Scalar]) {
    use ff::PrimeField;

    println!("   Standard order:");
    for (i, s) in canonical_pi.iter().enumerate() {
        let hex_str = hex::encode(s.to_repr());
        println!("     pi[{}] = {}...", i, &hex_str[..16.min(hex_str.len())]);
    }

    println!("   If limbs were swapped:");
    let mut swapped = canonical_pi.to_vec();
    if swapped.len() >= 8 {
        swapped.swap(2, 3); // Swap rp_hash limbs
        swapped.swap(4, 5); // Swap issuer limbs
        swapped.swap(6, 7); // Swap nullifier limbs
    }

    for (i, s) in swapped.iter().enumerate() {
        let hex_str = hex::encode(s.to_repr());
        println!("     pi[{}] = {}...", i, &hex_str[..16.min(hex_str.len())]);
    }
}

fn test_circuit_synthesis_with_values(
    cutoff_days: i32,
    rp_hash: [u8; 32],
    issuer_key_hash: [u8; 32],
    cred_nullifier: [u8; 32],
) -> Result<()> {
    use provii_crypto_commit::{generate_commitment_randomness, pedersen_commit_dob_validated};
    use provii_crypto_commons::CredMsgV2;
    use provii_crypto_sig_redjubjub::{generate_keypair, sign_cred_v2};
    use rand::thread_rng;

    let mut rng = thread_rng();
    let (issuer_sk, issuer_vk) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut rng, 128);
    let dob_days = 7300i32;

    // Create a proper commitment
    let commitment =
        pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Create a valid credential
    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(), // Exactly 14 bytes
        c: commitment,
        iat: 1000,
        exp: 2000,
        schema: "provii.age/0".to_string(), // Exactly 12 bytes
    };

    // Sign it properly to get a valid signature
    let sig = sign_cred_v2(&cred, &issuer_sk)?;

    // Create witness with VALID signature
    let witness = AgeWitness {
        dob_days,
        r_bits: r_bits.to_vec(),
        issuer_vk_bytes: issuer_vk,
        sig_rj_bytes: sig.to_vec(), // Use the real signature
        v: cred.v,
        kid: cred.kid.as_bytes().to_vec(),
        c_bytes: commitment, // Use the actual commitment
        iat: cred.iat,
        exp: cred.exp,
        schema: cred.schema.as_bytes().to_vec(),
        // Note: rp_challenge removed from witness
    };

    let public = AgePublic {
        direction: AgeDirection::Over,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes: issuer_key_hash, // Using issuer_key_hash as VK bytes for testing
        cred_nullifier,
    };

    let circuit = AgeCircuit {
        public,
        witness: Some(witness),
    };

    let mut cs = TestConstraintSystem::<Scalar>::new();
    circuit.synthesize(&mut cs)?;

    println!("   Constraints: {}", cs.num_constraints());
    println!("   Public inputs: {}", cs.num_inputs());
    println!("   Satisfied: {}", cs.is_satisfied());

    if !cs.is_satisfied() {
        if let Some(name) = cs.which_is_unsatisfied() {
            println!("   ❌ First unsatisfied: {name}");
            // This is expected since we're using mismatched public inputs
            // The test is checking that the canonical assembly produces the right format
        }
    }

    Ok(())
}
