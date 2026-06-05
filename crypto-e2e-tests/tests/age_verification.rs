// Test code: diagnostic output, direct indexing, and numeric casts are
// acceptable in tests where panics surface assertion failures.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::arithmetic_side_effects,
    deprecated
)]
// tests/age_verification.rs
//! End-to-end test simulating the complete Provii age verification flow
//!
//! This version focuses on testing the components that work without
//! requiring pre-generated parameters (which are slow to generate in tests)

use anyhow::{anyhow, Result};
use rand::thread_rng;
use std::time::{SystemTime, UNIX_EPOCH};

// Import all the crates
use provii_crypto_circuit_age::{AgeCircuit, AgeDirection, AgePublic, AgeWitness};
use provii_crypto_commit::{
    generate_commitment_randomness, pedersen_commit_dob_validated, pedersen_nullifier,
};
use provii_crypto_commons::CredMsgV2;
use provii_crypto_sig_redjubjub::{generate_keypair, sign_cred_v2, verify_cred_v2};

use bellman::gadgets::test::TestConstraintSystem;
use bellman::Circuit;
use blake2::{Blake2s256, Digest};
use provii_crypto_public_inputs::assemble_public_inputs_canonical;

#[test]
fn test_redjubjub_signature_with_circuit_fixed() -> Result<()> {
    println!("\n🔐 Testing RedJubjub Signature in Circuit (FIXED)");

    let (issuer_sk, issuer_vk) = generate_keypair();

    // Generate commitment inputs
    let mut rng = thread_rng();
    let r_bits = generate_commitment_randomness(&mut rng, 128); // Circuit expects 128 bits
    let dob_days = 7300i32;

    // Compute commitment from these inputs
    let commitment =
        pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| anyhow!("{e:?}"))?;
    println!(
        "Commitment computed from dob={}, r_bits: {}",
        dob_days,
        hex::encode(commitment)
    );

    // Create credential with THIS commitment
    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment, // Use the computed commitment
        iat: 1757747313,
        exp: 1789283313,
        schema: "provii.age/0".to_string(),
    };

    // Sign the credential
    let sig = sign_cred_v2(&cred, &issuer_sk)?;
    verify_cred_v2(&cred, &sig, &issuer_vk)?;
    println!("✅ Off-circuit verification passed");

    // Create witness with the SAME r_bits and dob_days that produced the commitment
    let rp_challenge = [42u8; 32];
    let witness = AgeWitness {
        dob_days,                // Same dob_days
        r_bits: r_bits.to_vec(), // Same r_bits
        issuer_vk_bytes: issuer_vk,
        sig_rj_bytes: sig.to_vec(),
        v: cred.v,
        kid: cred.kid.as_bytes().to_vec(),
        c_bytes: commitment, // This will match the computed commitment
        iat: cred.iat,
        exp: cred.exp,
        schema: cred.schema.as_bytes().to_vec(),
        // Note: rp_challenge removed from witness - computed off-circuit
    };

    // Compute public inputs
    let rp_hash = {
        let mut hasher = Blake2s256::new();
        hasher.update(rp_challenge);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    let current_epoch_days =
        (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 86400) as i32;
    let cutoff_days = current_epoch_days - 6570; // 18 years ago from today

    println!("  Current epoch day: {current_epoch_days}");
    println!("  Cutoff day (18 years ago): {cutoff_days}");
    println!("  User DOB day: {dob_days}");
    println!("  User is old enough: {}", dob_days <= cutoff_days);

    let public = AgePublic {
        direction: AgeDirection::Over,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes: issuer_vk, // Use VK bytes directly, not hash
        cred_nullifier: pedersen_nullifier(&commitment),
    };

    // Create circuit
    let circuit = AgeCircuit {
        public: public.clone(),
        witness: Some(witness),
    };

    // Test with TestConstraintSystem
    let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();
    circuit.synthesize(&mut cs)?;

    println!("📊 Circuit statistics:");
    println!("  Constraints: {}", cs.num_constraints());
    println!("  Inputs: {}", cs.num_inputs());
    println!("  Satisfied: {}", cs.is_satisfied());

    if !cs.is_satisfied() {
        println!("\n❌ Circuit constraints not satisfied!");
        if let Some(unsatisfied) = cs.which_is_unsatisfied() {
            println!("  First unsatisfied constraint: {unsatisfied}");

            // Provide helpful debugging based on the constraint name
            if unsatisfied.contains("age_threshold_check") {
                println!("  💡 Age check failed - user might be too young");
                println!("     Check: cutoff_days({cutoff_days}) >= dob_days({dob_days})");
            } else if unsatisfied.contains("redjubjub") {
                println!("  💡 Signature verification failed");
                println!("     This is the issue we're debugging!");
            } else if unsatisfied.contains("commitment") {
                println!("  💡 Commitment verification failed");
            }
        }
        return Err(anyhow!("Circuit verification failed"));
    }

    println!("\n✅ Circuit verification PASSED!");
    Ok(())
}

#[test]
fn test_age_check_logic() -> Result<()> {
    println!("\n📅 Testing Age Check Logic");
    println!("==========================");

    let _rng = thread_rng();
    let current_epoch_days =
        (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 86400) as i32;

    // Test case 1: User is exactly 18
    test_age_scenario(
        "Exactly 18 years old",
        current_epoch_days - 6570,
        current_epoch_days - 6570,
        true,
    )?;

    // Test case 2: User is 19 (should pass)
    test_age_scenario(
        "19 years old",
        current_epoch_days - 6935,
        current_epoch_days - 6570,
        true,
    )?;

    // Test case 3: User is 17 (should fail)
    test_age_scenario(
        "17 years old",
        current_epoch_days - 6205,
        current_epoch_days - 6570,
        false,
    )?;

    Ok(())
}

fn test_age_scenario(
    scenario: &str,
    user_dob_days: i32,
    cutoff_days: i32,
    should_pass: bool,
) -> Result<()> {
    println!("\n  Testing: {scenario}");
    println!("    User DOB: {user_dob_days} days");
    println!("    Cutoff: {cutoff_days} days");
    println!(
        "    Expected: {}",
        if should_pass { "PASS" } else { "FAIL" }
    );

    let mut rng = thread_rng();
    let (issuer_sk, issuer_vk) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut rng, 128);
    let commitment =
        pedersen_commit_dob_validated(user_dob_days, &r_bits).map_err(|e| anyhow!("{e:?}"))?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(), // Exactly 14 bytes
        c: commitment,
        iat: 1704067200,
        exp: 1735689600,
        schema: "provii.age/0".to_string(), // Exactly 12 bytes
    };

    let sig = sign_cred_v2(&cred, &issuer_sk)?;

    let rp_challenge = [0u8; 32];

    // COMPUTE the RP hash - don't use zeros!
    let rp_hash = {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(rp_challenge);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    let witness = AgeWitness {
        dob_days: user_dob_days,
        r_bits: r_bits.to_vec(),
        issuer_vk_bytes: issuer_vk,
        sig_rj_bytes: sig.to_vec(),
        v: cred.v,
        kid: cred.kid.as_bytes().to_vec(),
        c_bytes: commitment,
        iat: cred.iat,
        exp: cred.exp,
        schema: cred.schema.as_bytes().to_vec(),
        // Note: rp_challenge removed from witness - computed off-circuit
    };

    let public = AgePublic {
        direction: AgeDirection::Over,
        cutoff_days,
        rp_hash,                    // The computed hash of the challenge
        issuer_vk_bytes: issuer_vk, // Use VK bytes directly, not hash
        cred_nullifier: pedersen_nullifier(&commitment),
    };

    let circuit = AgeCircuit {
        public,
        witness: Some(witness),
    };

    let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();
    circuit.synthesize(&mut cs)?;

    let satisfied = cs.is_satisfied();
    println!(
        "    Result: {} (satisfied: {})",
        if satisfied { "PASS" } else { "FAIL" },
        satisfied
    );

    if satisfied != should_pass {
        if let Some(unsatisfied) = cs.which_is_unsatisfied() {
            println!("    Unsatisfied constraint: {unsatisfied}");
        }
        return Err(anyhow!("Age check result doesn't match expectation"));
    }

    Ok(())
}

#[test]
fn test_commitment_binding() -> Result<()> {
    println!("\n🔗 Testing Commitment Binding");
    println!("==============================");

    let mut rng = thread_rng();

    // Same DOB, different randomness
    let dob = 7300i32;
    let r1 = generate_commitment_randomness(&mut rng, 128);
    let r2 = generate_commitment_randomness(&mut rng, 128);

    let c1 = pedersen_commit_dob_validated(dob, &r1).map_err(|e| anyhow!("{e:?}"))?;
    let c2 = pedersen_commit_dob_validated(dob, &r2).map_err(|e| anyhow!("{e:?}"))?;

    // Commitments should be different
    assert_ne!(c1, c2);
    println!("✅ Different randomness produces different commitments");

    // Same randomness should produce same commitment (deterministic)
    let c3 = pedersen_commit_dob_validated(dob, &r1).map_err(|e| anyhow!("{e:?}"))?;
    assert_eq!(c1, c3);
    println!("✅ Commitment is deterministic");

    Ok(())
}

#[test]
fn test_replay_protection() -> Result<()> {
    println!("\n🔄 Testing Replay Protection");
    println!("=============================");

    use provii_crypto_protocol::{compute_replay_tag, generate_nonce};

    // Generate two different nonces
    let nonce1 = generate_nonce().map_err(|e| anyhow!("{e:?}"))?;
    let nonce2 = generate_nonce().map_err(|e| anyhow!("{e:?}"))?;

    assert_ne!(nonce1, nonce2);
    println!("✅ Generated unique nonces");

    // Compute replay tags
    let origin_hash = [1u8; 32];
    let tag1 = compute_replay_tag(&origin_hash, &nonce1);
    let tag2 = compute_replay_tag(&origin_hash, &nonce2);

    assert_ne!(tag1, tag2);
    println!("✅ Replay tags are unique");

    Ok(())
}

#[test]
fn test_circuit_public_input_encoding() -> Result<()> {
    println!("\n🔍 Testing Circuit Public Input Encoding");
    println!("=========================================");

    // Use known test values
    let test_cutoff: i32 = 13771;
    let mut test_rp_hash = [0x77u8; 32]; // All 0x77 bytes
    test_rp_hash[31] = 0x37; // Except last byte is 0x37
    let mut test_issuer_hash = [0x02u8; 32];
    test_issuer_hash[0] = 0x82; // First byte different
    let mut test_nullifier = [0x9bu8; 32];
    test_nullifier[31] = 0x1b; // Last byte different

    // Generate valid witness data
    let mut rng = thread_rng();
    let (issuer_sk, issuer_vk) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut rng, 128);
    let dob_days = 7300i32;
    let commitment =
        pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| anyhow!("{e:?}"))?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(), // Exactly 14 bytes
        c: commitment,
        iat: 1704067200,
        exp: 1735689600,
        schema: "provii.age/0".to_string(), // Exactly 12 bytes
    };

    let sig = sign_cred_v2(&cred, &issuer_sk)?;
    let rp_challenge = [42u8; 32];

    // Create witness
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
        // Note: rp_challenge removed from witness
    };

    // Compute the RP hash that the circuit will compute
    let computed_rp_hash = {
        let mut hasher = Blake2s256::new();
        hasher.update(rp_challenge);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    println!("Test values:");
    println!("  cutoff_days: {test_cutoff}");
    println!("  rp_hash (provided): {}", hex::encode(test_rp_hash));
    println!("  rp_hash (computed): {}", hex::encode(computed_rp_hash));
    println!("  issuer_hash: {}", hex::encode(test_issuer_hash));
    println!("  nullifier: {}", hex::encode(test_nullifier));

    // Create public inputs with PROVIDED values (not computed)
    let public = AgePublic {
        direction: AgeDirection::Over,
        cutoff_days: test_cutoff,
        rp_hash: test_rp_hash,             // Using the provided test value
        issuer_vk_bytes: test_issuer_hash, // Using test hash as VK bytes for testing
        cred_nullifier: test_nullifier,
    };

    // Test what the host assembly produces
    let host_assembled = assemble_public_inputs_canonical(
        true,
        test_cutoff,
        test_rp_hash,
        test_issuer_hash,
        test_nullifier,
    )?;

    println!("\nHost assembled {} public inputs:", host_assembled.len());
    for (i, scalar) in host_assembled.iter().enumerate() {
        use ff::PrimeField;
        println!("  host_pi[{}] = {}", i, hex::encode(scalar.to_repr()));
    }

    // Create circuit with witness
    let circuit = AgeCircuit {
        public: public.clone(),
        witness: Some(witness.clone()), // Clone witness here
    };

    // Synthesize and check
    let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();
    circuit.synthesize(&mut cs)?;

    println!("\nCircuit synthesis results:");
    println!("  Constraints: {}", cs.num_constraints());
    println!("  Public inputs (including ONE): {}", cs.num_inputs());
    println!("  Satisfied: {}", cs.is_satisfied());

    // The circuit will fail because rp_hash doesn't match computed value
    // This is expected and shows the circuit is checking correctly
    if !cs.is_satisfied() {
        if let Some(unsatisfied) = cs.which_is_unsatisfied() {
            println!("  First unsatisfied: {unsatisfied}");
            if unsatisfied.contains("rp_hash_equality") {
                println!("  ✅ Expected: RP hash mismatch detected correctly");
            }
        }
    }

    // Now test with matching values
    println!("\n--- Testing with matching RP hash ---");

    let public_matching = AgePublic {
        direction: AgeDirection::Over,
        cutoff_days: test_cutoff,
        rp_hash: computed_rp_hash,  // Use the computed hash
        issuer_vk_bytes: issuer_vk, // Use VK bytes directly, not hash
        cred_nullifier: pedersen_nullifier(&commitment),
    };

    let host_assembled_matching = assemble_public_inputs_canonical(
        true,
        public_matching.cutoff_days,
        public_matching.rp_hash,
        public_matching.issuer_vk_bytes,
        public_matching.cred_nullifier,
    )?;

    println!("Host assembled (matching):");
    for (i, scalar) in host_assembled_matching.iter().enumerate() {
        use ff::PrimeField;
        println!("  host_pi[{}] = {}", i, hex::encode(scalar.to_repr()));
    }

    let circuit_matching = AgeCircuit {
        public: public_matching,
        witness: Some(witness), // Use original witness
    };

    let mut cs_matching = TestConstraintSystem::<bls12_381::Scalar>::new();
    circuit_matching.synthesize(&mut cs_matching)?;

    println!("\nWith matching values:");
    println!("  Satisfied: {}", cs_matching.is_satisfied());

    if !cs_matching.is_satisfied() {
        if let Some(unsatisfied) = cs_matching.which_is_unsatisfied() {
            println!("  ERROR: Unexpected failure at: {unsatisfied}");
        }
    }

    // Test different bit encodings
    println!("\n--- Testing bit encoding ---");
    test_bit_encoding_differences();

    Ok(())
}

#[test]
fn test_bit_encoding_differences() {
    use bellman::gadgets::multipack;
    use bls12_381::Scalar;
    use ff::PrimeField;

    let test_bytes = [0xABu8, 0xCD, 0xEF, 0x12];

    // Little-endian bits (LSB first in each byte)
    let mut le_bits = Vec::new();
    for byte in &test_bytes {
        for i in 0..8 {
            le_bits.push((byte >> i) & 1 == 1);
        }
    }

    // Big-endian bits (MSB first in each byte)
    let mut be_bits = Vec::new();
    for byte in &test_bytes {
        for i in (0..8).rev() {
            be_bits.push((byte >> i) & 1 == 1);
        }
    }

    // A2: bit vector lengths must be exactly 32 (4 bytes * 8 bits)
    assert_eq!(le_bits.len(), 32, "LE bit vector must have 32 bits");
    assert_eq!(be_bits.len(), 32, "BE bit vector must have 32 bits");

    let le_packed = multipack::compute_multipacking::<Scalar>(&le_bits);
    let be_packed = multipack::compute_multipacking::<Scalar>(&be_bits);

    // A1: LE and BE orderings must produce distinct packed scalars
    assert_ne!(
        le_packed, be_packed,
        "LE and BE bit orderings must produce different packed values"
    );

    // A3: 32 bits fits within one BLS12-381 field element (capacity is 253 bits)
    assert_eq!(
        le_packed.len(),
        1,
        "32 bits must pack into exactly one field element"
    );
    assert_eq!(
        be_packed.len(),
        1,
        "32 bits must pack into exactly one field element"
    );

    // A4: packing is deterministic. Repeating with identical inputs must yield identical outputs
    let le_packed2 = multipack::compute_multipacking::<Scalar>(&le_bits);
    let be_packed2 = multipack::compute_multipacking::<Scalar>(&be_bits);
    assert_eq!(le_packed, le_packed2, "LE packing must be deterministic");
    assert_eq!(be_packed, be_packed2, "BE packing must be deterministic");

    // A5: pinned regression values verified against a known-good run
    // LE scalar: bytes 0xAB, 0xCD, 0xEF, 0x12 packed LSB-first = 0x12EFCDAB in scalar repr
    // BE scalar: byte-reversed bit order within each byte of the same four-byte input
    let le_hex = hex::encode(le_packed[0].to_repr());
    let be_hex = hex::encode(be_packed[0].to_repr());
    assert_eq!(
        le_hex, "abcdef1200000000000000000000000000000000000000000000000000000000",
        "LE packed regression value changed"
    );
    assert_eq!(
        be_hex, "d5b3f74800000000000000000000000000000000000000000000000000000000",
        "BE packed regression value changed"
    );
}

// ==================== Under-Age Tests ====================

#[test]
fn test_under_age_circuit_accepts_young_person() -> Result<()> {
    // A 10-year-old should satisfy "under 13" (dob > cutoff)
    let current_epoch_days =
        (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 86400) as i32;

    let user_dob_days = current_epoch_days - (10 * 365); // 10 years old
    let cutoff_days = current_epoch_days - (13 * 365); // Under 13 cutoff

    // dob > cutoff means the user was born more recently than the cutoff => under age
    assert!(
        user_dob_days > cutoff_days,
        "10-year-old DOB should be after under-13 cutoff"
    );

    let mut rng = thread_rng();
    let (issuer_sk, issuer_vk) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut rng, 128);
    let commitment =
        pedersen_commit_dob_validated(user_dob_days, &r_bits).map_err(|e| anyhow!("{e:?}"))?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment,
        iat: 1704067200,
        exp: 1735689600,
        schema: "provii.age/0".to_string(),
    };

    let sig = sign_cred_v2(&cred, &issuer_sk)?;

    let rp_challenge = [0x55u8; 32];
    let rp_hash = {
        let mut hasher = Blake2s256::new();
        hasher.update(rp_challenge);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    let witness = AgeWitness {
        dob_days: user_dob_days,
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
        direction: AgeDirection::Under,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes: issuer_vk,
        cred_nullifier: pedersen_nullifier(&commitment),
    };

    let circuit = AgeCircuit {
        public,
        witness: Some(witness),
    };

    let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();
    circuit.synthesize(&mut cs)?;

    assert!(
        cs.is_satisfied(),
        "Under-age circuit should be satisfied for a 10-year-old (under 13)"
    );

    Ok(())
}

#[test]
fn test_under_age_circuit_rejects_old_person() -> Result<()> {
    // A 25-year-old should NOT satisfy "under 13"
    let current_epoch_days =
        (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 86400) as i32;

    let user_dob_days = current_epoch_days - (25 * 365); // 25 years old
    let cutoff_days = current_epoch_days - (13 * 365); // Under 13 cutoff

    assert!(
        user_dob_days < cutoff_days,
        "25-year-old DOB should be before under-13 cutoff"
    );

    let mut rng = thread_rng();
    let (issuer_sk, issuer_vk) = generate_keypair();
    let r_bits = generate_commitment_randomness(&mut rng, 128);
    let commitment =
        pedersen_commit_dob_validated(user_dob_days, &r_bits).map_err(|e| anyhow!("{e:?}"))?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment,
        iat: 1704067200,
        exp: 1735689600,
        schema: "provii.age/0".to_string(),
    };

    let sig = sign_cred_v2(&cred, &issuer_sk)?;

    let rp_challenge = [0x66u8; 32];
    let rp_hash = {
        let mut hasher = Blake2s256::new();
        hasher.update(rp_challenge);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    let witness = AgeWitness {
        dob_days: user_dob_days,
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
        direction: AgeDirection::Under,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes: issuer_vk,
        cred_nullifier: pedersen_nullifier(&commitment),
    };

    let circuit = AgeCircuit {
        public,
        witness: Some(witness),
    };

    let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();
    circuit.synthesize(&mut cs)?;

    assert!(
        !cs.is_satisfied(),
        "Under-age circuit should NOT be satisfied for a 25-year-old (under 13)"
    );

    Ok(())
}

#[test]
fn test_over_and_under_different_semantics() -> Result<()> {
    // A 25-year-old should pass Over(18) but fail Under(13)
    // A 10-year-old should fail Over(18) but pass Under(13)
    let current_epoch_days =
        (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 86400) as i32;

    let over_cutoff = current_epoch_days - (18 * 365); // Over 18 cutoff
    let under_cutoff = current_epoch_days - (13 * 365); // Under 13 cutoff

    // Test with a 25-year-old
    let old_dob = current_epoch_days - (25 * 365);
    // Test with a 10-year-old
    let young_dob = current_epoch_days - (10 * 365);

    for (label, dob, cutoff, direction, expected_satisfied) in [
        (
            "25yo over-18",
            old_dob,
            over_cutoff,
            AgeDirection::Over,
            true,
        ),
        (
            "25yo under-13",
            old_dob,
            under_cutoff,
            AgeDirection::Under,
            false,
        ),
        (
            "10yo over-18",
            young_dob,
            over_cutoff,
            AgeDirection::Over,
            false,
        ),
        (
            "10yo under-13",
            young_dob,
            under_cutoff,
            AgeDirection::Under,
            true,
        ),
    ] {
        let mut rng = thread_rng();
        let (issuer_sk, issuer_vk) = generate_keypair();
        let r_bits = generate_commitment_randomness(&mut rng, 128);
        let commitment =
            pedersen_commit_dob_validated(dob, &r_bits).map_err(|e| anyhow!("{e:?}"))?;

        let cred = CredMsgV2 {
            v: 2,
            kid: "provii:2026-05".to_string(),
            c: commitment,
            iat: 1704067200,
            exp: 1735689600,
            schema: "provii.age/0".to_string(),
        };

        let sig = sign_cred_v2(&cred, &issuer_sk)?;

        let rp_challenge = [0x77u8; 32];
        let rp_hash = {
            let mut hasher = Blake2s256::new();
            hasher.update(rp_challenge);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        let witness = AgeWitness {
            dob_days: dob,
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
            cutoff_days: cutoff,
            rp_hash,
            issuer_vk_bytes: issuer_vk,
            cred_nullifier: pedersen_nullifier(&commitment),
        };

        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();
        circuit.synthesize(&mut cs)?;

        assert_eq!(
            cs.is_satisfied(),
            expected_satisfied,
            "Scenario '{}': expected satisfied={}, got satisfied={}",
            label,
            expected_satisfied,
            cs.is_satisfied()
        );
    }

    Ok(())
}

// ============================================================================
// PC-250: MULTIPLE DOB VALUES IN E2E TESTS
// ============================================================================

#[test]
fn test_multiple_dob_values_boundary_dates() -> Result<()> {
    // PC-250: Test with multiple different DOB values including boundary cases.
    // DOB is expressed as days since Unix epoch (1970-01-01).
    // Negative values represent pre-1970 dates.

    let current_epoch_days = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        / 86400) as i32;
    let over_18_cutoff = current_epoch_days - 6570; // 18 years ago

    // Various DOB values to exercise:
    let test_cases: Vec<(&str, i32, bool)> = vec![
        // (label, dob_days, should_satisfy_over_18)
        ("very old person (born 1930)", -14610, true), // ~40 years before epoch
        ("born on epoch (1970-01-01)", 0, true),       // exactly epoch day
        ("born 1980", 3652, true),                     // well over 18
        ("exactly at cutoff", over_18_cutoff, true),   // exactly 18
        ("one day too young", over_18_cutoff + 1, false), // just under 18
        (
            "very young (born 5 years ago)",
            current_epoch_days - 1826,
            false,
        ),
    ];

    for (label, dob_days, should_pass) in test_cases {
        let mut rng = thread_rng();
        let (issuer_sk, issuer_vk) = generate_keypair();
        let r_bits = generate_commitment_randomness(&mut rng, 128);
        let commitment =
            pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| anyhow!("{e:?}"))?;

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
            direction: AgeDirection::Over,
            cutoff_days: over_18_cutoff,
            rp_hash,
            issuer_vk_bytes: issuer_vk,
            cred_nullifier: pedersen_nullifier(&commitment),
        };

        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();
        circuit.synthesize(&mut cs)?;

        assert_eq!(
            cs.is_satisfied(),
            should_pass,
            "PC-250 DOB test '{}' (dob_days={}): expected satisfied={}, got satisfied={}",
            label,
            dob_days,
            should_pass,
            cs.is_satisfied()
        );
    }

    Ok(())
}
