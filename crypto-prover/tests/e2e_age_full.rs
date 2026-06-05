// Test code: direct indexing is acceptable in tests where panics
// surface assertion failures.
#![allow(clippy::indexing_slicing, deprecated)]

//! End-to-end age proof across crates:
//! - Pedersen commit DOB (crypto-commit)
//! - Build credential (crypto-commons)
//! - Sign credential with RedJubjub (crypto-sig-redjubjub)
//! - Generate Groth16 params for AgeCircuit (crypto-circuit-age)
//! - Prove (crypto-prover)
//! - Verify (crypto-verifier)

use bellman::groth16::{
    generate_random_parameters, prepare_verifying_key, verify_proof, Parameters,
};
use bls12_381::Bls12;
use std::time::{SystemTime, UNIX_EPOCH};

use provii_crypto_commit::{
    generate_commitment_randomness, pedersen_commit_dob_validated, pedersen_nullifier,
};
use provii_crypto_commons::CredMsgV2;
use provii_crypto_sig_redjubjub::{generate_keypair, sign_cred_v2};

use provii_crypto_circuit_age::{AgeCircuit, AgeDirection, AgePublic, AgeWitness};
use provii_crypto_prover::{prove_age_snark_auto, AgeSnarkProofV2Extended};
use provii_crypto_verifier::{init_with_vk_registry, verify_age_snark};

fn years_in_days(y: i32) -> anyhow::Result<i32> {
    // 365.2425 approx -> add leap-day fudge every 4 years
    let base = y
        .checked_mul(365)
        .ok_or_else(|| anyhow::anyhow!("overflow in years * 365"))?;
    let leap = y
        .checked_div(4)
        .ok_or_else(|| anyhow::anyhow!("overflow in years / 4"))?;
    base.checked_add(leap)
        .ok_or_else(|| anyhow::anyhow!("overflow in days addition"))
}

fn current_epoch_days() -> anyhow::Result<i32> {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let days = i32::try_from(secs / 86400)?;
    Ok(days)
}

#[test]
fn e2e_credential_sign_prove_verify() -> anyhow::Result<()> {
    // -------------------------
    // 1) Issuer keys & message
    // -------------------------
    let (sk_bytes, issuer_vk_bytes) = generate_keypair();

    // User DOB (days since epoch) and randomness for commitment
    // Person born 21 years ago (epoch day when they were born)
    let today = current_epoch_days()?;
    let dob_days: i32 = today
        .checked_sub(years_in_days(21)?)
        .ok_or_else(|| anyhow::anyhow!("overflow in dob_days"))?;
    let r_bits = generate_commitment_randomness(&mut rand::thread_rng(), 128);
    assert_eq!(r_bits.len(), 128);

    // Pedersen commit to DOB
    let c_bytes =
        pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Credential contents
    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(), // Exactly 14 bytes
        c: c_bytes,
        iat: 1_704_067_200,                 // 2024-01-01T00:00:00Z
        exp: 1_735_689_600,                 // 2024-12-31T00:00:00Z
        schema: "provii.age/0".to_string(), // Exactly 12 bytes
    };

    // RedJubjub signature (NO RP binding, circuit checks RP hash separately)
    let sig_bytes = sign_cred_v2(&cred, &sk_bytes)?;

    // -------------------------
    // 2) Public inputs & witness
    // -------------------------
    // cutoff_days = epoch day 18 years ago (anyone born on or before this is 18+)
    let cutoff_days = today
        .checked_sub(years_in_days(18)?)
        .ok_or_else(|| anyhow::anyhow!("overflow in cutoff_days"))?;
    let rp_challenge = [0x42u8; 32]; // what the RP sends; hash checked in-circuit

    let witness = AgeWitness {
        // commitment witness
        dob_days,
        r_bits: r_bits.to_vec(),

        // signature witness
        issuer_vk_bytes,
        sig_rj_bytes: sig_bytes.to_vec(),

        // the signed message fields (must EXACTLY match host prehash)
        v: cred.v,
        kid: cred.kid.as_bytes().to_vec(),
        c_bytes: cred.c,
        iat: cred.iat,
        exp: cred.exp,
        schema: cred.schema.as_bytes().to_vec(),
        // Note: rp_challenge removed - now computed off-circuit
    };

    // Public inputs consistent with witness
    let public = AgePublic {
        direction: AgeDirection::Over,
        cutoff_days,
        rp_hash: {
            use blake2::{Blake2s256, Digest};
            let mut h = Blake2s256::new();
            h.update(rp_challenge);
            h.finalize().into()
        },
        issuer_vk_bytes, // Raw issuer VK bytes
        cred_nullifier: pedersen_nullifier(&c_bytes),
    };

    // -------------------------------------------------
    // 3) Trusted setup (Groth16 params) for THIS shape
    // -------------------------------------------------
    // IMPORTANT: parameter generation must use the SAME "shape" (lengths of kid/schema/r_bits)
    // as proving. Supplying the exact witness here is the simplest approach for tests.
    let circuit = AgeCircuit {
        public: public.clone(),
        witness: Some(witness.clone()),
    };
    let mut rng = rand::thread_rng();
    let params: Parameters<Bls12> = generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)?;

    // Prepare and serialize VK for the verifier crate
    let vk_bytes = {
        let mut buf = vec![];
        params.vk.write(&mut buf)?;
        buf
    };
    // Verifier uses a global VK registry; initialize with vk_id=1
    init_with_vk_registry(vec![(1, vk_bytes)])?;

    // -------------------------
    // 4) Prove with those params
    // -------------------------
    // vk_id is an application-chosen version number; use 1 here
    let proof_ext: AgeSnarkProofV2Extended = prove_age_snark_auto(
        &params,
        cutoff_days,
        rp_challenge,
        witness.clone(),
        1,
        AgeDirection::Over,
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // -------------------------
    // 5) Verify (public inputs extracted)
    // -------------------------
    let ok = verify_age_snark(
        &proof_ext.proof,
        true,
        proof_ext.cutoff,
        proof_ext.rp_hash,
        proof_ext.issuer_vk_bytes, // Use raw VK bytes (matches circuit)
        proof_ext.cred_nullifier,
        1,
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert!(ok.direction);
    assert_eq!(ok.cutoff_days, cutoff_days);
    assert_eq!(ok.rp_hash, public.rp_hash);
    assert_eq!(ok.issuer_vk_bytes, public.issuer_vk_bytes); // Compare raw VK bytes
    assert_eq!(ok.cred_nullifier, public.cred_nullifier);

    // -------------------------
    // 6) Negative checks
    // -------------------------
    // Wrong RP hash
    let bad = verify_age_snark(
        &proof_ext.proof,
        true,
        proof_ext.cutoff,
        {
            let mut x = proof_ext.rp_hash;
            x[0] ^= 1;
            x
        },
        proof_ext.issuer_vk_bytes,
        proof_ext.cred_nullifier,
        1,
    );
    assert!(bad.is_err(), "verification must fail on wrong RP hash");

    // Wrong issuer VK bytes
    let bad2 = verify_age_snark(
        &proof_ext.proof,
        true,
        proof_ext.cutoff,
        proof_ext.rp_hash,
        {
            let mut x = proof_ext.issuer_vk_bytes;
            x[0] ^= 1;
            x
        },
        proof_ext.cred_nullifier,
        1,
    );
    assert!(bad2.is_err(), "verification must fail on wrong issuer VK");

    // Wrong cutoff days
    let bad3 = verify_age_snark(
        &proof_ext.proof,
        true,
        cutoff_days
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("overflow"))?,
        proof_ext.rp_hash,
        proof_ext.issuer_vk_bytes,
        proof_ext.cred_nullifier,
        1,
    );
    assert!(bad3.is_err(), "verification must fail on wrong cutoff days");

    // Prover should fail if signature is tampered (unsatisfied constraints)
    let mut witness_bad = witness.clone();
    witness_bad.sig_rj_bytes[0] ^= 1;
    let bad_proof = prove_age_snark_auto(
        &params,
        cutoff_days,
        rp_challenge,
        witness_bad,
        1,
        AgeDirection::Over,
    );
    assert!(bad_proof.is_err(), "prover must fail for bad signature");
    Ok(())
}

#[test]
fn e2e_under_direction_prove_verify() -> anyhow::Result<()> {
    let (sk_bytes, issuer_vk_bytes) = generate_keypair();

    let today = current_epoch_days()?;
    let dob_days: i32 = today
        .checked_sub(years_in_days(10)?)
        .ok_or_else(|| anyhow::anyhow!("overflow"))?;
    let r_bits = generate_commitment_randomness(&mut rand::thread_rng(), 128);

    let c_bytes =
        pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: c_bytes,
        iat: 1_704_067_200,
        exp: 1_735_689_600,
        schema: "provii.age/0".to_string(),
    };

    let sig_bytes = sign_cred_v2(&cred, &sk_bytes)?;

    let cutoff_days = today
        .checked_sub(years_in_days(13)?)
        .ok_or_else(|| anyhow::anyhow!("overflow"))?;
    let rp_challenge = [0x77u8; 32];

    let witness = AgeWitness {
        dob_days,
        r_bits: r_bits.to_vec(),
        issuer_vk_bytes,
        sig_rj_bytes: sig_bytes.to_vec(),
        v: cred.v,
        kid: cred.kid.as_bytes().to_vec(),
        c_bytes: cred.c,
        iat: cred.iat,
        exp: cred.exp,
        schema: cred.schema.as_bytes().to_vec(),
    };

    let public = AgePublic {
        direction: AgeDirection::Under,
        cutoff_days,
        rp_hash: {
            use blake2::{Blake2s256, Digest};
            let mut h = Blake2s256::new();
            h.update(rp_challenge);
            h.finalize().into()
        },
        issuer_vk_bytes,
        cred_nullifier: pedersen_nullifier(&c_bytes),
    };

    let circuit = AgeCircuit {
        public: public.clone(),
        witness: Some(witness.clone()),
    };
    let mut rng = rand::thread_rng();
    let params: Parameters<Bls12> = generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)?;

    let proof_ext: AgeSnarkProofV2Extended = prove_age_snark_auto(
        &params,
        cutoff_days,
        rp_challenge,
        witness,
        2,
        AgeDirection::Under,
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Verify directly via bellman to avoid OnceCell conflict with the other
    // e2e test that also calls init_with_vk_registry in the same test binary.
    let pvk = prepare_verifying_key(&params.vk);
    let proof =
        bellman::groth16::Proof::read(&proof_ext.proof[..]).map_err(|e| anyhow::anyhow!("{e}"))?;
    let public_inputs = provii_crypto_public_inputs::assemble_public_inputs_canonical(
        false,
        proof_ext.cutoff,
        proof_ext.rp_hash,
        proof_ext.issuer_vk_bytes,
        proof_ext.cred_nullifier,
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert!(
        verify_proof(&pvk, &proof, &public_inputs).is_ok(),
        "Under-direction proof must verify"
    );
    assert_eq!(proof_ext.cutoff, cutoff_days);

    Ok(())
}

#[test]
fn e2e_tampered_r_bits_rejected() -> anyhow::Result<()> {
    let (sk_bytes, issuer_vk_bytes) = generate_keypair();

    let today = current_epoch_days()?;
    let dob_days: i32 = today
        .checked_sub(years_in_days(25)?)
        .ok_or_else(|| anyhow::anyhow!("overflow"))?;
    let r_bits = generate_commitment_randomness(&mut rand::thread_rng(), 128);

    let c_bytes =
        pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: c_bytes,
        iat: 1_704_067_200,
        exp: 1_735_689_600,
        schema: "provii.age/0".to_string(),
    };

    let sig_bytes = sign_cred_v2(&cred, &sk_bytes)?;

    let cutoff_days = today
        .checked_sub(years_in_days(18)?)
        .ok_or_else(|| anyhow::anyhow!("overflow"))?;
    let rp_challenge = [0x33u8; 32];

    let mut tampered_r_bits = r_bits.to_vec();
    tampered_r_bits[0] = !tampered_r_bits[0];

    let witness = AgeWitness {
        dob_days,
        r_bits: tampered_r_bits,
        issuer_vk_bytes,
        sig_rj_bytes: sig_bytes.to_vec(),
        v: cred.v,
        kid: cred.kid.as_bytes().to_vec(),
        c_bytes: cred.c,
        iat: cred.iat,
        exp: cred.exp,
        schema: cred.schema.as_bytes().to_vec(),
    };

    let public = AgePublic {
        direction: AgeDirection::Over,
        cutoff_days,
        rp_hash: {
            use blake2::{Blake2s256, Digest};
            let mut h = Blake2s256::new();
            h.update(rp_challenge);
            h.finalize().into()
        },
        issuer_vk_bytes,
        cred_nullifier: pedersen_nullifier(&c_bytes),
    };

    let circuit = AgeCircuit {
        public: public.clone(),
        witness: Some(witness.clone()),
    };
    let mut rng = rand::thread_rng();
    let params: Parameters<Bls12> = generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)?;

    let result = prove_age_snark_auto(
        &params,
        cutoff_days,
        rp_challenge,
        witness,
        1,
        AgeDirection::Over,
    );
    assert!(
        result.is_err(),
        "prover must fail when r_bits are tampered (commitment mismatch)"
    );

    Ok(())
}
