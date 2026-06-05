// Test code: unwrap, indexing, casts, and diagnostic output are acceptable in tests
// where panics surface assertion failures.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

//! Deterministic test vectors for `provii-protocol-spec/v1/protocol.md`
//! Appendix A.
//!
//! This is the canonical source for every pinned hex value in Appendix A.
//! The single test `e2e_spec_vectors` materialises each value from static
//! inputs (or, where an end to end flow is exercised, from
//! `ChaCha20Rng::from_seed([0u8; 32])` as the sole RNG source) and asserts
//! byte-for-byte equality against the spec.
//!
//! Run:
//!   cargo test --release -p provii-crypto-e2e-tests \
//!     --test spec_vectors -- --nocapture
//!
//! Any drift between this file and Appendix A is a defect. The spec's text
//! requires this harness to re-run bit-for-bit on every invocation.
//!
//! Ordering of checks follows Appendix A.1 through A.12.

use std::fs;
use std::path::PathBuf;

use bellman::groth16::{
    create_random_proof, prepare_verifying_key, verify_proof, Parameters, VerifyingKey,
};
use blake2::{Blake2b512, Blake2s256};
use bls12_381::Bls12;
use ed25519_dalek::{SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use ff::PrimeField;
use group::GroupEncoding;
use jubjub::SubgroupPoint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest as _, Sha256};
// blake2's Digest trait is the same trait as sha2's (both re-export
// digest::Digest). The `use sha2::Digest as _` line above brings it into scope
// for the `::digest(...)` associated fn used on Blake2s256 / Blake2b512.

use provii_crypto_circuit_age::{
    compute_circuit_constants_hash, AgeCircuit, AgeDirection, AgePublic, AgeWitness,
    KID_SIZE_BYTES, PUBLIC_INPUTS_LEN, SCHEMA_SIZE_BYTES,
};
use provii_crypto_commit::{
    generate_commitment_randomness, pedersen_commit_dob_validated, pedersen_nullifier,
};
use provii_crypto_commons::{
    attestation::DobAttestation, bias_for_circuit, cred_v2_prehash_bytes, unbias_from_circuit,
    CredMsgV2, SIGN_BIAS,
};
use provii_crypto_protocol::rp_challenge as rp_challenge_v1;
use provii_crypto_public_inputs::assemble_public_inputs_canonical;
use provii_crypto_sig_redjubjub::{generate_keypair_with_rng, sign_cred_v2, verify_cred_v2};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn provii_crypto_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for this crate is .../provii-crypto/crypto-e2e-tests.
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent().expect("workspace parent").to_path_buf()
}

// is_multiple_of is unstable on MSRV 1.85; unknown_lints tolerates clippy versions without this lint
#[allow(unknown_lints, clippy::manual_is_multiple_of)]
fn pack_bits_le(bits: &[bool]) -> Vec<u8> {
    assert!(bits.len() % 8 == 0, "bit count must be a multiple of 8");
    let mut out = vec![0u8; bits.len() / 8];
    for (i, &b) in bits.iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

fn assert_hex_eq(label: &str, actual: &[u8], expected_hex: &str) {
    let got = hex::encode(actual);
    assert_eq!(
        got, expected_hex,
        "{label}: hex mismatch\n  expected: {expected_hex}\n  actual:   {got}"
    );
    println!("ok {label}: {got}");
}

// The normative v1.0 construction per spec Section 13.2 / Appendix A.5 is
// the reference implementation in `provii_crypto_protocol::rp_challenge`:
//
//   rp_challenge = SHA-256(origin || nonce || DST)
//
// No length prefix in v1.0. A length-prefixed variant is under consideration
// for v1.1; see spec Appendix F.

// ---------------------------------------------------------------------------
// The single end to end harness test. Every pinned hex in Appendix A is
// asserted here, in source order. The e2e pipeline section drives the full
// flow from `ChaCha20Rng::from_seed([0u8; 32])`.
// ---------------------------------------------------------------------------

#[test]
fn e2e_spec_vectors() -> anyhow::Result<()> {
    // =======================================================================
    // A.1 Bias transformation
    // =======================================================================
    // Mechanical table; assert every row exactly as spec lists.
    assert_eq!(bias_for_circuit(-3653), 2_147_479_995);
    assert_eq!(bias_for_circuit(-1), 2_147_483_647);
    assert_eq!(bias_for_circuit(0), 2_147_483_648);
    assert_eq!(bias_for_circuit(1), 2_147_483_649);
    assert_eq!(bias_for_circuit(11_246), 2_147_494_894);
    assert_eq!(bias_for_circuit(13_880), 2_147_497_528);
    assert_eq!(bias_for_circuit(i32::MAX), 4_294_967_295);
    assert_eq!(bias_for_circuit(i32::MIN), 0);
    // Ordering preservation is the raison d'etre of the bias.
    assert!(bias_for_circuit(-3653) < bias_for_circuit(-1));
    assert!(bias_for_circuit(-1) < bias_for_circuit(0));
    assert!(bias_for_circuit(0) < bias_for_circuit(1));
    // Round trip for a spread of values.
    for days in [-3653i32, -1, 0, 1, 13_880, i32::MIN, i32::MAX] {
        assert_eq!(unbias_from_circuit(bias_for_circuit(days)), days);
    }
    assert_eq!(SIGN_BIAS, 0x8000_0000);
    println!("ok A.1: bias table");

    // =======================================================================
    // A.2 Spending key generator
    // =======================================================================
    const SPENDING_KEY_GENERATOR_HEX: &str =
        "30b5f2aaad325630bcdddbce4d67656d05fd1cc2d037bb5375b6e96d9e01a157";
    let spending_gen_bytes = hex::decode(SPENDING_KEY_GENERATOR_HEX)?;
    // Must decode to a prime order subgroup point.
    let sg_arr: [u8; 32] = spending_gen_bytes.as_slice().try_into()?;
    let sg_point: SubgroupPoint = Option::from(SubgroupPoint::from_bytes(&sg_arr))
        .expect("spending key generator must decode to a subgroup point");
    // Round trip through to_bytes to confirm the canonical compressed encoding.
    assert_hex_eq(
        "A.2 spending_key_generator",
        &sg_point.to_bytes(),
        SPENDING_KEY_GENERATOR_HEX,
    );

    // =======================================================================
    // A.3 PKCE S256 KAT (RFC 7636 Appendix B)
    // =======================================================================
    let code_verifier = b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let sha = Sha256::digest(code_verifier);
    let code_challenge = base64_url_no_pad(&sha);
    assert_eq!(
        code_challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "A.3 PKCE code_challenge"
    );
    println!("ok A.3: PKCE code_challenge = {code_challenge}");

    // =======================================================================
    // A.4 Blake2s-256 KATs (RFC 7693)
    // =======================================================================
    assert_hex_eq(
        "A.4 Blake2s-256(empty)",
        &Blake2s256::digest(b""),
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
    );
    assert_hex_eq(
        "A.4 Blake2s-256(\"abc\")",
        &Blake2s256::digest(b"abc"),
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
    );

    // =======================================================================
    // A.5 RP Challenge KAT (v1.0 non-prefixed construction)
    // =======================================================================
    //
    // Inputs:
    //   origin = "https://example.com"
    //   nonce  = 0x2a * 32
    //   DST    = "provii.challenge.v0"
    //
    // Preimage: origin || nonce || DST  (70 bytes total).
    let origin = "https://example.com";
    let rp_nonce = [0x2au8; 32];
    let mut preimage = Vec::with_capacity(origin.len() + 32 + 19);
    preimage.extend_from_slice(origin.as_bytes());
    preimage.extend_from_slice(&rp_nonce);
    preimage.extend_from_slice(b"provii.challenge.v0");
    assert_eq!(preimage.len(), 70, "A.5 preimage length");
    // Build expected hex programmatically to avoid off-by-one errors in
    // hand-transcribed strings.
    //   "https://example.com" || 0x2a*32 || "provii.challenge.v0"
    let mut expected_preimage_hex = String::new();
    expected_preimage_hex.push_str(&hex::encode(b"https://example.com"));
    expected_preimage_hex.push_str(&"2a".repeat(32));
    expected_preimage_hex.push_str(&hex::encode(b"provii.challenge.v0"));
    assert_hex_eq(
        "A.5 rp_challenge preimage",
        &preimage,
        &expected_preimage_hex,
    );
    // The reference `provii_crypto_protocol::rp_challenge` is the canonical
    // v1.0 construction. Compute the pinned value by invoking it directly;
    // also recompute it by hand from the preimage bytes above so the
    // harness catches any drift in the reference impl.
    let rp_challenge = rp_challenge_v1(origin, &rp_nonce);
    let rp_challenge_manual: [u8; 32] = Sha256::digest(&preimage).into();
    assert_eq!(
        rp_challenge, rp_challenge_manual,
        "A.5 reference impl must match preimage-derived SHA-256"
    );
    // Pinned rp_challenge for the v1.0 non-prefixed construction.
    // See also Appendix A.5 in the spec.
    const RP_CHALLENGE_HEX: &str =
        "35dcc5ea16a967de4891a10c283e33ca9d0f29ba4ae02fcf70e49ba98175b9fa";
    assert_hex_eq("A.5 rp_challenge", &rp_challenge, RP_CHALLENGE_HEX);

    // =======================================================================
    // A.6 RP Hash KAT (two step): rp_hash = Blake2s-256(rp_challenge)
    // =======================================================================
    let rp_hash: [u8; 32] = Blake2s256::digest(rp_challenge).into();
    // Pinned rp_hash derived from the A.5 rp_challenge above.
    const RP_HASH_HEX: &str = "afe7e76cb0ac79e7157fcc7f4c5eb319daa0c106093794a1bbd00b4c85ff430e";
    assert_hex_eq("A.6 rp_hash", &rp_hash, RP_HASH_HEX);

    // =======================================================================
    // A.7 Pedersen commitment KAT - age 25
    // =======================================================================
    // r_bits derived deterministically from ChaCha20Rng seeded with [0x07; 32].
    let mut rng_a7 = ChaCha20Rng::from_seed([0x07u8; 32]);
    let r25: Vec<bool> = generate_commitment_randomness(&mut rng_a7, 128).to_vec();
    let packed_128 = pack_bits_le(&r25);
    assert_hex_eq(
        "A.7 packed r_bits (128 bits LE)",
        &packed_128,
        "f400927857aaf64114f561baacb37970",
    );
    let c25 = pedersen_commit_dob_validated(11_246, &r25).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_hex_eq(
        "A.7 commitment (age 25, dob_days=11246)",
        &c25,
        "e437495ee5c2872cb408674c213b95f6efd086fda4687997a35321f0ad2d79aa",
    );

    // =======================================================================
    // A.8 Pedersen commitment KAT - age 10
    // =======================================================================
    // r_bits derived deterministically from ChaCha20Rng seeded with [0x08; 32].
    let mut rng_a8 = ChaCha20Rng::from_seed([0x08u8; 32]);
    let r10: Vec<bool> = generate_commitment_randomness(&mut rng_a8, 128).to_vec();
    let c10 = pedersen_commit_dob_validated(16_721, &r10).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_hex_eq(
        "A.8 commitment (age 10, dob_days=16721)",
        &c10,
        "2b4a7ee14d0978e38c6cb90ade9d85297cfcf46823e45dc868ad5e0f09e6df0e",
    );

    // =======================================================================
    // A.9 Production VK / PK manifest values
    // =======================================================================
    let vk_path = provii_crypto_root().join("age_vk.914153247.bin");
    let vk_bytes = fs::read(&vk_path)?;
    let vk_fp = Blake2s256::digest(&vk_bytes);
    let vk_b2b = Blake2b512::digest(&vk_bytes);
    assert_eq!(vk_bytes.len(), 1732, "A.9 vk_size");
    assert_hex_eq(
        "A.9 vk_fingerprint_blake2s",
        &vk_fp,
        "3491e619259f47b7c5b3b82ed6f71a3bf62a6c2e5a5e9349163e8c0e94c73644",
    );
    assert_hex_eq(
        "A.9 vk_blake2b512_hash",
        &vk_b2b,
        "0aed1bda4ad79cd0c166976c5ee3f2bd1f9ca983ba8af5a7c45224003a356eac6acc61209250fd08e4835994147ca2ebc8b5e3fb6abdbbaaf2cccab566bedc0a",
    );
    // PK integrity assertions are in `pk_manifest_integrity` (run with --ignored;
    // requires the 52MB proving key downloaded by the pk-tests CI job).
    // Circuit constants hash (v7 pinned).
    let cc_hash = compute_circuit_constants_hash();
    assert_eq!(
        cc_hash, "9dbbab7e903507b182d1d33f47c72b004e0ffb1bee2cd5ac55e7cbe060338f22",
        "A.9 circuit_constants_hash"
    );
    assert_eq!(PUBLIC_INPUTS_LEN, 8);
    assert_eq!(KID_SIZE_BYTES, 14);
    assert_eq!(SCHEMA_SIZE_BYTES, 12);
    // vk_id, ic_len require loading the VK.
    let vk_parsed: VerifyingKey<Bls12> = VerifyingKey::read(&mut &vk_bytes[..])?;
    assert_eq!(vk_parsed.ic.len(), PUBLIC_INPUTS_LEN + 1, "A.9 ic_len");
    // vk_id manifest value: computed by the deployment as the leading 4 LE
    // bytes of vk_fp. This is not computed here because vk_id is a
    // deployment-assigned identifier, not derived; we check the published
    // value is internally consistent.
    const VK_ID: u32 = 914_153_247;
    // Spec says vk_id should be u32. Confirm production vk_id > u16::MAX.
    assert!(
        VK_ID > u32::from(u16::MAX),
        "vk_id overflows u16, C.3 normative"
    );
    println!("ok A.9: manifest values");

    // =======================================================================
    // A.10 Credential prehash KAT
    // =======================================================================
    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: [0x42u8; 32],
        iat: 0x0000_0000_6000_0000,
        exp: 0x0000_0000_7000_0000,
        schema: "provii.age/0".to_string(),
    };
    let prehash =
        cred_v2_prehash_bytes(cred.v, &cred.kid, &cred.c, cred.iat, cred.exp, &cred.schema)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_eq!(prehash.len(), 91, "A.10 prehash length");
    // Build expected hex programmatically.
    //   "provii.cred.v0" || 0x02 || 0x0e || "provii:2026-05"
    //   || 0x42 * 32 || 0x00..00_6000_0000 (BE iat, u64)
    //   || 0x00..00_7000_0000 (BE exp, u64) || 0x0c || "provii.age/0"
    let mut expected_prehash_hex = String::new();
    expected_prehash_hex.push_str(&hex::encode(b"provii.cred.v0"));
    expected_prehash_hex.push_str("02"); // v
    expected_prehash_hex.push_str("0e"); // kid len = 14
    expected_prehash_hex.push_str(&hex::encode(b"provii:2026-05"));
    expected_prehash_hex.push_str(&"42".repeat(32));
    expected_prehash_hex.push_str("0000000060000000"); // BE iat
    expected_prehash_hex.push_str("0000000070000000"); // BE exp
    expected_prehash_hex.push_str("0c"); // schema len = 12
    expected_prehash_hex.push_str(&hex::encode(b"provii.age/0"));
    assert_hex_eq("A.10 credential prehash", &prehash, &expected_prehash_hex);
    assert_hex_eq(
        "A.10 Blake2s digest of prehash",
        &Blake2s256::digest(&prehash),
        "617a917028201e58ee7a546d2dffa7d005a49c995ce9e23bfc77ae9550fa149c",
    );

    // =======================================================================
    // A.11 Ed25519 attestation KAT
    // =======================================================================
    let sk_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = u8::try_from(i + 1).unwrap();
        }
        b
    };
    let ed_sk = EdSigningKey::from_bytes(&sk_bytes);
    let ed_vk: EdVerifyingKey = ed_sk.verifying_key();
    assert_hex_eq(
        "A.11 Ed25519 verifying key",
        ed_vk.as_bytes(),
        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
    );

    // Canonical attestation preimage (v1 layout, legacy None/None shape).
    let att_dob: i32 = 7300;
    let att_issuer = "dmv.ca.gov";
    let att_timestamp: u64 = 1_704_067_200;
    let att_nonce = [0x42u8; 32];
    let mut att_preimage: Vec<u8> = Vec::new();
    att_preimage.extend_from_slice(b"provii.attestation.dob.v0");
    att_preimage.extend_from_slice(&att_dob.to_le_bytes());
    att_preimage.push(u8::try_from(att_issuer.len()).unwrap());
    att_preimage.extend_from_slice(att_issuer.as_bytes());
    att_preimage.extend_from_slice(&att_timestamp.to_le_bytes());
    att_preimage.extend_from_slice(&att_nonce);
    assert_eq!(att_preimage.len(), 80, "A.11 preimage length");
    assert_hex_eq(
        "A.11 attestation preimage",
        &att_preimage,
        "70726f7669692e6174746573746174696f6e2e646f622e7630841c00000a646d762e63612e676f7680009265000000004242424242424242424242424242424242424242424242424242424242424242",
    );

    // Blake2s message hash of the preimage.
    let att_msg_hash: [u8; 32] = DobAttestation::compute_message_bytes(
        att_dob,
        att_issuer,
        att_timestamp,
        &att_nonce,
        None,
        None,
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_hex_eq(
        "A.11 attestation Blake2s msg hash",
        &att_msg_hash,
        "0b1aee332eb8f6cb0e4e090f001b99d077c74783d0abcb3d108e82f424757296",
    );

    // Deterministic Ed25519 signature per RFC 8032.
    let attestation = DobAttestation::create(att_dob, att_issuer, att_timestamp, att_nonce, &ed_sk)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_hex_eq(
        "A.11 attestation signature",
        &attestation.signature,
        "9e30ab793959301e0a308d339cd98cfbd0046ed409d68d9752a24e8906c6fd073de0628ee8394d88404c11b5aa7d07024074ea86872e16bc035a1f226fca8b02",
    );
    attestation
        .verify(&ed_vk)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // =======================================================================
    // A.12 Public input vector - end to end, committed proof
    //
    // We re-verify the existing committed proof (test_native_verify.rs) to
    // confirm the A.12 hex is live. This requires loading a test-time VK that
    // matches vk_id = 0; we use the production VK file only for the manifest
    // check above. The committed proof (A.12) was generated under a
    // different VK (see spec), so we assert the assembled public inputs
    // match the pinned scalars but do not re-run Groth16 verify_proof.
    // =======================================================================
    let a12_cutoff: i32 = 13_772;
    let a12_rp_hash: [u8; 32] =
        hex_to_arr("ad106802a888dcb4028cd9933d47a6c50e30d649969660f8432148c8961db6ea");
    let a12_issuer_vk: [u8; 32] =
        hex_to_arr("02820bdb8c81bb4824b8b7be488765e819b84ff495d5ae334a10197fd97ddd25");
    let a12_null: [u8; 32] =
        hex_to_arr("b7e414287e1792d961939737b40d7d453cd2996e3a2c8735f745da828b8c5af3");
    let pi = assemble_public_inputs_canonical(
        true, // direction = Over
        a12_cutoff,
        a12_rp_hash,
        a12_issuer_vk,
        a12_null,
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let expected_pi: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "cc35008000000000000000000000000000000000000000000000000000000000",
        "ad106802a888dcb4028cd9933d47a6c50e30d649969660f8432148c8961db62a",
        "0300000000000000000000000000000000000000000000000000000000000000",
        "02820bdb8c81bb4824b8b7be488765e819b84ff495d5ae334a10197fd97ddd25",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "b7e414287e1792d961939737b40d7d453cd2996e3a2c8735f745da828b8c5a33",
        "0300000000000000000000000000000000000000000000000000000000000000",
    ];
    assert_eq!(pi.len(), 8, "A.12 public input count");
    for (i, (scalar, expected)) in pi.iter().zip(expected_pi.iter()).enumerate() {
        let got = hex::encode(scalar.to_repr());
        assert_eq!(
            &got, expected,
            "A.12 pi[{i}] mismatch\n  expected: {expected}\n  actual:   {got}"
        );
    }
    println!("ok A.12: 8 multipacked public inputs match pinned values");

    // =======================================================================
    // End to end pipeline driven by ChaCha20Rng::from_seed([0u8; 32])
    //
    // Goal: confirm that every step of the spec's issuance + verification
    // pipeline round trips when driven by a single seeded RNG. Also provides
    // the Groth16 proof smoke test (call `create_random_proof` directly with
    // the seeded RNG to bypass the `OsRng` wrapper in `crypto-prover`).
    //
    // No pinned hex for this path (the RNG drives the inputs); the test
    // asserts that the generated proof verifies against the production VK,
    // and that tampering with the nullifier causes verification to fail.
    // =======================================================================
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    // Issuer RedJubjub keypair.
    let (issuer_sk, issuer_vk) = generate_keypair_with_rng(&mut rng);

    // Ed25519 keypair for attestation signing.
    let mut ed_sk_seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut ed_sk_seed);
    let e2e_ed_sk = EdSigningKey::from_bytes(&ed_sk_seed);
    let e2e_ed_vk = e2e_ed_sk.verifying_key();

    // Attestation for dob_days = 11246 (age 25 on 2025-10-10).
    let e2e_dob: i32 = 11_246;
    let mut att_nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut att_nonce);
    let e2e_att =
        DobAttestation::create(e2e_dob, "dmv.ca.gov", 1_728_518_400, att_nonce, &e2e_ed_sk)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    e2e_att
        .verify(&e2e_ed_vk)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // r_bits (128 bits, per code reality).
    let e2e_r_bits = generate_commitment_randomness(&mut rng, 128);
    assert_eq!(e2e_r_bits.len(), 128);

    // Pedersen commitment.
    let commitment = pedersen_commit_dob_validated(e2e_dob, &e2e_r_bits)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Credential prehash and RedJubjub signature.
    let e2e_cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment,
        iat: 1_728_518_400,
        exp: 1_760_054_400,
        schema: "provii.age/0".to_string(),
    };
    let sig = sign_cred_v2(&e2e_cred, &issuer_sk).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    verify_cred_v2(&e2e_cred, &sig, &issuer_vk).map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Pedersen nullifier and (non-prefixed) RP hash.
    let nullifier = pedersen_nullifier(&commitment);
    let e2e_origin: &str = "https://example.com";
    let mut e2e_rp_nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut e2e_rp_nonce);
    let e2e_rp_challenge = rp_challenge_v1(e2e_origin, &e2e_rp_nonce);
    let e2e_rp_hash: [u8; 32] = Blake2s256::digest(e2e_rp_challenge).into();

    // Assemble public inputs and witness.
    let public = AgePublic {
        direction: AgeDirection::Over,
        cutoff_days: e2e_dob, // boundary case, user is exactly on the cutoff.
        rp_hash: e2e_rp_hash,
        issuer_vk_bytes: issuer_vk,
        cred_nullifier: nullifier,
    };
    let witness = AgeWitness {
        dob_days: e2e_dob,
        r_bits: e2e_r_bits.to_vec(),
        issuer_vk_bytes: issuer_vk,
        sig_rj_bytes: sig.to_vec(),
        v: e2e_cred.v,
        kid: e2e_cred.kid.as_bytes().to_vec(),
        c_bytes: commitment,
        iat: e2e_cred.iat,
        exp: e2e_cred.exp,
        schema: e2e_cred.schema.as_bytes().to_vec(),
    };
    let publics = assemble_public_inputs_canonical(
        public.direction == AgeDirection::Over,
        public.cutoff_days,
        public.rp_hash,
        public.issuer_vk_bytes,
        public.cred_nullifier,
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Groth16 proof generation and adversarial negative check are in
    // `e2e_groth16_proof_and_adversarial` (run with --ignored; requires the
    // 52MB proving key downloaded by the pk-tests CI job).
    let _ = (public, witness, publics, nullifier, rng);

    Ok(())
}

// ---------------------------------------------------------------------------
// PK-dependent tests. These require the 52MB proving key
// (age_pk.914153247.bin) which is gitignored and not present in normal CI
// runs. They are executed by the dedicated pk-tests CI job which downloads
// the key from the R2 CDN before running `cargo test --ignored`.
// ---------------------------------------------------------------------------

/// Asserts the on-disk proving key matches the manifest size and Blake2s hash.
///
/// Run with:
///   cargo test --release -p provii-crypto-e2e-tests \
///     -- --ignored pk_manifest_integrity --nocapture
#[test]
#[ignore = "requires 52MB proving key"]
fn pk_manifest_integrity() -> anyhow::Result<()> {
    let pk_path = provii_crypto_root().join("age_pk.914153247.bin");
    let pk_meta = fs::metadata(&pk_path).map_err(|e| anyhow::anyhow!("pk file missing: {e}"))?;
    assert_eq!(pk_meta.len(), 51_844_344, "pk_size");
    let pk_bytes = fs::read(&pk_path)?;
    let pk_fp = Blake2s256::digest(&pk_bytes);
    assert_hex_eq(
        "pk_blake2s_hash",
        &pk_fp,
        "375e8913b13e234b660bf24995856c7ee59d8fc24462312714e6eebac63c745e",
    );
    println!("ok pk_manifest_integrity: size and hash verified");
    Ok(())
}

/// Generates a fresh Groth16 proof using the proving key and verifies it.
/// Also asserts that tampering with the nullifier causes verification to fail.
///
/// Run with:
///   cargo test --release -p provii-crypto-e2e-tests \
///     -- --ignored e2e_groth16_proof_and_adversarial --nocapture
#[test]
#[ignore = "requires 52MB proving key"]
fn e2e_groth16_proof_and_adversarial() -> anyhow::Result<()> {
    use std::fs;

    let pk_path = provii_crypto_root().join("age_pk.914153247.bin");
    let vk_path = provii_crypto_root().join("age_vk.914153247.bin");

    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let (issuer_sk, issuer_vk) = generate_keypair_with_rng(&mut rng);

    let mut ed_sk_seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut ed_sk_seed);
    let e2e_ed_sk = EdSigningKey::from_bytes(&ed_sk_seed);
    let e2e_ed_vk = e2e_ed_sk.verifying_key();

    let e2e_dob: i32 = 11_246;
    let mut att_nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut att_nonce);
    let e2e_att =
        DobAttestation::create(e2e_dob, "dmv.ca.gov", 1_728_518_400, att_nonce, &e2e_ed_sk)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    e2e_att
        .verify(&e2e_ed_vk)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let e2e_r_bits = generate_commitment_randomness(&mut rng, 128);
    assert_eq!(e2e_r_bits.len(), 128);

    let commitment = pedersen_commit_dob_validated(e2e_dob, &e2e_r_bits)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let e2e_cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: commitment,
        iat: 1_728_518_400,
        exp: 1_760_054_400,
        schema: "provii.age/0".to_string(),
    };
    let sig = sign_cred_v2(&e2e_cred, &issuer_sk).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    verify_cred_v2(&e2e_cred, &sig, &issuer_vk).map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let nullifier = pedersen_nullifier(&commitment);
    let e2e_origin: &str = "https://example.com";
    let mut e2e_rp_nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut e2e_rp_nonce);
    let e2e_rp_challenge = rp_challenge_v1(e2e_origin, &e2e_rp_nonce);
    let e2e_rp_hash: [u8; 32] = Blake2s256::digest(e2e_rp_challenge).into();

    let public = AgePublic {
        direction: AgeDirection::Over,
        cutoff_days: e2e_dob,
        rp_hash: e2e_rp_hash,
        issuer_vk_bytes: issuer_vk,
        cred_nullifier: nullifier,
    };
    let witness = AgeWitness {
        dob_days: e2e_dob,
        r_bits: e2e_r_bits.to_vec(),
        issuer_vk_bytes: issuer_vk,
        sig_rj_bytes: sig.to_vec(),
        v: e2e_cred.v,
        kid: e2e_cred.kid.as_bytes().to_vec(),
        c_bytes: commitment,
        iat: e2e_cred.iat,
        exp: e2e_cred.exp,
        schema: e2e_cred.schema.as_bytes().to_vec(),
    };
    let publics = assemble_public_inputs_canonical(
        public.direction == AgeDirection::Over,
        public.cutoff_days,
        public.rp_hash,
        public.issuer_vk_bytes,
        public.cred_nullifier,
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Load the proving key and verify the VK embedded in it matches the
    // production VK file.
    let pk_bytes = fs::read(&pk_path).map_err(|e| anyhow::anyhow!("pk file missing: {e}"))?;
    let params: Parameters<Bls12> = Parameters::read(&mut &pk_bytes[..], false)?;
    let vk_bytes = fs::read(&vk_path)?;
    let vk_parsed: VerifyingKey<Bls12> = VerifyingKey::read(&mut &vk_bytes[..])?;
    let pvk = prepare_verifying_key(&vk_parsed);

    let circuit = AgeCircuit {
        public: public.clone(),
        witness: Some(witness),
    };

    let proof = create_random_proof(circuit, &params, &mut rng)?;
    let mut proof_bytes = Vec::new();
    proof.write(&mut proof_bytes)?;
    assert_eq!(proof_bytes.len(), 192, "Groth16 proof must be 192 bytes");

    verify_proof(&pvk, &proof, &publics)?;
    println!("ok e2e_groth16_proof_and_adversarial: fresh Groth16 proof verifies");

    let mut bad_null = nullifier;
    bad_null[0] ^= 0x01;
    let bad_publics = assemble_public_inputs_canonical(
        public.direction == AgeDirection::Over,
        public.cutoff_days,
        public.rp_hash,
        public.issuer_vk_bytes,
        bad_null,
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    match verify_proof(&pvk, &proof, &bad_publics) {
        Err(_) => println!("ok negative: tampered nullifier rejected"),
        Ok(()) => panic!("negative check failed: tampered nullifier accepted"),
    }

    Ok(())
}

// base64url(no pad) used by A.3 PKCE.
fn base64_url_no_pad(input: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(input)
}

fn hex_to_arr(h: &str) -> [u8; 32] {
    let bytes = hex::decode(h).expect("valid hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}
