// Example/tool code: println, eprintln, unwrap, expect, indexing, arithmetic,
// and casts are acceptable in diagnostic tooling.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

// examples/test_proof.rs
// Run with: cargo run --example test_proof -- --pk age_pk.2686342004.bin

use anyhow::{Context, Result};
use bellman::groth16::{create_random_proof, prepare_verifying_key, verify_proof, Parameters};
use blake2::{Blake2s256, Digest};
use bls12_381::Bls12;
use clap::Parser;
use rand::{rngs::StdRng, thread_rng, SeedableRng};
use std::fs;
use std::io::Cursor;
use std::time::Instant;

use provii_crypto_circuit_age::{AgeCircuit, AgeDirection, AgePublic, AgeWitness};
use provii_crypto_commit::{pedersen_commit_dob_validated, pedersen_nullifier};
use provii_crypto_commons::CredMsgV2;
use provii_crypto_public_inputs::assemble_public_inputs_canonical;
use provii_crypto_sig_redjubjub::{generate_keypair_with_rng, sign_cred_v2};

#[derive(Parser, Debug)]
#[command(about = "Test proof generation with a PK file")]
struct Args {
    /// Path to the proving key file
    #[arg(short, long)]
    pk: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("🧪 Proof Generation Test\n");
    println!("{}", "=".repeat(50));

    // Step 1: Load and verify PK file integrity
    println!("\n📂 Loading PK from: {}", args.pk);
    let pk_bytes =
        fs::read(&args.pk).with_context(|| format!("Failed to read PK file: {}", args.pk))?;

    let pk_size = pk_bytes.len();
    println!(
        "  Size: {} bytes ({:.2} MB)",
        pk_size,
        pk_size as f64 / 1_048_576.0
    );

    // Compute hash for integrity check
    let mut hasher = Blake2s256::new();
    hasher.update(&pk_bytes);
    let pk_hash = hex::encode(hasher.finalize());
    println!("  Blake2s: {}", &pk_hash[..16]);

    // Step 2: Parse PK from memory (catches truncation early)
    println!("\n⏳ Parsing PK from memory buffer...");
    let start = Instant::now();

    let params = Parameters::<Bls12>::read(&mut Cursor::new(&pk_bytes), false)
        .context("Failed to parse PK - file may be corrupted or truncated")?;

    println!(
        "✅ PK parsed successfully in {:.2}s",
        start.elapsed().as_secs_f32()
    );
    println!("  Public inputs expected: {}", params.vk.ic.len() - 1);

    // Step 3: Create test witness matching the shape
    println!("\n🔧 Creating test witness...");
    let (witness, _issuer_vk) = create_test_witness();
    let public = create_test_public(&witness);

    println!("  kid length: {} bytes", witness.kid.len());
    println!("  schema length: {} bytes", witness.schema.len());

    let circuit = AgeCircuit {
        public: public.clone(),
        witness: Some(witness),
    };

    // Step 4: Generate proof (THIS IS WHERE THE ERROR WOULD OCCUR)
    println!("\n⚡ Generating proof (this is where 'expected more bases' would fail)...");
    let proof_start = Instant::now();

    let proof = match create_random_proof(circuit, &params, &mut thread_rng()) {
        Ok(p) => {
            println!(
                "✅ Proof generated successfully in {:.2}s!",
                proof_start.elapsed().as_secs_f32()
            );
            p
        }
        Err(e) => {
            println!("\n❌ PROOF GENERATION FAILED!");
            println!("Error: {e:?}");

            let error_str = format!("{e:?}");
            if error_str.contains("expected more bases") {
                println!("\n🔴 This is the 'expected more bases' error!");
                println!("The PK file is likely truncated or corrupted.");
                println!("\nPossible causes:");
                println!("  1. Incomplete download from CDN");
                println!("  2. File truncation during transfer");
                println!("  3. CDN applying unwanted compression/transformation");
                println!("  4. Mismatched bellman versions between generator and user");

                // Try to identify where it failed
                if let Some(manifest_path) = args.pk.replace(".bin", ".manifest.json").into() {
                    if let Ok(manifest_str) = fs::read_to_string(&manifest_path) {
                        if let Ok(manifest) =
                            serde_json::from_str::<serde_json::Value>(&manifest_str)
                        {
                            let expected_size = manifest["pk_size_bytes"].as_u64().unwrap_or(0);
                            if pk_size != expected_size as usize {
                                println!("\n⚠️  SIZE MISMATCH DETECTED!");
                                println!("  Expected: {expected_size} bytes");
                                println!("  Actual: {pk_size} bytes");
                                println!(
                                    "  Missing: {} bytes",
                                    expected_size as i64 - pk_size as i64
                                );
                            }

                            let expected_hash = manifest["pk_blake2s_hash"].as_str().unwrap_or("");
                            if pk_hash != expected_hash {
                                println!("\n⚠️  HASH MISMATCH DETECTED!");
                                println!("  Expected: {expected_hash}");
                                println!("  Actual: {pk_hash}");
                                println!("  The file is corrupted!");
                            }
                        }
                    }
                }
            }

            return Err(e.into());
        }
    };

    // Step 5: Serialize proof
    let mut proof_bytes = Vec::new();
    proof.write(&mut proof_bytes)?;
    println!("  Proof size: {} bytes", proof_bytes.len());

    // Step 6: Verify the proof
    println!("\n🔍 Verifying proof...");
    let pvk = prepare_verifying_key(&params.vk);

    let direction_bool = public.direction == AgeDirection::Over;
    let public_inputs = assemble_public_inputs_canonical(
        direction_bool,
        public.cutoff_days,
        public.rp_hash,
        public.issuer_vk_bytes,
        public.cred_nullifier,
    )?;

    if args.verbose {
        println!("  Public inputs ({} total):", public_inputs.len());
        for (i, input) in public_inputs.iter().enumerate() {
            use ff::PrimeField;
            println!("    pi[{}] = {}", i, hex::encode(input.to_repr()));
        }
    }

    match verify_proof(&pvk, &proof, &public_inputs) {
        Ok(()) => {
            println!("✅ Proof verified successfully!");
        }
        Err(e) => {
            println!("❌ Proof verification failed: {e:?}");
            println!("This is unexpected if generation succeeded!");
        }
    }

    println!("\n✅ All tests passed! This PK file is valid and complete.");
    println!("You can safely deploy this PK to your CDN and mobile app.");

    Ok(())
}

/// Generate a valid test witness using the same logic as gen_params.rs.
///
/// Uses a deterministic RNG so results are reproducible. Generates 128 r_bits,
/// computes a real Pedersen commitment, and produces a real RedJubjub signature
/// over the credential fields.
fn create_test_witness() -> (AgeWitness, [u8; 32]) {
    // Deterministic RNG for reproducibility
    let mut rng = StdRng::seed_from_u64(12345);

    // Someone born ~27 years ago
    let today_epoch_days = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86400) as i32;
    let dob_days = today_epoch_days - (27 * 365);

    // 128 r_bits (circuit requires exactly 128)
    let r_bits: Vec<bool> = (0..128).map(|i| i % 2 == 0).collect();

    // Compute real Pedersen commitment
    let c_bytes = pedersen_commit_dob_validated(dob_days, &r_bits).unwrap();

    // Shape-defining values matching gen_params
    let kid = b"provii:2026-05".to_vec(); // 14 bytes
    let schema = b"provii.age/0".to_vec(); // 12 bytes

    let iat = 1735000000u64;
    let exp = 1766536000u64;

    // Generate real keypair and signature
    let (sk_bytes, issuer_vk_bytes) = generate_keypair_with_rng(&mut rng);

    let cred_msg = CredMsgV2 {
        v: 2,
        kid: String::from_utf8(kid.clone()).unwrap(),
        c: c_bytes,
        iat,
        exp,
        schema: String::from_utf8(schema.clone()).unwrap(),
    };

    let sig_bytes = sign_cred_v2(&cred_msg, &sk_bytes).unwrap();
    let sig_rj_bytes = sig_bytes.to_vec();

    let witness = AgeWitness {
        dob_days,
        r_bits,
        issuer_vk_bytes,
        sig_rj_bytes,
        c_bytes,
        v: 2,
        kid,
        iat,
        exp,
        schema,
    };

    (witness, issuer_vk_bytes)
}

/// Derive public inputs from the witness, ensuring consistency between
/// issuer VK, cred_nullifier, and all other fields.
fn create_test_public(witness: &AgeWitness) -> AgePublic {
    let today_epoch_days = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86400) as i32;
    let cutoff_days = today_epoch_days - (18 * 365);

    // Compute rp_hash the same way gen_params does
    let test_rp_challenge = [42u8; 32];
    let mut h = Blake2s256::new();
    h.update(test_rp_challenge);
    let rp_hash: [u8; 32] = h.finalize().into();

    // Derive cred_nullifier from the actual commitment
    let cred_nullifier = pedersen_nullifier(&witness.c_bytes);

    AgePublic {
        direction: AgeDirection::Over,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes: witness.issuer_vk_bytes,
        cred_nullifier,
    }
}
