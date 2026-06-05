// Example/tool code: println, eprintln, unwrap, expect, indexing, arithmetic,
// and casts are acceptable for parameter generation tooling.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    deprecated
)]

use std::fs::{self, File};

use bellman::groth16::{generate_random_parameters, Parameters, VerifyingKey};
use bellman::Circuit;
use blake2::{Blake2b512, Blake2s256, Digest};
use bls12_381::Bls12;
use ff::PrimeField;
use provii_crypto_circuit_age::{AgeCircuit, AgeDirection, AgePublic, AgeWitness};
use provii_crypto_commit::pedersen_nullifier;
use rand_core::OsRng;
use serde_json::json;

/// Compute a Blake2s fingerprint of the verifying key.
fn vk_fingerprint(vk: &VerifyingKey<Bls12>) -> [u8; 32] {
    let mut bytes = Vec::new();
    vk.write(&mut bytes)
        .expect("Failed to serialize verifying key");

    let mut hasher = Blake2s256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

/// Compute VK ID using domain separator
fn compute_vk_id(vk: &VerifyingKey<Bls12>) -> u32 {
    let mut bytes = Vec::new();
    vk.write(&mut bytes)
        .expect("Failed to serialize verifying key");

    let mut hasher = Blake2s256::new();
    hasher.update(b"provii.vk.id.v0");
    hasher.update(&bytes);
    let result = hasher.finalize();

    u32::from_le_bytes([result[0], result[1], result[2], result[3]])
}

/// Helper function for Blake2s hashing
fn blake2s32(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(data);
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// Derive public inputs from witness values (matches optimized circuit)
fn public_from_witness(
    w: &AgeWitness,
    cutoff_days: i32,
    rp_hash: [u8; 32],
    direction: AgeDirection,
) -> AgePublic {
    // Use Pedersen for nullifier (matching the optimized circuit)
    let cred_nullifier = pedersen_nullifier(&w.c_bytes);

    AgePublic {
        direction,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes: w.issuer_vk_bytes, // Direct VK bytes, no hash
        cred_nullifier,
    }
}

/// Generate valid test witness values that won't cause constraint failures
fn generate_valid_test_witness() -> AgeWitness {
    // CRITICAL: These MUST match the sizes used in parameter generation!
    const KID_SIZE: usize = 14;
    const SCHEMA_SIZE: usize = 12;

    // Calculate proper epoch days
    let today_epoch_days = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86400) as i32;

    eprintln!("Today's epoch day: {today_epoch_days}");

    // Someone who is ~27 years old today (born 27 years ago)
    let dob_days = today_epoch_days - (27 * 365);
    eprintln!("Test DOB epoch day: {dob_days} (27 years ago)");

    // Commitment randomness for the dummy setup witness. Deterministic for
    // reproducibility, with enough byte diversity to satisfy
    // validate_commitment_randomness (which requires at least 8 distinct byte
    // values): byte k holds value k, giving 16 distinct bytes across 128 bits.
    let r_bits: Vec<bool> = (0..128)
        .map(|idx| {
            let k = (idx / 8) as u8;
            ((k >> (idx % 8)) & 1) == 1
        })
        .collect();

    // Compute the actual commitment using Pedersen
    use provii_crypto_commit::pedersen_commit_dob_validated;
    let c_bytes = pedersen_commit_dob_validated(dob_days, &r_bits).unwrap();
    eprintln!(
        "DEBUG [Host]: Pedersen commitment result: {}",
        hex::encode(c_bytes)
    );

    // Shape-defining values - MUST be exactly these sizes!
    let kid = b"provii:2026-05".to_vec(); // MUST be exactly 14 bytes
    let schema = b"provii.age/0".to_vec(); // MUST be exactly 12 bytes

    // Verify sizes are correct
    assert_eq!(kid.len(), KID_SIZE, "kid must be exactly {KID_SIZE} bytes");
    assert_eq!(
        schema.len(),
        SCHEMA_SIZE,
        "schema must be exactly {SCHEMA_SIZE} bytes"
    );

    // Valid timestamps
    let iat = 1735000000u64; // ~Dec 2024
    let exp = 1766536000u64; // ~Dec 2025

    // Generate a DETERMINISTIC signature that will pass verification
    use provii_crypto_commons::CredMsgV2;
    use provii_crypto_sig_redjubjub::{generate_keypair_with_rng, sign_cred_v2};
    use rand::{rngs::StdRng, SeedableRng};

    // Create a deterministic RNG with a fixed seed
    let mut rng = StdRng::seed_from_u64(12345);
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

    // Note: No rp_challenge in witness anymore (computed off-circuit)
    AgeWitness {
        dob_days,
        r_bits,
        issuer_vk_bytes,
        sig_rj_bytes,
        c_bytes,
        v: 2, // credential format version
        kid,
        iat,
        exp,
        schema,
    }
}

fn main() -> anyhow::Result<()> {
    // Direction no longer affects circuit structure. Unified circuit handles both.
    let direction = AgeDirection::Over; // Arbitrary; circuit shape is identical for both.
    eprintln!("Unified circuit (direction bit is a public input, not a structural parameter)");

    // Calculate proper cutoff days (18 years ago from today)
    let today_epoch_days = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86400) as i32;

    let cutoff_days = today_epoch_days - (18 * 365); // 18 years ago
    eprintln!("Cutoff epoch day: {cutoff_days} (18 years ago from today)");

    // Generate valid test witness
    let witness = generate_valid_test_witness();

    // Generate test RP hash (computed off-circuit now)
    let test_rp_challenge = [42u8; 32];
    let rp_hash = blake2s32(&test_rp_challenge);

    // CRITICAL: Derive public inputs from the witness with proper cutoff
    let public = public_from_witness(&witness, cutoff_days, rp_hash, direction);

    // Log the age check that will happen
    eprintln!("\n📅 Age check preview:");
    eprintln!("  Cutoff day: {cutoff_days} (must be born on or before this day)");
    eprintln!("  DOB day: {}", witness.dob_days);
    eprintln!(
        "  Check: {} >= {} = {}",
        cutoff_days,
        witness.dob_days,
        cutoff_days >= witness.dob_days
    );
    if cutoff_days >= witness.dob_days {
        eprintln!("  ✅ Person is old enough (born before cutoff)");
    } else {
        eprintln!("  ❌ Person is too young (born after cutoff)");
    }

    // Log the shapes for verification
    let kid_len = witness.kid.len();
    let schema_len = witness.schema.len();
    let r_bits_len = witness.r_bits.len();

    eprintln!("\n🔍 Shape parameters:");
    eprintln!("  kid length: {kid_len} bytes");
    eprintln!("  schema length: {schema_len} bytes");
    eprintln!("  r_bits length: {r_bits_len} bits");

    // Log the computed public inputs
    eprintln!("\n📊 Public inputs (derived from witness):");
    eprintln!("  cutoff_days: {}", public.cutoff_days);
    eprintln!("  rp_hash: {}", hex::encode(public.rp_hash));
    eprintln!("  issuer_vk_bytes: {}", hex::encode(public.issuer_vk_bytes));
    eprintln!(
        "  cred_nullifier (Pedersen): {}",
        hex::encode(public.cred_nullifier)
    );

    use provii_crypto_circuit_age::compute_circuit_constants_hash;
    let constants_hash = compute_circuit_constants_hash();
    eprintln!("\n🔐 Circuit constants hash: {constants_hash}");

    eprintln!("Scalar::CAPACITY = {}", bls12_381::Scalar::CAPACITY);

    // Generate parameters WITHOUT witness to avoid baking in values
    eprintln!("\n🔧 Generating trusted setup parameters...");
    eprintln!("  This may take several minutes for large circuits.");
    eprintln!("  Using shape-only circuit (no witness) for parameter generation...");
    eprintln!("  Note: Circuit now has ~55k fewer constraints from optimizations!");

    // Create a circuit without witness for parameter generation
    let param_gen_circuit = AgeCircuit {
        public: public.clone(),
        witness: None, // No witness during param gen!
    };

    let mut rng = OsRng;
    let params: Parameters<Bls12> =
        generate_random_parameters::<Bls12, _, _>(param_gen_circuit, &mut rng)?;

    // Calculate VK fingerprint and ID for filenames
    let vk = &params.vk;
    let vk_fp = vk_fingerprint(vk);
    let vk_id = compute_vk_id(vk);

    // Create filenames with VK ID in decimal format (unified circuit, no direction prefix)
    let pk_filename = format!("age_pk.{vk_id}.bin");
    let vk_filename = format!("age_vk.{vk_id}.bin");

    // Write proving key
    let mut pk_file = File::create(&pk_filename)?;
    params.write(&mut pk_file)?;
    pk_file.sync_all()?;
    drop(pk_file);

    // Read back and compute integrity check
    let pk_bytes = fs::read(&pk_filename)?;
    let pk_size = pk_bytes.len();
    let mut pk_hasher = Blake2s256::new();
    pk_hasher.update(&pk_bytes);
    let pk_hash: [u8; 32] = pk_hasher.finalize().into();

    eprintln!(
        "\n✅ Proving key written to {} ({:.2} MB)",
        pk_filename,
        pk_size as f64 / 1_048_576.0
    );
    eprintln!("  Size: {pk_size} bytes");
    eprintln!("  Blake2s: {}", hex::encode(pk_hash));

    // Write verifying key
    let mut vk_file = File::create(&vk_filename)?;
    vk.write(&mut vk_file)?;
    vk_file.sync_all()?;
    drop(vk_file);

    let vk_bytes = fs::read(&vk_filename)?;
    let vk_size = vk_bytes.len();

    eprintln!(
        "✅ Verifying key written to {} ({:.2} KB)",
        vk_filename,
        vk_size as f64 / 1024.0
    );

    let actual_constraints = {
        use bellman::gadgets::test::TestConstraintSystem;

        // Need to create a test witness to count constraints
        let test_witness = generate_valid_test_witness();
        let test_public = public_from_witness(&test_witness, cutoff_days, rp_hash, direction);

        let count_circuit = AgeCircuit {
            public: test_public,
            witness: Some(test_witness),
        };

        let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();
        count_circuit
            .synthesize(&mut cs)
            .expect("synthesis for counting");
        cs.num_constraints()
    };

    // Compute Blake2b-512 hash of VK (matching provii-verifier's integrity check algorithm)
    let mut vk_b2b_hasher = Blake2b512::new();
    vk_b2b_hasher.update(&vk_bytes);
    let vk_blake2b512_hash: [u8; 64] = vk_b2b_hasher.finalize().into();

    eprintln!(
        "✅ VK Blake2b-512 hash: {}",
        hex::encode(vk_blake2b512_hash)
    );

    let expected_public_inputs = params.vk.ic.len().saturating_sub(1);

    // Create manifest file with all metadata for verification
    let pk_url = format!("https://cdn.provii.app/age_pk.{vk_id}.bin");
    let manifest = json!({
        "vk_id": vk_id,
        "vk_fingerprint_blake2s": hex::encode(vk_fp),
        "vk_blake2b512_hash": hex::encode(vk_blake2b512_hash),
        "circuit_constants_hash": constants_hash,
        "pk_filename": pk_filename,
        "pk_size_bytes": pk_size,
        "pk_blake2s_hash": hex::encode(pk_hash),
        "pk_url": pk_url,
        "vk_filename": vk_filename,
        "vk_size_bytes": vk_size,
        "expected_public_inputs": expected_public_inputs,
        "shape": {
            "kid_bytes": kid_len,
            "schema_bytes": schema_len,
            "constraints": actual_constraints,
            "public_inputs": expected_public_inputs,
        },
        "optimizations": {
            "rp_hash": "computed off-circuit",
            "issuer_vk": "direct bytes (no hash)",
            "nullifier": "Pedersen-based",
            "direction": "unified circuit with direction bit public input",
        },
        "query_lengths": {
            "ic_len": params.vk.ic.len(),
            "note": "Other query lengths (a, b_g1, b_g2, h, l) are private in Parameters struct"
        },
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "bellman_version": "0.14.0",
        "backend": "bls12_381"
    });

    let manifest_filename = format!("age_pk.{vk_id}.manifest.json");
    fs::write(&manifest_filename, serde_json::to_string_pretty(&manifest)?)?;

    // Write canonical manifest to repo root (for downstream consumers and CI)
    let manifest_pretty = serde_json::to_string_pretty(&manifest)?;
    if let Ok(cargo_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        // Running as `cargo run --example`, workspace root is parent of crypto-circuit-age
        let workspace_root = std::path::Path::new(&cargo_dir)
            .parent()
            .unwrap_or(std::path::Path::new("."));

        let root_manifest = workspace_root.join("zk-params-manifest.json");
        fs::write(&root_manifest, &manifest_pretty)?;
        eprintln!(
            "✅ Canonical manifest written to {}",
            root_manifest.display()
        );

        // Copy VK binary to repo root for easy access. Guard against a
        // self-copy: when the run already happens from the workspace root the
        // source and destination are the same path, and fs::copy truncates the
        // destination before reading, which would zero the file.
        let root_vk = workspace_root.join(&vk_filename);
        let src_canon = std::fs::canonicalize(&vk_filename).ok();
        let dst_canon = std::fs::canonicalize(&root_vk).ok();
        if src_canon.is_some() && src_canon == dst_canon {
            eprintln!("✅ VK binary already at repo root {}", root_vk.display());
        } else {
            fs::copy(&vk_filename, &root_vk)?;
            eprintln!("✅ VK binary copied to {}", root_vk.display());
        }
    }

    // Validation section - test that generated parameters actually work
    eprintln!("\n🔍 Validating generated parameters can create and verify proofs...");

    // Re-create test data for validation
    let test_witness = generate_valid_test_witness();

    // CRITICAL: Use the same cutoff_days we calculated earlier
    let test_public = public_from_witness(&test_witness, cutoff_days, rp_hash, direction);

    eprintln!("\n📊 Test public inputs (for validation):");
    eprintln!("  cutoff_days: {}", test_public.cutoff_days);
    eprintln!("  rp_hash: {}", hex::encode(test_public.rp_hash));
    eprintln!(
        "  issuer_vk_bytes: {}",
        hex::encode(test_public.issuer_vk_bytes)
    );
    eprintln!(
        "  cred_nullifier: {}",
        hex::encode(test_public.cred_nullifier)
    );

    // FIRST: Do the satisfiability check
    {
        use bellman::gadgets::test::TestConstraintSystem;

        let test_circ = AgeCircuit {
            public: test_public.clone(),
            witness: Some(test_witness.clone()),
        };

        let mut tcs = TestConstraintSystem::<bls12_381::Scalar>::new();
        test_circ
            .synthesize(&mut tcs)
            .expect("synthesis in test constraint system");

        if !tcs.is_satisfied() {
            eprintln!("\n❌ Circuit not satisfied!");
            if let Some(unsatisfied) = tcs.which_is_unsatisfied() {
                eprintln!("   Failed constraint: {unsatisfied}");
            }
            eprintln!("   Total constraints: {}", tcs.num_constraints());
            std::process::exit(1);
        } else {
            eprintln!("\n✅ All constraints satisfied in test");
            eprintln!(
                "   Total constraints: {} (reduced from ~117k)",
                tcs.num_constraints()
            );
        }
    }

    // THEN: Create the circuit for proof generation
    let test_circuit = AgeCircuit {
        public: test_public.clone(),
        witness: Some(test_witness),
    };

    // Try to create a proof with the generated parameters
    use bellman::groth16::{create_random_proof, prepare_verifying_key, verify_proof};
    use provii_crypto_public_inputs::assemble_public_inputs_canonical;

    match create_random_proof(test_circuit, &params, &mut rng) {
        Ok(proof) => {
            eprintln!("  ✅ Proof generation successful");

            // Now verify it with the CORRECTLY DERIVED public inputs
            let pvk = prepare_verifying_key(&params.vk);
            let direction_bool = test_public.direction == AgeDirection::Over;
            let public_inputs = assemble_public_inputs_canonical(
                direction_bool,
                test_public.cutoff_days,
                test_public.rp_hash,
                test_public.issuer_vk_bytes, // Direct VK bytes
                test_public.cred_nullifier,
            )?;

            // DEBUG: Log the exact public inputs being used for verification
            eprintln!("\n  📊 Public inputs for verification:");
            eprintln!("    Count: {} (expected 8)", public_inputs.len());
            for (i, pi) in public_inputs.iter().enumerate() {
                use ff::PrimeField;
                eprintln!("    pi[{}] = {}", i, hex::encode(pi.to_repr()));
            }

            match verify_proof(&pvk, &proof, &public_inputs) {
                Ok(()) => {
                    eprintln!("\n  ✅ Proof verification successful");
                    eprintln!("  ✅ Parameters are valid and can create verifiable proofs!");
                }
                Err(e) => {
                    eprintln!("\n  ❌ FATAL: Proof verification failed: {e:?}");
                    eprintln!("     This should not happen with correctly derived public inputs.");
                    eprintln!("     Check that the circuit and host compute matching values.");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("  ❌ FATAL: Could not create proof with generated parameters!");
            eprintln!("     Error: {e:?}");
            eprintln!("     This likely means the circuit has issues.");
            std::process::exit(1);
        }
    }

    // Display VK fingerprint for verification
    let vk_fp = vk_fingerprint(vk);
    let vk_id_check = u64::from_le_bytes(vk_fp[0..8].try_into().unwrap());

    eprintln!("\n📋 Verification key fingerprint:");
    eprintln!("  Blake2s (full): {}", hex::encode(vk_fp));
    eprintln!("  VK ID: {vk_id_check:016x}");

    eprintln!("\n✅ Parameter generation complete!");
    eprintln!("  These parameters define the optimized circuit shape for:");
    eprintln!("    - kid: {kid_len} bytes");
    eprintln!("    - schema: {schema_len} bytes");
    eprintln!("    - ~55k fewer constraints than before");
    eprintln!("  ⚠️ Ensure all proofs use exactly these lengths!");

    Ok(())
}
