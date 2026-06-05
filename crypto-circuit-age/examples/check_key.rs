// Example/tool code: println, eprintln, unwrap, expect, indexing, arithmetic,
// and casts are acceptable in diagnostic tooling.
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
    clippy::string_slice
)]

// Cargo.toml dependencies:
// [dependencies]
// bellman = "0.14"
// bls12_381 = "0.8"
// blake2 = "0.10"
// hex = "0.4"
// anyhow = "1.0"
// clap = { version = "4.0", features = ["derive"] }

use anyhow::{Context, Result};
use bellman::groth16::{Parameters, VerifyingKey};
use blake2::{Blake2s256, Digest};
use bls12_381::Bls12;
use clap::Parser;
use std::fs::File;
use std::io::{Cursor, Read};

#[derive(Parser, Debug)]
#[command(author, version, about = "Check PK/VK compatibility and extract VK from PK", long_about = None)]
struct Args {
    /// Path to the proving key file
    #[arg(short, long)]
    pk: String,

    /// Path to the verifying key file (optional - if not provided, will extract from PK)
    #[arg(short, long)]
    vk: Option<String>,

    /// Output path for extracted VK (optional)
    #[arg(short, long)]
    output: Option<String>,

    /// Verbose output
    #[arg(short = 'B', long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("🔍 PK/VK Compatibility Checker\n");
    println!("===============================\n");

    // Load and analyze the proving key
    println!("📂 Loading proving key from: {}", args.pk);
    let pk_info = analyze_proving_key(&args.pk, args.verbose)?;

    println!("\n✅ Proving Key Analysis:");
    println!("  - File size: {} bytes", pk_info.file_size);
    println!("  - VK embedded in PK:");
    println!(
        "    - Public inputs expected: {}",
        pk_info.num_public_inputs
    );
    println!("    - VK fingerprint (Blake2s): {}", pk_info.vk_fingerprint);
    println!(
        "    - VK fingerprint (full): {}",
        pk_info.vk_fingerprint_full
    );
    println!("    - Computed vk_id: {}", pk_info.vk_id);

    // If VK file is provided, check compatibility
    if let Some(vk_path) = args.vk {
        println!("\n📂 Loading standalone VK from: {vk_path}");
        let vk_info = analyze_verifying_key(&vk_path, args.verbose)?;

        println!("\n✅ Standalone VK Analysis:");
        println!("  - File size: {} bytes", vk_info.file_size);
        println!("  - Public inputs expected: {}", vk_info.num_public_inputs);
        println!("  - VK fingerprint (Blake2s): {}", vk_info.vk_fingerprint);
        println!("  - VK fingerprint (full): {}", vk_info.vk_fingerprint_full);
        println!("  - Computed vk_id: {}", vk_info.vk_id);

        // Compare
        println!("\n🔄 Compatibility Check:");
        println!("=====================================");

        let mut compatible = true;

        if pk_info.num_public_inputs != vk_info.num_public_inputs {
            println!("❌ PUBLIC INPUT COUNT MISMATCH!");
            println!("   PK expects: {} inputs", pk_info.num_public_inputs);
            println!("   VK expects: {} inputs", vk_info.num_public_inputs);
            compatible = false;
        } else {
            println!(
                "✅ Public input count matches: {}",
                pk_info.num_public_inputs
            );
        }

        if pk_info.vk_fingerprint != vk_info.vk_fingerprint {
            println!("❌ VK FINGERPRINT MISMATCH!");
            println!("   PK's embedded VK: {}", pk_info.vk_fingerprint);
            println!("   Standalone VK:    {}", vk_info.vk_fingerprint);
            println!("\n   These are DIFFERENT verifying keys!");
            println!("   Proofs generated with the PK will NOT verify with this VK.");
            compatible = false;
        } else {
            println!("✅ VK fingerprints match: {}", pk_info.vk_fingerprint);
        }

        if pk_info.vk_id != vk_info.vk_id {
            println!("⚠️  Computed vk_id differs:");
            println!("   PK's VK: {}", pk_info.vk_id);
            println!("   Standalone VK: {}", vk_info.vk_id);
            if compatible {
                println!("   (This should not happen if fingerprints match - check computation)");
            }
        } else {
            println!("✅ Computed vk_id matches: {}", pk_info.vk_id);
        }

        if compatible {
            println!("\n✅ SUCCESS: The PK and VK are compatible!");
            println!("   Proofs generated with this PK will verify with this VK.");
        } else {
            println!("\n❌ FAILURE: The PK and VK are NOT compatible!");
            println!("   You need to either:");
            println!("   1. Extract the correct VK from the PK (use --output flag)");
            println!("   2. Regenerate both PK and VK from the same circuit");
        }
    }

    // Extract VK if requested
    if let Some(output_path) = args.output {
        println!("\n📤 Extracting VK from PK to: {output_path}");
        extract_vk_from_pk(&args.pk, &output_path)?;
        println!("✅ VK extracted successfully!");
        println!(
            "   File size: {} bytes",
            std::fs::metadata(&output_path)?.len()
        );

        // Verify the extracted VK
        let extracted_info = analyze_verifying_key(&output_path, false)?;
        if extracted_info.vk_fingerprint == pk_info.vk_fingerprint {
            println!("✅ Verification: Extracted VK matches the one embedded in PK");
        } else {
            println!("❌ ERROR: Extracted VK doesn't match! This shouldn't happen.");
        }
    }

    // Print server deployment instructions
    println!("\n📝 Server Deployment Notes:");
    println!("============================");
    println!(
        "Your server should use a VK with fingerprint: {}",
        pk_info.vk_fingerprint
    );
    println!("Expected vk_id: {}", pk_info.vk_id);
    println!("\nIn your server logs, look for:");
    println!(
        "  [/v1/verify] VK fingerprint (Blake2s): {}",
        pk_info.vk_fingerprint
    );
    println!("\nIf it shows a different fingerprint, you need to update the server's VK file.");

    Ok(())
}

struct KeyInfo {
    file_size: u64,
    num_public_inputs: usize,
    vk_fingerprint: String,      // First 8 bytes hex (matching server format)
    vk_fingerprint_full: String, // Full 32 bytes hex
    vk_id: u32,
}

fn analyze_proving_key(path: &str, verbose: bool) -> Result<KeyInfo> {
    let mut file = File::open(path).with_context(|| format!("Failed to open PK file: {path}"))?;

    let file_size = file.metadata()?.len();

    let mut pk_bytes = Vec::new();
    file.read_to_end(&mut pk_bytes)
        .context("Failed to read PK file")?;

    if verbose {
        println!("  Reading {} bytes...", pk_bytes.len());
    }

    // Parse the proving key
    let params = Parameters::<Bls12>::read(&mut Cursor::new(&pk_bytes), false)
        .context("Failed to parse proving key - invalid format or corrupted file")?;

    // Extract VK and compute fingerprint
    let mut vk_bytes = Vec::new();
    params
        .vk
        .write(&mut vk_bytes)
        .context("Failed to serialize embedded VK")?;

    let fingerprint_full = compute_fingerprint(&vk_bytes);
    let fingerprint_short = &fingerprint_full[..16]; // First 8 bytes as hex

    let vk_id = compute_vk_id(&vk_bytes);
    let num_public_inputs = params.vk.ic.len().saturating_sub(1);

    if verbose {
        println!(
            "  VK IC elements: {} (means {} public inputs)",
            params.vk.ic.len(),
            num_public_inputs
        );
        println!("  VK serialized size: {} bytes", vk_bytes.len());
    }

    Ok(KeyInfo {
        file_size,
        num_public_inputs,
        vk_fingerprint: fingerprint_short.to_string(),
        vk_fingerprint_full: fingerprint_full,
        vk_id,
    })
}

fn analyze_verifying_key(path: &str, verbose: bool) -> Result<KeyInfo> {
    let mut file = File::open(path).with_context(|| format!("Failed to open VK file: {path}"))?;

    let file_size = file.metadata()?.len();

    let mut vk_bytes = Vec::new();
    file.read_to_end(&mut vk_bytes)
        .context("Failed to read VK file")?;

    if verbose {
        println!("  Reading {} bytes...", vk_bytes.len());
    }

    // Parse the verifying key
    let vk = VerifyingKey::<Bls12>::read(&mut Cursor::new(&vk_bytes))
        .context("Failed to parse verifying key - invalid format or corrupted file")?;

    let fingerprint_full = compute_fingerprint(&vk_bytes);
    let fingerprint_short = &fingerprint_full[..16]; // First 8 bytes as hex

    let vk_id = compute_vk_id(&vk_bytes);
    let num_public_inputs = vk.ic.len().saturating_sub(1);

    if verbose {
        println!(
            "  VK IC elements: {} (means {} public inputs)",
            vk.ic.len(),
            num_public_inputs
        );
    }

    Ok(KeyInfo {
        file_size,
        num_public_inputs,
        vk_fingerprint: fingerprint_short.to_string(),
        vk_fingerprint_full: fingerprint_full,
        vk_id,
    })
}

fn extract_vk_from_pk(pk_path: &str, output_path: &str) -> Result<()> {
    let mut pk_file = File::open(pk_path).context("Failed to open PK file")?;

    let mut pk_bytes = Vec::new();
    pk_file
        .read_to_end(&mut pk_bytes)
        .context("Failed to read PK file")?;

    // Parse PK to get the embedded VK
    let params = Parameters::<Bls12>::read(&mut Cursor::new(&pk_bytes), false)
        .context("Failed to parse proving key")?;

    // Serialize just the VK
    let mut vk_bytes = Vec::new();
    params
        .vk
        .write(&mut vk_bytes)
        .context("Failed to serialize VK")?;

    // Write to output file
    std::fs::write(output_path, &vk_bytes)
        .with_context(|| format!("Failed to write VK to {output_path}"))?;

    Ok(())
}

fn compute_fingerprint(vk_bytes: &[u8]) -> String {
    let mut hasher = Blake2s256::new();
    hasher.update(vk_bytes);
    let result = hasher.finalize();
    hex::encode(result)
}

fn compute_vk_id(vk_bytes: &[u8]) -> u32 {
    let mut hasher = Blake2s256::new();
    hasher.update(b"provii.vk.id.v0");
    hasher.update(vk_bytes);
    let result = hasher.finalize();

    // Use first 4 bytes as u32 (little-endian)
    u32::from_le_bytes([result[0], result[1], result[2], result[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_computation() {
        let test_data = b"test verifying key data";
        let fp = compute_fingerprint(test_data);
        assert_eq!(fp.len(), 64); // 32 bytes = 64 hex chars

        let vk_id = compute_vk_id(test_data);
        assert!(vk_id > 0);
    }
}
