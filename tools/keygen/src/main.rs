#![forbid(unsafe_code)]
// CLI tool: stdout is the expected output channel.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use provii_crypto_commons::CredMsgV2;
use provii_crypto_sig_redjubjub::generate_keypair;
use serde_json::json;
use zeroize::Zeroizing;

fn print_usage() {
    eprintln!("Usage: generate-issuer-keys [OPTIONS]");
    eprintln!();
    eprintln!("Generate a RedJubjub issuer keypair for the Provii credential system.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --output <FILE>  Write secret key JSON to FILE (default: issuer_secret_key.json)");
    eprintln!("  --help           Show this help message");
    eprintln!("  --version        Print version");
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut output_file = "issuer_secret_key.json".to_string();

    let mut i = 1;
    #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            "--version" | "-V" => {
                eprintln!("generate-issuer-keys {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--output" | "-o" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--output requires a file path argument");
                }
                output_file = args[i].clone();
            }
            other => {
                anyhow::bail!("unknown argument: {other}\nRun with --help for usage");
            }
        }
        i += 1;
    }

    println!("RedJubjub Issuer Keypair Generator\n");

    println!("Generating new keypair...");
    let (sk_bytes, vk_bytes) = generate_keypair();

    // Only print the public key to stdout.
    println!("Public Key (32 bytes):");
    println!("  Hex: {}", hex::encode(vk_bytes));

    // Encode the key material for storage.
    let sk_b64 = Zeroizing::new(URL_SAFE_NO_PAD.encode(*sk_bytes));
    let vk_b64 = URL_SAFE_NO_PAD.encode(vk_bytes);

    println!("  Base64url: {vk_b64}");

    let sk_filename = &output_file;
    let sk_json = Zeroizing::new(
        json!({
            "sk_hex": hex::encode(*sk_bytes),
            "sk_b64u": &*sk_b64,
            "vk_hex": hex::encode(vk_bytes),
            "vk_b64u": vk_b64.clone(),
        })
        .to_string(),
    );

    std::fs::write(sk_filename, sk_json.as_bytes())?;

    // Set file permissions to owner-read-write only (0o600).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sk_filename, std::fs::Permissions::from_mode(0o600))?;
    }

    println!("\nSecret key written to {sk_filename} (permissions 0600)");
    println!("WARNING: This file contains secret key material. Handle accordingly.");

    // Prepare the Cloudflare KV storage payload.
    let kid = format!("provii:{}", chrono::Utc::now().format("%Y-%m"));
    let kv_key = format!("rj:keypair:{kid}");
    let kv_value = Zeroizing::new(
        json!({
            "sk": &*sk_b64,
            "vk": vk_b64,
        })
        .to_string(),
    );

    println!("\nCloudflare KV Storage Format:");
    println!("  Key: {kv_key}");
    println!("  Value: (written to {sk_filename})");

    // Verify that the generated keys operate correctly.
    println!("\nTesting signature operations...");

    let test_msg = CredMsgV2 {
        v: 2,
        kid: kid.clone(),
        c: [42u8; 32],
        iat: 1704067200,
        exp: 1735689600,
        schema: "test".to_string(),
    };

    // Sign the sample credential message.
    let sig = provii_crypto_sig_redjubjub::sign_cred_v2(&test_msg, &sk_bytes)
        .map_err(|e| anyhow::anyhow!("Signature creation failed: {e:?}"))?;
    println!("  Signature created successfully");

    // Verify the signature with the generated public key.
    provii_crypto_sig_redjubjub::verify_cred_v2(&test_msg, &sig, &vk_bytes)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {e:?}"))?;
    println!("  Signature verified successfully");

    // Validate that the public key lies on the Jubjub curve.
    use group::GroupEncoding;
    use jubjub::SubgroupPoint;

    let point_option = SubgroupPoint::from_bytes(&vk_bytes);
    if point_option.is_none().into() {
        return Err(anyhow::anyhow!("Public key is NOT a valid Jubjub point!"));
    }
    println!("  Public key is a valid Jubjub subgroup point");

    // Generate a JWKS entry for distribution.
    let jwks_entry = json!({
        "kty": "OKP",
        "crv": "JUBJUB",
        "kid": kid,
        "use": "sig",
        "alg": "RedJubjub",
        "x": vk_b64,
        "name": format!("Provii Issuer ({})", chrono::Utc::now().format("%B %Y")),
        "revoked": false
    });

    println!("\nJWKS Entry (add to jwks.json):");
    println!("{}", serde_json::to_string_pretty(&jwks_entry)?);

    println!("\nDirect VK Bytes (used in optimised circuit):");
    println!("  Base64url: {vk_b64}");
    println!("  Hex: {}", hex::encode(vk_bytes));
    println!("  Note: The optimised circuit uses raw VK bytes directly");

    println!("\nGeneration complete.");

    println!("\nNext steps:");
    println!("1. Store the KV entry in IS_KEYS namespace (value in {sk_filename})");
    println!("2. Add the JWKS entry to cdn.provii.app/v1/jwks.json");
    println!("3. The raw VK bytes are used directly in proofs (no hashing)");
    println!("4. Re-issue credentials with the new keypair");

    // Ensure KV value is dropped/zeroized before exit.
    drop(kv_value);

    Ok(())
}
