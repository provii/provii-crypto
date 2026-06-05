#![forbid(unsafe_code)]
// CLI tool: stdout is the expected output channel.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use dialoguer::{Confirm, Input};
use provii_crypto_sig_redjubjub::generate_keypair;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Write;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(author, version, about = "Generate issuer configuration package with signing keys", long_about = None)]
struct Args {
    /// Skip interactive prompts and use defaults (for scripting)
    #[arg(long)]
    non_interactive: bool,

    /// Output file path (default: issuer-package-{timestamp}.json)
    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SigningKeyData {
    key_id: String,
    private_key: String, // base64url (UNENCRYPTED - will be encrypted by admin portal)
    public_key: String,  // base64url
    key_type: String,
}

impl fmt::Debug for SigningKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeyData")
            .field("key_id", &self.key_id)
            .field("private_key", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .field("key_type", &self.key_type)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct IssuerPackage {
    // Metadata
    generated_at: String,
    generated_by: String,

    // Issuer identity
    issuer_kid: String,
    organization_name: String,
    domain: String,
    logo_url: String,

    // Environment-specific signing keypairs
    // Each environment gets its own keypair for cryptographic isolation
    signing_keys_production: SigningKeyData,
    signing_keys_sandbox: SigningKeyData,

    // Default policies
    max_validity_days: u32,
    allow_revocation: bool,
    key_rotation_days: u32,

    // Instructions
    _instructions: String,
}

impl fmt::Debug for IssuerPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuerPackage")
            .field("generated_at", &self.generated_at)
            .field("generated_by", &self.generated_by)
            .field("issuer_kid", &self.issuer_kid)
            .field("organization_name", &self.organization_name)
            .field("domain", &self.domain)
            .field("signing_keys_production", &"[REDACTED]")
            .field("signing_keys_sandbox", &"[REDACTED]")
            .finish()
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       Provii Issuer Package Generator v0.4.0            ║");
    println!("║                                                          ║");
    println!("║  Generates issuer configuration package:                ║");
    println!("║  • Issuer identity (org name, domain, logo)             ║");
    println!("║  • RedJubJub signing keypairs (production + sandbox)    ║");
    println!("║  • Default policies                                     ║");
    println!("║                                                          ║");
    println!("║  Officers and client apps managed via admin portal      ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    // Step 1: Issuer Identity
    println!("📋 Step 1: Issuer Identity");
    println!("════════════════════════════════════════\n");

    let organization_name = if args.non_interactive {
        "Example Organization".to_string()
    } else {
        Input::<String>::new()
            .with_prompt("Organization Name")
            .interact_text()?
    };

    let domain = if args.non_interactive {
        "issuer.example.com".to_string()
    } else {
        Input::<String>::new()
            .with_prompt("Domain")
            .interact_text()?
    };

    // Auto-generate issuer_kid from organization name
    let org_slug = organization_name
        .to_lowercase()
        .replace(|c: char| !c.is_alphanumeric() && c != '-', "-")
        .trim_matches('-')
        .to_string();
    let timestamp = chrono::Utc::now().format("%Y%m%d");
    let issuer_kid = format!("{org_slug}-{timestamp}");

    println!("\n✓ Issuer Key ID (auto-generated): {issuer_kid}");

    // Logo URL (optional)
    let logo_url = if args.non_interactive {
        "https://cdn.provii.app/v1/logos/default.png".to_string()
    } else {
        let url: String = Input::new()
            .with_prompt("Logo URL (press Enter to skip)")
            .allow_empty(true)
            .interact_text()?;

        if url.is_empty() {
            println!("  ✓ No logo specified");
            String::new()
        } else if url.starts_with("https://") && (url.ends_with(".png") || url.ends_with(".svg")) {
            println!("  ✓ Logo URL set");
            url
        } else {
            println!("  ⚠️  Invalid URL format, skipping logo");
            String::new()
        }
    };

    // Step 2: Generate RedJubJub Signing Keypairs (PRODUCTION + SANDBOX)
    println!("\n🔑 Step 2: Generating RedJubJub Signing Keypairs");
    println!("════════════════════════════════════════\n");

    // CRITICAL: Key IDs must be exactly 14 bytes for the ZK circuit
    // Format: "EE:YYYYMMDD:XX" where EE=environment, XX=random hex
    // Example: "pr:20251206:a7" (production) or "sb:20251206:s3" (sandbox)
    let date_str = chrono::Utc::now().format("%Y%m%d").to_string();
    let random_suffix: u8 = rand::random();

    // Generate PRODUCTION keypair
    println!("🏭 Generating PRODUCTION keypair...");
    let (prod_sk_bytes, prod_vk_bytes) = generate_keypair();
    let prod_sk_b64 = Zeroizing::new(URL_SAFE_NO_PAD.encode(*prod_sk_bytes));
    let prod_vk_b64 = URL_SAFE_NO_PAD.encode(prod_vk_bytes);
    let prod_key_id = format!("pr:{date_str}:{random_suffix:02x}");
    assert_eq!(
        prod_key_id.len(),
        14,
        "Production key ID must be exactly 14 bytes for ZK circuit"
    );

    println!("  ✓ Production keypair generated");
    println!("    Key ID: {prod_key_id}");
    println!("    Public Key: {prod_vk_b64}");

    // Verify production signature operations
    println!("  🧪 Testing production signature...");
    let test_msg_prod = provii_crypto_commons::CredMsgV2 {
        v: 2,
        kid: prod_key_id.clone(),
        c: [42u8; 32],
        iat: 1704067200,
        exp: 1735689600,
        schema: "test".to_string(),
    };
    let sig_prod = provii_crypto_sig_redjubjub::sign_cred_v2(&test_msg_prod, &prod_sk_bytes)?;
    provii_crypto_sig_redjubjub::verify_cred_v2(&test_msg_prod, &sig_prod, &prod_vk_bytes)?;
    println!("    ✅ Production signature verified\n");

    // Generate SANDBOX keypair
    println!("🧪 Generating SANDBOX keypair...");
    let (sandbox_sk_bytes, sandbox_vk_bytes) = generate_keypair();
    let sandbox_sk_b64 = Zeroizing::new(URL_SAFE_NO_PAD.encode(*sandbox_sk_bytes));
    let sandbox_vk_b64 = URL_SAFE_NO_PAD.encode(sandbox_vk_bytes);
    let sandbox_key_id = format!("sb:{date_str}:{random_suffix:02x}");
    assert_eq!(
        sandbox_key_id.len(),
        14,
        "Sandbox key ID must be exactly 14 bytes for ZK circuit"
    );

    println!("  ✓ Sandbox keypair generated");
    println!("    Key ID: {sandbox_key_id}");
    println!("    Public Key: {sandbox_vk_b64}");

    // Verify sandbox signature operations
    println!("  🧪 Testing sandbox signature...");
    let test_msg_sandbox = provii_crypto_commons::CredMsgV2 {
        v: 2,
        kid: sandbox_key_id.clone(),
        c: [42u8; 32],
        iat: 1704067200,
        exp: 1735689600,
        schema: "test".to_string(),
    };
    let sig_sandbox =
        provii_crypto_sig_redjubjub::sign_cred_v2(&test_msg_sandbox, &sandbox_sk_bytes)?;
    provii_crypto_sig_redjubjub::verify_cred_v2(
        &test_msg_sandbox,
        &sig_sandbox,
        &sandbox_vk_bytes,
    )?;
    println!("    ✅ Sandbox signature verified");

    // Step 3: Default Policies
    println!("\n📋 Step 3: Credential Policies");
    println!("════════════════════════════════════════\n");

    let (max_validity_days, allow_revocation, key_rotation_days) = if args.non_interactive {
        (365, true, 90)
    } else {
        let max_validity_days: u32 = Input::new()
            .with_prompt("Maximum credential validity (days)")
            .with_initial_text("365")
            .interact_text()?;

        let allow_revocation = Confirm::new()
            .with_prompt("Allow credential revocation?")
            .default(true)
            .interact()?;

        let key_rotation_days: u32 = loop {
            let days: u32 = Input::new()
                .with_prompt("Key rotation interval (days, max 365)")
                .with_initial_text("90")
                .interact_text()?;

            if days > 365 {
                println!("  ⚠️  Must be ≤ 365 days");
                continue;
            }
            break days;
        };

        (max_validity_days, allow_revocation, key_rotation_days)
    };

    println!("\n✓ Policies configured:");
    println!("  • Max validity: {max_validity_days} days");
    println!(
        "  • Revocation: {}",
        if allow_revocation {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("  • Key rotation: every {key_rotation_days} days");

    // Build the package with DUAL environment keys
    let package = IssuerPackage {
        generated_at: chrono::Utc::now().to_rfc3339(),
        generated_by: "issuer-gen v0.4.0".to_string(),
        issuer_kid: issuer_kid.clone(),
        organization_name: organization_name.clone(),
        domain: domain.clone(),
        logo_url,
        signing_keys_production: SigningKeyData {
            key_id: prod_key_id.clone(),
            private_key: prod_sk_b64.to_string(),
            public_key: prod_vk_b64,
            key_type: "redjubjub".to_string(),
        },
        signing_keys_sandbox: SigningKeyData {
            key_id: sandbox_key_id.clone(),
            private_key: sandbox_sk_b64.to_string(),
            public_key: sandbox_vk_b64,
            key_type: "redjubjub".to_string(),
        },
        max_validity_days,
        allow_revocation,
        key_rotation_days,
        _instructions: "SECURITY WARNING: This file contains UNENCRYPTED private keys for BOTH environments. \
            Upload to admin portal immediately and DELETE this file. \
            The admin portal will encrypt both private keys before storing. \
            Production keys will be encrypted with ISSUER_KEK, sandbox keys with SANDBOX_ISSUER_KEK. \
            Officers and client apps should be created via the admin portal GUI.".to_string(),
    };

    // Write to file
    let output_path = args.output.unwrap_or_else(|| {
        format!(
            "issuer-package-{}.json",
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        )
    });

    let json_output = Zeroizing::new(serde_json::to_string_pretty(&package)?);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&output_path)?;
        file.write_all(json_output.as_bytes())?;
        std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&output_path, json_output.as_bytes())?;
    }

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║              ✨ Package Generated! ✨                     ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    println!("\n📦 Package Summary:");
    println!("  • Issuer: {}", package.issuer_kid);
    println!("  • Organization: {organization_name}");
    println!("  • Domain: {domain}");
    println!("  • Production Key: {prod_key_id} (RedJubJub)");
    println!("  • Sandbox Key: {sandbox_key_id} (RedJubJub)");
    println!("  • File: {output_path}");

    println!("\n⚠️  SECURITY:");
    println!("  • This file contains UNENCRYPTED private keys for BOTH environments");
    println!("  • Upload to admin portal IMMEDIATELY");
    println!("  • DELETE this file after import");

    println!("\n📋 Next Steps:");
    println!("  1. Go to https://admin.zerokp.id/customers/onboard");
    println!("  2. Select 'Issuer' and upload: {output_path}");
    println!("  3. Both production and sandbox keys will be stored securely");
    println!("  4. Add officers and client apps via the GUI");
    println!("  5. DELETE this file");

    println!("\n✅ Done!");

    Ok(())
}
