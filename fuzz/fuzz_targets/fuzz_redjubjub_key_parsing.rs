#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_sig_redjubjub::{SigningKey, VerificationKey, Signature};

/// Fuzz target for RedJubjub key and signature parsing from arbitrary bytes.
///
/// Exercises `SigningKey::from_bytes`, `VerificationKey::from_bytes`, and
/// `Signature::from_bytes` with untrusted inputs. Valid keys are further
/// exercised through derivation and round-trip serialisation to confirm
/// no panics occur on any byte pattern.
fuzz_target!(|data: &[u8]| {
    // Test 1: SigningKey::from_bytes with 32-byte input.
    if data.len() >= 32 {
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&data[..32]);

        match SigningKey::from_bytes(&sk_bytes) {
            Ok(sk) => {
                // Derive VK from valid SK (must not panic).
                let vk = sk.verification_key();
                let vk_bytes = vk.to_bytes();

                // VK round-trip must succeed.
                let vk2 = VerificationKey::from_bytes(&vk_bytes);
                assert!(vk2.is_ok(), "VK derived from valid SK must round-trip");

                // SK round-trip must succeed.
                let sk_exported = sk.to_bytes();
                let sk2 = SigningKey::from_bytes(&sk_exported);
                assert!(sk2.is_ok(), "Valid SK must round-trip through to_bytes");
            }
            Err(_) => {
                // Invalid SK bytes are expected for most inputs.
            }
        }
    }

    // Test 2: VerificationKey::from_bytes with 32-byte input.
    if data.len() >= 32 {
        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(&data[..32]);

        match VerificationKey::from_bytes(&vk_bytes) {
            Ok(vk) => {
                // Round-trip must succeed.
                let exported = vk.to_bytes();
                assert_eq!(exported, vk_bytes, "VK round-trip must be identity");
            }
            Err(_) => {}
        }
    }

    // Test 3: Signature::from_bytes with 64-byte input.
    if data.len() >= 64 {
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&data[..64]);

        match Signature::from_bytes(&sig_bytes) {
            Ok(sig) => {
                // Round-trip must succeed.
                let exported = sig.to_bytes();
                assert_eq!(exported, sig_bytes, "Signature round-trip must be identity");
            }
            Err(_) => {}
        }
    }

    // Test 4: Edge cases with all zeros and all 0xFF.
    let _ = SigningKey::from_bytes(&[0u8; 32]);
    let _ = SigningKey::from_bytes(&[0xFF; 32]);
    let _ = VerificationKey::from_bytes(&[0u8; 32]);
    let _ = VerificationKey::from_bytes(&[0xFF; 32]);
    let _ = Signature::from_bytes(&[0u8; 64]);
    let _ = Signature::from_bytes(&[0xFF; 64]);
});
