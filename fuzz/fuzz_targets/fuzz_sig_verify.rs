#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_commons::CredMsgV2;
use provii_crypto_sig_redjubjub::{verify_cred_v2, sign_cred_v2};

fuzz_target!(|data: &[u8]| {
    // We need at least 32 (vk) + 64 (sig) + 32 (c) + 16 (iat/exp/kid_len) = 144 bytes minimum
    if data.len() < 144 {
        return;
    }

    // Parse fuzzer input into components
    let vk_bytes = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[0..32]);
        arr
    };

    let signature = {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&data[32..96]);
        arr
    };

    let c_bytes = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[96..128]);
        arr
    };

    // Parse timestamps (8 bytes each)
    let iat = u64::from_le_bytes([
        data[128], data[129], data[130], data[131],
        data[132], data[133], data[134], data[135],
    ]);

    let exp = u64::from_le_bytes([
        data[136], data[137], data[138], data[139],
        data[140], data[141], data[142], data[143],
    ]);

    // Create a credential message
    let cred_msg = CredMsgV2 {
        v: 2,
        kid: "fuzz-key".to_string(),
        c: c_bytes,
        iat,
        exp,
        schema: "https://example.com/schema.json".to_string(),
    };

    // Test 1: Verify with random signature (should almost always fail gracefully)
    let _ = verify_cred_v2(&cred_msg, &signature, &vk_bytes);

    // Test 2: If we have enough data, try creating a valid keypair and signature
    if data.len() >= 176 {
        let sk_bytes = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&data[144..176]);
            arr
        };

        // Try to sign with the random key (may fail if sk is invalid)
        if let Ok(valid_sig) = sign_cred_v2(&cred_msg, &sk_bytes) {
            // Derive the actual verification key from the signing key
            // For now, we just test that verify doesn't panic
            let _ = verify_cred_v2(&cred_msg, &valid_sig, &vk_bytes);
        }
    }

    // Test 3: Signature malleability - flip bits in signature
    if data.len() >= 145 {
        let mut tampered_sig = signature;
        let flip_byte = data[144] as usize % 64;
        tampered_sig[flip_byte] ^= 0xFF;
        let _ = verify_cred_v2(&cred_msg, &tampered_sig, &vk_bytes);
    }

    // Test 4: VK malleability - flip bits in verification key
    if data.len() >= 146 {
        let mut tampered_vk = vk_bytes;
        let flip_byte = data[145] as usize % 32;
        tampered_vk[flip_byte] ^= 0xFF;
        let _ = verify_cred_v2(&cred_msg, &signature, &tampered_vk);
    }

    // Test 5: Zero signature (edge case)
    let zero_sig = [0u8; 64];
    let _ = verify_cred_v2(&cred_msg, &zero_sig, &vk_bytes);

    // Test 6: Max signature (edge case)
    let max_sig = [0xFFu8; 64];
    let _ = verify_cred_v2(&cred_msg, &max_sig, &vk_bytes);

    // Test 7: Zero verification key (edge case)
    let zero_vk = [0u8; 32];
    let _ = verify_cred_v2(&cred_msg, &signature, &zero_vk);
});
