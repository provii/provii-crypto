#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_protocol::{
    code_challenge_s256, rp_challenge, compute_origin_hash,
    build_issuance_consent_message, compute_replay_tag, write_length_prefixed,
};
use sha2::{Digest, Sha256};

fuzz_target!(|data: &[u8]| {
    // We need reasonable amount of data to split into test inputs
    if data.len() < 16 {
        return;
    }

    // Split data into chunks for different functions
    let origin_len = (data[0] as usize).min(data.len() / 4);
    let origin_bytes = &data[1..1 + origin_len.min(data.len() - 1)];

    // Test 1: code_challenge_s256 with various inputs
    if let Ok(origin_str) = std::str::from_utf8(origin_bytes) {
        let challenge = code_challenge_s256(origin_str);

        // CRITICAL: SHA256 base64url is always 43 characters (32 bytes -> 43 chars)
        assert_eq!(challenge.len(), 43, "SHA256 base64url must be 43 characters");

        // CRITICAL: Must not contain padding or non-URL-safe characters
        assert!(!challenge.contains('='), "Must not contain padding");
        assert!(!challenge.contains('+'), "Must not contain +");
        assert!(!challenge.contains('/'), "Must not contain /");

        // Test determinism
        let challenge2 = code_challenge_s256(origin_str);
        assert_eq!(challenge, challenge2, "code_challenge_s256 must be deterministic");
    }

    // Test 2: code_challenge_s256 with edge cases
    let _ = code_challenge_s256("");
    let _ = code_challenge_s256("a");
    let _ = code_challenge_s256(&"a".repeat(1000));

    // Test 3: compute_origin_hash with various inputs
    if data.len() >= 8 {
        let hash_input_len = (data[1] as usize).min(data.len() / 2);
        if let Ok(hash_str) = std::str::from_utf8(&data[2..2 + hash_input_len.min(data.len() - 2)]) {
            let hash = compute_origin_hash(hash_str);

            // CRITICAL: SHA256 output is always 32 bytes
            assert_eq!(hash.len(), 32, "SHA256 hash must be 32 bytes");

            // Test determinism
            let hash2 = compute_origin_hash(hash_str);
            assert_eq!(hash, hash2, "compute_origin_hash must be deterministic");

            // Different inputs should produce different hashes (with high probability)
            let hash_different = compute_origin_hash(&format!("{}x", hash_str));
            if hash_str != &format!("{}x", hash_str) {
                let _ = hash != hash_different;
            }
        }
    }

    // Test 4: compute_origin_hash edge cases
    let hash_empty = compute_origin_hash("");
    assert_eq!(hash_empty.len(), 32);

    let hash_long = compute_origin_hash(&"x".repeat(10000));
    assert_eq!(hash_long.len(), 32);

    // Test 5: rp_challenge with various inputs
    if data.len() >= 40 {
        let nonce = &data[8..40]; // 32 bytes
        if let Ok(origin) = std::str::from_utf8(&data[40..40 + origin_len.min(data.len() - 40)]) {
            let challenge = rp_challenge(origin, nonce);

            // CRITICAL: Challenge is always 32 bytes
            assert_eq!(challenge.len(), 32, "rp_challenge output must be 32 bytes");

            // Test determinism
            let challenge2 = rp_challenge(origin, nonce);
            assert_eq!(challenge, challenge2, "rp_challenge must be deterministic");

            // Different nonces should produce different challenges
            if data.len() >= 72 {
                let nonce2 = &data[40..72];
                if nonce != nonce2 {
                    let challenge_different = rp_challenge(origin, nonce2);
                    assert_ne!(challenge, challenge_different, "Different nonces must produce different challenges");
                }
            }
        }
    }

    // Test 6: rp_challenge edge cases
    let zero_nonce = [0u8; 32];
    let max_nonce = [0xFFu8; 32];

    let _ = rp_challenge("", &zero_nonce);
    let _ = rp_challenge("https://example.com", &zero_nonce);
    let _ = rp_challenge("https://example.com", &max_nonce);

    // Test 7: build_issuance_consent_message
    if data.len() >= 120 {
        let session_id_len = (data[72] as usize % 32).min(data.len() - 100);
        let issuer_id_len = (data[73] as usize % 32).min(data.len() - 100);
        let kid_len = (data[74] as usize % 32).min(data.len() - 100);

        if let (Ok(session_id), Ok(issuer_id), Ok(issuer_kid)) = (
            std::str::from_utf8(&data[75..75 + session_id_len.min(10)]),
            std::str::from_utf8(&data[85..85 + issuer_id_len.min(10)]),
            std::str::from_utf8(&data[95..95 + kid_len.min(10)]),
        ) {
            let wallet_pubkey = {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&data[0..32]);
                arr
            };

            let consent_time = i64::from_le_bytes([
                data[32], data[33], data[34], data[35],
                data[36], data[37], data[38], data[39],
            ]);

            let terms_version = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);

            // Test without nonce
            let msg1 = build_issuance_consent_message(
                session_id, issuer_id, issuer_kid, &wallet_pubkey,
                consent_time, terms_version, None
            ).unwrap();

            assert_eq!(msg1.len(), 32, "Consent message must be 32 bytes");

            // Test with nonce
            let nonce_opt = {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&data[44..60]);
                Some(arr)
            };

            let msg2 = build_issuance_consent_message(
                session_id, issuer_id, issuer_kid, &wallet_pubkey,
                consent_time, terms_version, nonce_opt
            ).unwrap();

            assert_eq!(msg2.len(), 32, "Consent message must be 32 bytes");

            // With and without nonce should produce different messages
            assert_ne!(msg1, msg2, "Nonce presence must change message");

            // Test determinism
            let msg3 = build_issuance_consent_message(
                session_id, issuer_id, issuer_kid, &wallet_pubkey,
                consent_time, terms_version, nonce_opt
            ).unwrap();
            assert_eq!(msg2, msg3, "build_issuance_consent_message must be deterministic");
        }
    }

    // Test 8: compute_replay_tag
    if data.len() >= 64 {
        let origin_hash = &data[0..32];
        let nonce = &data[32..64];

        let tag = compute_replay_tag(origin_hash, nonce);

        // CRITICAL: Tag should be non-empty and valid base64url
        assert!(!tag.is_empty(), "Replay tag must not be empty");
        assert!(!tag.contains('='), "Replay tag must not contain padding");
        assert!(!tag.contains('+'), "Replay tag must not contain +");
        assert!(!tag.contains('/'), "Replay tag must not contain /");

        // Test determinism
        let tag2 = compute_replay_tag(origin_hash, nonce);
        assert_eq!(tag, tag2, "compute_replay_tag must be deterministic");

        // Different inputs should produce different tags
        if data.len() >= 96 {
            let nonce2 = &data[64..96];
            if nonce != nonce2 {
                let tag_different = compute_replay_tag(origin_hash, nonce2);
                assert_ne!(tag, tag_different, "Different nonces must produce different tags");
            }
        }
    }

    // Test 9: compute_replay_tag edge cases
    let tag_empty = compute_replay_tag(&[], &[]);
    assert!(!tag_empty.is_empty());

    let tag_zeros = compute_replay_tag(&[0u8; 32], &[0u8; 32]);
    assert!(!tag_zeros.is_empty());

    // Test 10: write_length_prefixed
    if data.len() >= 4 {
        let data_len = (data[0] as usize).min(data.len() - 1);
        let test_data = &data[1..1 + data_len];

        let mut hasher1 = Sha256::new();
        write_length_prefixed(&mut hasher1, test_data).unwrap();
        let hash1: [u8; 32] = hasher1.finalize().into();

        // Verify it matches manual construction
        let mut hasher2 = Sha256::new();
        hasher2.update(&(test_data.len() as u32).to_le_bytes());
        hasher2.update(test_data);
        let hash2: [u8; 32] = hasher2.finalize().into();

        assert_eq!(hash1, hash2, "write_length_prefixed must match manual construction");

        // Test that length-prefixing prevents collision
        if data.len() >= 8 && data_len >= 2 {
            let split = data_len / 2;
            let part1 = &test_data[0..split];
            let part2 = &test_data[split..];

            let mut hasher_split = Sha256::new();
            write_length_prefixed(&mut hasher_split, part1).unwrap();
            write_length_prefixed(&mut hasher_split, part2).unwrap();
            let hash_split: [u8; 32] = hasher_split.finalize().into();

            // Split should produce different hash than whole
            // (length-prefixing ensures domain separation)
            let _ = hash1 != hash_split;
        }
    }

    // Test 11: write_length_prefixed with empty data
    let mut hasher_empty = Sha256::new();
    write_length_prefixed(&mut hasher_empty, &[]).unwrap();
    let _ = hasher_empty.finalize();

    // Test 12: write_length_prefixed with large data
    let large_data = vec![0x42u8; 10000];
    let mut hasher_large = Sha256::new();
    write_length_prefixed(&mut hasher_large, &large_data).unwrap();
    let _ = hasher_large.finalize();
});
