#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_protocol::compute_replay_tag;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    origin_hash: Vec<u8>,
    nonce: Vec<u8>,
}

/// Fuzz compute_replay_tag function
/// Tests:
/// - Various lengths of origin_hash (empty, short, 32 bytes, long)
/// - Various lengths of nonce
/// - Very large inputs
/// - Empty inputs
/// - Determinism
/// - URL-safe base64 output
fuzz_target!(|input: FuzzInput| {
    let tag = compute_replay_tag(&input.origin_hash, &input.nonce);

    // Invariant: output is never empty
    assert!(!tag.is_empty(), "Tag must not be empty");

    // Invariant: no padding
    assert!(!tag.contains('='), "Tag must not contain padding");

    // Invariant: URL-safe characters only
    assert!(!tag.contains('+'), "Tag must not contain '+'");
    assert!(!tag.contains('/'), "Tag must not contain '/'");

    // Invariant: only valid base64url characters
    assert!(tag.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '-' || c == '_'
    }), "Tag must only contain base64url characters");

    // Invariant: determinism
    let tag2 = compute_replay_tag(&input.origin_hash, &input.nonce);
    assert_eq!(tag, tag2, "Function must be deterministic");

    // Test with empty inputs
    let empty_tag = compute_replay_tag(&[], &[]);
    assert!(!empty_tag.is_empty(), "Empty inputs should produce non-empty tag");

    // Test with large inputs (should not panic or overflow)
    if input.origin_hash.len() < 10000 && input.nonce.len() < 10000 {
        let large_hash = vec![0xAA; 10000];
        let large_nonce = vec![0xBB; 10000];
        let large_tag = compute_replay_tag(&large_hash, &large_nonce);
        assert!(!large_tag.is_empty(), "Large inputs should produce non-empty tag");
    }
});
