#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_protocol::compute_origin_hash;

/// Fuzz compute_origin_hash function
/// Tests:
/// - Empty origins
/// - Very long origins
/// - Unicode characters (non-ASCII domains)
/// - Special characters
/// - Case sensitivity
/// - Determinism
/// - Output is always 32 bytes
fuzz_target!(|data: &[u8]| {
    if let Ok(origin) = std::str::from_utf8(data) {
        let hash = compute_origin_hash(origin);

        // Invariant: output is always 32 bytes
        assert_eq!(hash.len(), 32, "Hash must be 32 bytes");

        // Invariant: determinism
        let hash2 = compute_origin_hash(origin);
        assert_eq!(hash, hash2, "Function must be deterministic");

        // Invariant: case sensitivity - different cases should produce different hashes
        if origin.len() > 0 {
            let upper = origin.to_uppercase();
            let lower = origin.to_lowercase();
            if upper != lower {
                let hash_upper = compute_origin_hash(&upper);
                let hash_lower = compute_origin_hash(&lower);
                if upper != origin {
                    assert_ne!(hash, hash_upper, "Case sensitivity check failed");
                }
                if lower != origin {
                    assert_ne!(hash, hash_lower, "Case sensitivity check failed");
                }
            }
        }
    }
});
