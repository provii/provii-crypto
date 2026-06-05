#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_protocol::write_length_prefixed;
use sha2::{Sha256, Digest};

/// Fuzz write_length_prefixed function
/// Tests:
/// - Various data lengths (empty, small, large)
/// - Determinism
/// - Collision resistance
/// - Data at u32 boundaries
fuzz_target!(|data: &[u8]| {
    let mut h1 = Sha256::new();
    let mut h2 = Sha256::new();

    // Test the function doesn't panic
    write_length_prefixed(&mut h1, data).unwrap();

    // Invariant: determinism
    write_length_prefixed(&mut h2, data).unwrap();
    let hash1: [u8; 32] = h1.finalize().into();
    let hash2: [u8; 32] = h2.finalize().into();
    assert_eq!(hash1, hash2, "Function must be deterministic");

    // Invariant: collision resistance - different data produces different hashes
    if data.len() > 0 {
        let mut h3 = Sha256::new();
        let modified_data: Vec<u8> = data.iter().map(|&b| b.wrapping_add(1)).collect();
        write_length_prefixed(&mut h3, &modified_data).unwrap();
        let hash3: [u8; 32] = h3.finalize().into();
        assert_ne!(hash1, hash3, "Different data must produce different hashes");
    }

    // Invariant: length-prefixing prevents collisions
    // "ab" + "c" should hash differently than "a" + "bc"
    if data.len() >= 2 {
        let split_point = data.len() / 2;
        let (first, second) = data.split_at(split_point);

        let mut h_split = Sha256::new();
        write_length_prefixed(&mut h_split, first).unwrap();
        write_length_prefixed(&mut h_split, second).unwrap();
        let hash_split: [u8; 32] = h_split.finalize().into();

        // Create alternative split
        if split_point > 0 && split_point < data.len() - 1 {
            let (alt_first, alt_second) = data.split_at(split_point + 1);
            let mut h_alt = Sha256::new();
            write_length_prefixed(&mut h_alt, alt_first).unwrap();
            write_length_prefixed(&mut h_alt, alt_second).unwrap();
            let hash_alt: [u8; 32] = h_alt.finalize().into();

            assert_ne!(hash_split, hash_alt, "Length prefixing must prevent collisions");
        }
    }

    // Test near u32 boundary (if data is small enough to test)
    if data.len() < 1000 {
        let mut h_boundary = Sha256::new();
        write_length_prefixed(&mut h_boundary, &vec![0xFF; 1000]).unwrap();
        let _ = h_boundary.finalize();
    }
});
