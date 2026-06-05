#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_protocol::rp_challenge;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    origin: Vec<u8>,
    nonce: [u8; 32],
}

/// Fuzz rp_challenge function
/// Tests:
/// - Various origin strings (empty, long, Unicode, special chars)
/// - Different nonce values
/// - Determinism
/// - Output is always 32 bytes
/// - Sensitivity to input changes
fuzz_target!(|input: FuzzInput| {
    if let Ok(origin) = std::str::from_utf8(&input.origin) {
        let challenge = rp_challenge(origin, &input.nonce);

        // Invariant: output is always 32 bytes
        assert_eq!(challenge.len(), 32, "Challenge must be 32 bytes");

        // Invariant: determinism
        let challenge2 = rp_challenge(origin, &input.nonce);
        assert_eq!(challenge, challenge2, "Function must be deterministic");

        // Invariant: different origins produce different challenges
        if origin.len() > 0 {
            let modified_origin = format!("{}_modified", origin);
            let challenge_modified = rp_challenge(&modified_origin, &input.nonce);
            assert_ne!(challenge, challenge_modified, "Different origins must produce different challenges");
        }

        // Invariant: different nonces produce different challenges
        let mut modified_nonce = input.nonce;
        modified_nonce[0] = modified_nonce[0].wrapping_add(1);
        let challenge_modified_nonce = rp_challenge(origin, &modified_nonce);
        assert_ne!(challenge, challenge_modified_nonce, "Different nonces must produce different challenges");
    }
});
