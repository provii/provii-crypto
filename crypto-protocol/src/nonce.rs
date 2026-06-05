//! Nonce generation and validation.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use provii_crypto_commons::Error;
use provii_crypto_commons::Result;
use zeroize::Zeroizing;

/// Generate a secure random nonce using a cryptographically secure RNG.
///
/// The intermediate buffer is wrapped in `Zeroizing` so that a copy of the
/// random bytes is cleared from the stack when the function returns. Note
/// that the returned array is a plain `[u8; 32]`; nonces are public protocol
/// values and do not require zeroization by the caller.
///
/// # Errors
/// Returns `Error::Internal` if the RNG fails to generate random bytes.
pub fn generate_nonce() -> Result<[u8; 32]> {
    let mut bytes = Zeroizing::new([0u8; 32]);

    #[cfg(target_arch = "wasm32")]
    {
        // Use `getrandom`, which hooks into the Web Crypto API.
        getrandom::getrandom(bytes.as_mut()).map_err(|_| Error::Internal)?;
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        // Use `OsRng` instead of `thread_rng` to maintain cryptographic security.
        use rand::rngs::OsRng;
        use rand::RngCore;
        OsRng.fill_bytes(bytes.as_mut());
    }

    Ok(*bytes)
}

/// Validate that the nonce is non-zero and has sufficient byte diversity.
///
/// Combines the non-zero check with [`has_sufficient_entropy`] to reject
/// trivial nonces (all zeros, single repeated byte, fewer than 8 unique bytes).
pub fn validate_nonce(nonce: &[u8; 32]) -> bool {
    nonce.iter().any(|&b| b != 0) && has_sufficient_entropy(nonce)
}

/// Check that the nonce has sufficient entropy (at least eight unique bytes).
///
/// This is a fast, deterministic heuristic. It counts the number of
/// distinct byte values in the 32-byte input and requires at least 8.
/// A CSPRNG-generated nonce will satisfy this with overwhelming
/// probability. The check catches degenerate inputs (constant bytes,
/// incrementing counters with narrow range) but is not a substitute
/// for using a proper CSPRNG.
pub fn has_sufficient_entropy(nonce: &[u8; 32]) -> bool {
    let mut seen = [false; 256];
    let mut uniq: u16 = 0;

    for &b in nonce {
        // SAFETY(indexing): b is u8 so b as usize is always 0..=255, within [bool; 256].
        #[allow(clippy::indexing_slicing)]
        let already_seen = seen[b as usize];
        if !already_seen {
            #[allow(clippy::indexing_slicing)]
            {
                seen[b as usize] = true;
            }
            // SAFETY(arithmetic): uniq <= 256 (max distinct u8 values), fits in u16.
            uniq = uniq.saturating_add(1);
        }
    }

    uniq >= 8
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() -> Result<()> {
        let nonce1 = generate_nonce()?;
        let nonce2 = generate_nonce()?;

        // Nonces should be different (with overwhelming probability).
        assert_ne!(nonce1, nonce2);

        // Each nonce should be exactly 32 bytes.
        assert_eq!(nonce1.len(), 32);
        assert_eq!(nonce2.len(), 32);

        // Each nonce should pass validation.
        assert!(validate_nonce(&nonce1));
        assert!(validate_nonce(&nonce2));

        // Each nonce should satisfy the entropy check.
        assert!(has_sufficient_entropy(&nonce1));
        assert!(has_sufficient_entropy(&nonce2));
        Ok(())
    }

    #[test]
    fn test_validate_nonce() {
        // All zeros should fail validation.
        let zeros = [0u8; 32];
        assert!(!validate_nonce(&zeros));

        // A nonce with only one non-zero byte should now fail (insufficient
        // entropy: only 2 unique byte values, need at least 8).
        let mut one_bit = [0u8; 32];
        one_bit[0] = 1;
        assert!(!validate_nonce(&one_bit));

        // A nonce with 8+ unique bytes should pass.
        let mut good_nonce = [0u8; 32];
        for (i, byte) in good_nonce.iter_mut().take(8).enumerate() {
            *byte = i as u8;
        }
        assert!(validate_nonce(&good_nonce));
    }

    #[test]
    fn test_entropy_check() -> Result<()> {
        // Using the same byte throughout should fail the entropy check.
        let same = [42u8; 32];
        assert!(!has_sufficient_entropy(&same));

        // Eight different bytes should pass.
        let mut varied = [0u8; 32];
        for (i, byte) in varied.iter_mut().take(8).enumerate() {
            *byte = i as u8;
        }
        assert!(has_sufficient_entropy(&varied));

        // A freshly generated nonce should have sufficient entropy.
        let nonce = generate_nonce()?;
        assert!(has_sufficient_entropy(&nonce));
        Ok(())
    }

    /* ========================================================================== */
    /*                    PC-297: STATISTICAL DISTRIBUTION TEST                  */
    /* ========================================================================== */

    #[test]
    fn test_generate_nonce_no_duplicates_in_1000() -> Result<()> {
        // PC-297: Generate 1000 nonces and verify no duplicates exist.
        // For a 32-byte CSPRNG output, the probability of any collision in 1000
        // samples is negligible (~2^-237). A duplicate would indicate a broken RNG.
        let mut nonces: Vec<[u8; 32]> = Vec::with_capacity(1000);
        for _ in 0..1000 {
            nonces.push(generate_nonce()?);
        }

        // Sort and check for adjacent duplicates (O(n log n) instead of O(n^2))
        nonces.sort();
        for window in nonces.windows(2) {
            assert_ne!(
                window[0], window[1],
                "CSPRNG produced duplicate nonces: this indicates a broken RNG"
            );
        }
        Ok(())
    }

    #[test]
    fn test_generate_nonce_byte_distribution() -> Result<()> {
        // PC-297: Check that nonce bytes are roughly uniformly distributed.
        // Generate 100 nonces (3200 bytes) and verify all 256 byte values appear
        // at least once. For uniform random, expected count per value is ~12.5.
        // The probability that any specific byte value never appears in 3200
        // trials is (255/256)^3200 ~ 3.5e-6, extremely unlikely.
        let mut byte_seen = [false; 256];
        for _ in 0..100 {
            let nonce = generate_nonce()?;
            for &b in &nonce {
                byte_seen[b as usize] = true;
            }
        }

        let unseen_count = byte_seen.iter().filter(|&&seen| !seen).count();
        // Allow up to 5 unseen values to avoid flaky tests, though typically 0
        assert!(
            unseen_count <= 5,
            "Too many byte values unseen in 3200 random bytes: {unseen_count} unseen (max 5 allowed)"
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    PHASE 4: WASM-SPECIFIC TESTS - GENERATE_NONCE         */
    /* ========================================================================== */

    /// Test that generate_nonce() works correctly on WASM
    /// NOTE: This test runs only when compiled for wasm32 target:
    ///   cargo test --target wasm32-unknown-unknown
    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_generate_nonce_wasm_success() -> Result<()> {
        let nonce = generate_nonce()?;
        assert_eq!(nonce.len(), 32, "WASM nonce must be 32 bytes");
        assert!(
            validate_nonce(&nonce),
            "WASM nonce must be valid (not all zeros)"
        );
        assert!(
            has_sufficient_entropy(&nonce),
            "WASM nonce must have sufficient entropy"
        );
        Ok(())
    }

    /// Test that generate_nonce() generates unique nonces on WASM
    /// NOTE: This test runs only when compiled for wasm32 target:
    ///   cargo test --target wasm32-unknown-unknown
    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_generate_nonce_wasm_unique() -> Result<()> {
        let nonce1 = generate_nonce()?;
        let nonce2 = generate_nonce()?;
        assert_ne!(nonce1, nonce2, "WASM nonces must be unique");
        Ok(())
    }
}
