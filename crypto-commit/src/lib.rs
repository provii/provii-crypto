#![forbid(unsafe_code)]

//! Commitment operations for Provii credentials.
//!
//! This module provides host-side Pedersen commitment on the Jubjub curve,
//! matching the in-circuit implementation for zero-knowledge proofs.

use group::GroupEncoding;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use provii_crypto_commons::Error;
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};

/// Maximum randomness bits that the Sapling Pedersen hash can accept.
///
/// Sapling provides 6 generators with 63 chunks each, 3 bits per chunk = 1134 total bits.
/// NoteCommitment personalization consumes 6 bits, leaving 1128 data bits.
/// After 32 bits for dob_days, at most 1096 bits of randomness remain.
/// In practice the protocol uses exactly 128 bits.
const MAX_PEDERSEN_RANDOMNESS_BITS: usize = 1096;

/// Minimum randomness bits required for a hiding Pedersen commitment.
///
/// 128 bits provides computational hiding against brute-force inversion.
/// Shorter randomness makes the commitment trivially invertible.
const MIN_PEDERSEN_RANDOMNESS_BITS: usize = 128;

/// Compute a Pedersen commitment for date of birth, validating entropy on `r_bits`.
///
/// Matches the circuit implementation exactly:
/// - Uses the same generator points as sapling-crypto NoteCommitment.
/// - Returns 32 bytes (compressed Jubjub point).
/// - Input: `dob_days` as i32 (biased to u32 via sign-magnitude XOR for circuit compatibility).
///
/// # Arguments
/// * `dob_days` - Days since epoch (i32, negative for pre-1970 dates).
/// * `r_bits` - Randomness bits (at least 128 and at most 1096, with sufficient byte-value
///   diversity per [`validate_commitment_randomness`]).
///
/// # Errors
/// Returns `Error::InvalidInput` if `r_bits` fails entropy validation, is shorter than 128 bits
/// (minimum for computational hiding), or exceeds the Pedersen generator capacity (1096 bits).
///
/// # Returns
/// 32-byte compressed Jubjub point.
pub fn pedersen_commit_dob_validated(dob_days: i32, r_bits: &[bool]) -> Result<[u8; 32], Error> {
    validate_commitment_randomness(r_bits)?;

    if r_bits.len() < MIN_PEDERSEN_RANDOMNESS_BITS {
        return Err(Error::InvalidInput);
    }
    if r_bits.len() > MAX_PEDERSEN_RANDOMNESS_BITS {
        return Err(Error::InvalidInput);
    }

    // Apply sign-magnitude bias so the circuit's unsigned comparison works correctly.
    let biased = provii_crypto_commons::bias_for_circuit(dob_days);

    // Convert biased value to little-endian bits.
    // Wrapped in Zeroizing because dob_bits reveals the date of birth.
    let mut dob_bits = Zeroizing::new(vec![]);
    let mut value = biased;
    for _ in 0..32 {
        dob_bits.push((value & 1) != 0);
        value >>= 1;
    }

    // Concatenate the date bits with the randomness bits.
    // Wrapped in Zeroizing because in_bits contains DOB + blinding factor.
    let mut in_bits = Zeroizing::new(std::mem::take(&mut *dob_bits));
    in_bits.extend_from_slice(r_bits);

    // Hash with the Pedersen generator set used by the circuit.
    let point = pedersen_hash(Personalization::NoteCommitment, in_bits.iter().copied());

    // Convert the resulting point to bytes.
    Ok(point.to_bytes())
}

/// Compute Pedersen-based nullifier matching the circuit implementation.
///
/// Produces a stable, deterministic 32-byte identifier for a credential by
/// hashing `NULLIFIER_DST || c_bytes` through the Sapling Pedersen hash with
/// `MerkleTree(0)` personalisation. The same commitment bytes always produce
/// the same nullifier.
///
/// # Privacy implications
///
/// This value is a SNARK public input and is visible to the Provii operator
/// (provii-verifier) on every verification. Because it is deterministic per
/// credential, the operator can observe that two verification sessions used
/// the same credential. Third-party verifier websites never see the nullifier;
/// it is not returned in any hosted-flow API response.
///
/// # Why this exists
///
/// The ban list requires a stable credential identifier so that individual
/// credentials can be revoked. Without a deterministic nullifier, revoking a
/// single compromised or abusive credential would be impossible. The trade-off
/// is operator-level session linkability in exchange for credential revocation
/// capability.
pub fn pedersen_nullifier(c_bytes: &[u8; 32]) -> [u8; 32] {
    // Imported from crypto-commons to keep a single source of truth.
    use provii_crypto_commons::NULLIFIER_DST;

    // Convert the domain and commitment bytes to little-endian bits.
    let mut bits = Vec::new();

    // Encode the domain separator bits.
    for byte in NULLIFIER_DST {
        for i in 0..8 {
            bits.push(((byte >> i) & 1) != 0);
        }
    }

    // Append the commitment bytes as bits.
    for byte in c_bytes {
        for i in 0..8 {
            bits.push(((byte >> i) & 1) != 0);
        }
    }

    // Hash with Pedersen using the MerkleTree personalization.
    use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};
    let point = pedersen_hash(Personalization::MerkleTree(0), bits);

    point.to_bytes()
}

/// Generate random bits for commitment randomness.
///
/// The returned value is wrapped in `Zeroizing` so the blinding factor is
/// automatically wiped from memory on drop. `Zeroizing<Vec<bool>>` implements
/// `Deref<Target = Vec<bool>>`, so callers can use it as a `&[bool]` without
/// change.
///
/// # Arguments
/// * `rng` - Random number generator
/// * `num_bits` - Number of random bits to generate (typically 192-256)
///
/// # Returns
/// `Zeroizing<Vec<bool>>` containing random boolean values
pub fn generate_commitment_randomness<R: CryptoRng + RngCore>(
    rng: &mut R,
    num_bits: usize,
) -> Zeroizing<Vec<bool>> {
    let num_bytes = num_bits.div_ceil(8);
    let mut buf = Zeroizing::new(vec![0u8; num_bytes]);
    rng.fill_bytes(&mut buf);

    let mut bits = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        // SAFETY: i / 8 < num_bytes = num_bits.div_ceil(8) >= (i / 8) + 1, always in bounds.
        let byte = buf.get(i / 8).copied().unwrap_or(0);
        bits.push(((byte >> (i % 8)) & 1) == 1);
    }

    Zeroizing::new(bits)
}

/// Validate that commitment randomness has sufficient entropy.
///
/// Checks that at least 8 unique byte values are present in the randomness.
/// This prevents weak randomness that could compromise commitment hiding.
///
/// # Arguments
/// * `r_bits` - Randomness bits (must be at least 32 bits)
///
/// # Returns
/// `Ok(())` if entropy is sufficient, `Err(Error::InvalidInput)` otherwise
pub fn validate_commitment_randomness(r_bits: &[bool]) -> Result<(), Error> {
    if r_bits.len() < 32 {
        return Err(Error::InvalidInput);
    }

    // Convert bits to bytes
    let mut bytes = Vec::with_capacity(r_bits.len().div_ceil(8));
    for chunk in r_bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << i;
            }
        }
        bytes.push(byte);
    }

    // Count unique byte values (require minimum 8)
    let mut seen = [false; 256];
    let mut unique: u16 = 0;
    for &b in &bytes {
        // ACCEPT(CT-001): timing on r_bits indexing is not exploitable, runs at issuance
        // before randomness is exposed, attacker cannot observe execution
        //
        // SAFETY(indexing): b is u8 so b as usize is always 0..=255, within [bool; 256].
        #[allow(clippy::indexing_slicing)]
        let already_seen = seen[b as usize];
        if !already_seen {
            #[allow(clippy::indexing_slicing)]
            {
                seen[b as usize] = true;
            }
            // SAFETY(arithmetic): unique <= 256 (max distinct u8 values), fits in u16.
            unique = unique.saturating_add(1);
        }
    }

    if unique >= 8 {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

#[cfg(test)]
// Test code: expect is the standard pattern for test setup that cannot fail with
// valid test inputs. A panic from `.expect()` in a test IS the correct failure mode.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Deterministic high-entropy randomness for tests. Produces `num_bits`
    /// of ChaCha20-derived bits seeded from `seed_byte` so different tests
    /// can derive distinct, reproducible randomness without `thread_rng()`.
    fn fixed_r_bits(seed_byte: u8, num_bits: usize) -> Vec<bool> {
        let mut rng = ChaCha20Rng::from_seed([seed_byte; 32]);
        generate_commitment_randomness(&mut rng, num_bits).to_vec()
    }

    /* ========================================================================== */
    /*                    PEDERSEN_COMMIT_DOB_VALIDATED TESTS                    */
    /* ========================================================================== */

    #[test]
    fn test_pedersen_commit_dob_determinism() -> Result<(), Error> {
        let dob_days = 7300i32;
        let r_bits = fixed_r_bits(0xA1, 192);

        let commitment1 = pedersen_commit_dob_validated(dob_days, &r_bits)?;
        let commitment2 = pedersen_commit_dob_validated(dob_days, &r_bits)?;

        assert_eq!(commitment1, commitment2);
        Ok(())
    }

    #[test]
    fn test_pedersen_commit_dob_output_length() -> Result<(), Error> {
        let dob_days = 100i32;
        let r_bits = fixed_r_bits(0xA2, 192);

        let commitment = pedersen_commit_dob_validated(dob_days, &r_bits)?;

        assert_eq!(commitment.len(), 32);
        Ok(())
    }

    #[test]
    fn test_pedersen_commit_dob_different_dob_different_output() -> Result<(), Error> {
        let r_bits = fixed_r_bits(0xA3, 192);

        let commitment1 = pedersen_commit_dob_validated(0, &r_bits)?;
        let commitment2 = pedersen_commit_dob_validated(1, &r_bits)?;
        let commitment3 = pedersen_commit_dob_validated(7300, &r_bits)?;

        assert_ne!(commitment1, commitment2);
        assert_ne!(commitment1, commitment3);
        assert_ne!(commitment2, commitment3);
        Ok(())
    }

    #[test]
    fn test_pedersen_commit_dob_different_randomness_different_output() -> Result<(), Error> {
        let dob_days = 7300i32;
        let r_bits1 = fixed_r_bits(0xA4, 192);
        let r_bits2 = fixed_r_bits(0xA5, 192);

        let commitment1 = pedersen_commit_dob_validated(dob_days, &r_bits1)?;
        let commitment2 = pedersen_commit_dob_validated(dob_days, &r_bits2)?;

        assert_ne!(commitment1, commitment2);
        Ok(())
    }

    #[test]
    fn test_pedersen_commit_dob_edge_case_zero_days() -> Result<(), Error> {
        let r_bits = fixed_r_bits(0xA6, 192);

        let commitment = pedersen_commit_dob_validated(0, &r_bits)?;

        assert_eq!(commitment.len(), 32);
        // Should not be all zeros (Pedersen hash should produce valid point)
        assert_ne!(commitment, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn test_pedersen_commit_dob_edge_case_max_i32() -> Result<(), Error> {
        let r_bits = fixed_r_bits(0xA7, 192);

        let commitment = pedersen_commit_dob_validated(i32::MAX, &r_bits)?;

        assert_eq!(commitment.len(), 32);
        assert_ne!(commitment, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn test_pedersen_commit_dob_edge_case_min_i32() -> Result<(), Error> {
        let r_bits = fixed_r_bits(0xB3, 192);
        let commitment = pedersen_commit_dob_validated(i32::MIN, &r_bits)?;
        assert_eq!(commitment.len(), 32);
        assert_ne!(commitment, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn test_pedersen_commit_dob_empty_randomness_returns_error() {
        let result = pedersen_commit_dob_validated(7300, &[]);
        assert!(result.is_err(), "Empty randomness must be rejected");
    }

    #[test]
    fn test_pedersen_commit_dob_low_entropy_rejected() {
        // Single-byte-value randomness fails entropy validation regardless of length.
        assert!(pedersen_commit_dob_validated(7300, &[true; 192]).is_err());
        assert!(pedersen_commit_dob_validated(7300, &[false; 192]).is_err());
    }

    #[test]
    fn test_pedersen_commit_dob_below_minimum_returns_error() {
        // Any length below 128 bits must be rejected (INV-PC-003), even with full entropy.
        for len in [32usize, 64, 100, 127] {
            // SAFETY(truncation): all values are <= 127, well within u8 range.
            let len_u8 = u8::try_from(len).expect("test values fit in u8");
            let r_bits = fixed_r_bits(0xB0u8.wrapping_add(len_u8), len);
            assert!(
                pedersen_commit_dob_validated(7300, &r_bits).is_err(),
                "r_bits of length {len} must be rejected (below 128-bit minimum)"
            );
        }
    }

    #[test]
    fn test_pedersen_commit_dob_short_randomness_rejected() {
        // One bit of randomness is trivially invertible.
        assert!(pedersen_commit_dob_validated(100, &[true]).is_err());
        assert!(pedersen_commit_dob_validated(100, &[false]).is_err());

        // 127 bits is still below the 128-bit minimum.
        let r_127 = fixed_r_bits(0xC0, 127);
        assert!(pedersen_commit_dob_validated(100, &r_127).is_err());

        // Exactly 128 bits with sufficient entropy must succeed.
        let r_128 = fixed_r_bits(0xC1, 128);
        let c = pedersen_commit_dob_validated(100, &r_128)
            .expect("128-bit randomness with sufficient entropy must succeed");
        assert_eq!(
            c.len(),
            32,
            "Commitment at minimum randomness length must still be 32 bytes"
        );
        assert_ne!(c, [0u8; 32], "Commitment must not be the zero point");
    }

    #[test]
    fn test_pedersen_commit_dob_various_randomness_lengths() -> Result<(), Error> {
        let dob_days = 7300i32;

        let commitment_192 = pedersen_commit_dob_validated(dob_days, &fixed_r_bits(0xD0, 192))?;
        let commitment_256 = pedersen_commit_dob_validated(dob_days, &fixed_r_bits(0xD0, 256))?;
        let commitment_384 = pedersen_commit_dob_validated(dob_days, &fixed_r_bits(0xD0, 384))?;

        assert_eq!(commitment_192.len(), 32);
        assert_eq!(commitment_256.len(), 32);
        assert_eq!(commitment_384.len(), 32);

        // Different randomness lengths should produce different outputs
        assert_ne!(commitment_192, commitment_256);
        assert_ne!(commitment_192, commitment_384);
        assert_ne!(commitment_256, commitment_384);
        Ok(())
    }

    #[test]
    fn test_pedersen_commit_dob_typical_use_case() -> Result<(), Error> {
        // Simulate typical age verification scenario with a seeded RNG for
        // deterministic test behaviour.
        let dob_days = 7300i32; // Approximately 20 years
        let mut rng = ChaCha20Rng::from_seed([0xBB; 32]);
        let r_bits = generate_commitment_randomness(&mut rng, 192);

        let commitment = pedersen_commit_dob_validated(dob_days, &r_bits)?;

        assert_eq!(commitment.len(), 32);

        // Repeated commitment with same inputs should match
        let commitment2 = pedersen_commit_dob_validated(dob_days, &r_bits)?;
        assert_eq!(commitment, commitment2);

        // Different randomness should produce different commitment
        let r_bits2 = generate_commitment_randomness(&mut rng, 192);
        let commitment3 = pedersen_commit_dob_validated(dob_days, &r_bits2)?;
        assert_ne!(commitment, commitment3);
        Ok(())
    }

    #[test]
    fn test_pedersen_commit_dob_oversized_randomness_returns_error() {
        let r_bits = fixed_r_bits(0xE0, MAX_PEDERSEN_RANDOMNESS_BITS + 1);
        let result = pedersen_commit_dob_validated(7300, &r_bits);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    PEDERSEN_NULLIFIER TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_pedersen_nullifier_determinism() {
        let commitment = [42u8; 32];

        let nullifier1 = pedersen_nullifier(&commitment);
        let nullifier2 = pedersen_nullifier(&commitment);

        assert_eq!(nullifier1, nullifier2);
    }

    #[test]
    fn test_pedersen_nullifier_output_length() {
        let commitment = [0u8; 32];

        let nullifier = pedersen_nullifier(&commitment);

        assert_eq!(nullifier.len(), 32);
    }

    #[test]
    fn test_pedersen_nullifier_different_commitments_different_nullifiers() {
        let commitment1 = [0u8; 32];
        let commitment2 = [1u8; 32];
        let commitment3 = [255u8; 32];

        let nullifier1 = pedersen_nullifier(&commitment1);
        let nullifier2 = pedersen_nullifier(&commitment2);
        let nullifier3 = pedersen_nullifier(&commitment3);

        assert_ne!(nullifier1, nullifier2);
        assert_ne!(nullifier1, nullifier3);
        assert_ne!(nullifier2, nullifier3);
    }

    #[test]
    fn test_pedersen_nullifier_all_zeros() {
        let commitment = [0u8; 32];

        let nullifier = pedersen_nullifier(&commitment);

        assert_eq!(nullifier.len(), 32);
        // Nullifier should not be all zeros (Pedersen hash output)
        assert_ne!(nullifier, [0u8; 32]);
    }

    #[test]
    fn test_pedersen_nullifier_all_ones() {
        let commitment = [255u8; 32];

        let nullifier = pedersen_nullifier(&commitment);

        assert_eq!(nullifier.len(), 32);
        assert_ne!(nullifier, [0u8; 32]);
        assert_ne!(nullifier, [255u8; 32]);
    }

    #[test]
    fn test_pedersen_nullifier_pattern_variation() {
        let commitment1 = [0xAAu8; 32]; // 10101010 pattern
        let commitment2 = [0x55u8; 32]; // 01010101 pattern

        let nullifier1 = pedersen_nullifier(&commitment1);
        let nullifier2 = pedersen_nullifier(&commitment2);

        assert_ne!(nullifier1, nullifier2);
    }

    #[test]
    fn test_pedersen_nullifier_single_bit_difference() {
        let commitment1 = [0u8; 32];
        let mut commitment2 = [0u8; 32];
        commitment2[0] = 1; // Single bit difference

        let nullifier1 = pedersen_nullifier(&commitment1);
        let nullifier2 = pedersen_nullifier(&commitment2);

        assert_ne!(nullifier1, nullifier2);
    }

    #[test]
    fn test_pedersen_nullifier_with_real_commitment() -> Result<(), Error> {
        // Generate a real commitment and compute its nullifier
        let dob_days = 7300i32;
        let r_bits = fixed_r_bits(0xF0, 192);

        let commitment = pedersen_commit_dob_validated(dob_days, &r_bits)?;
        let nullifier = pedersen_nullifier(&commitment);

        assert_eq!(nullifier.len(), 32);
        assert_ne!(nullifier, commitment);
        assert_ne!(nullifier, [0u8; 32]);
        Ok(())
    }

    /* ========================================================================== */
    /*                    GENERATE_COMMITMENT_RANDOMNESS TESTS                   */
    /* ========================================================================== */

    #[test]
    fn test_generate_commitment_randomness_correct_length() {
        let mut rng = ChaCha20Rng::from_seed([0xCC; 32]);

        let bits_0 = generate_commitment_randomness(&mut rng, 0);
        let bits_1 = generate_commitment_randomness(&mut rng, 1);
        let bits_8 = generate_commitment_randomness(&mut rng, 8);
        let bits_192 = generate_commitment_randomness(&mut rng, 192);
        let bits_256 = generate_commitment_randomness(&mut rng, 256);

        assert_eq!(bits_0.len(), 0);
        assert_eq!(bits_1.len(), 1);
        assert_eq!(bits_8.len(), 8);
        assert_eq!(bits_192.len(), 192);
        assert_eq!(bits_256.len(), 256);
    }

    #[test]
    fn test_generate_commitment_randomness_determinism_with_seed() {
        let seed = [42u8; 32];

        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let bits1 = generate_commitment_randomness(&mut rng1, 256);

        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let bits2 = generate_commitment_randomness(&mut rng2, 256);

        assert_eq!(bits1, bits2);
    }

    #[test]
    fn test_generate_commitment_randomness_different_seeds_different_output() {
        let seed1 = [42u8; 32];
        let seed2 = [43u8; 32];

        let mut rng1 = ChaCha20Rng::from_seed(seed1);
        let bits1 = generate_commitment_randomness(&mut rng1, 256);

        let mut rng2 = ChaCha20Rng::from_seed(seed2);
        let bits2 = generate_commitment_randomness(&mut rng2, 256);

        assert_ne!(bits1, bits2);
    }

    #[test]
    fn test_generate_commitment_randomness_distribution() {
        let mut rng = ChaCha20Rng::from_seed([0xDD; 32]);
        let bits = generate_commitment_randomness(&mut rng, 1000);

        assert_eq!(bits.len(), 1000);

        // Expect approximately 50% true values (with generous tolerance for
        // the fixed seed).
        let true_count = bits.iter().filter(|&&b| b).count();
        assert!(
            true_count > 350 && true_count < 650,
            "true_count={true_count}"
        );
    }

    #[test]
    fn test_generate_commitment_randomness_various_lengths() {
        let mut rng = ChaCha20Rng::from_seed([0xEE; 32]);

        // Test various bit lengths
        for num_bits in [0, 1, 7, 8, 9, 15, 16, 17, 192, 256, 384, 512] {
            let bits = generate_commitment_randomness(&mut rng, num_bits);
            assert_eq!(bits.len(), num_bits, "Failed for num_bits={num_bits}");
        }
    }

    #[test]
    fn test_generate_commitment_randomness_not_all_same() {
        let mut rng = ChaCha20Rng::from_seed([0x11; 32]);
        let bits = generate_commitment_randomness(&mut rng, 100);

        // With 100 seeded-random bits the output is deterministic but
        // still has both true and false values.
        let all_true = bits.iter().all(|&b| b);
        let all_false = bits.iter().all(|&b| !b);

        assert!(
            !all_true && !all_false,
            "Randomness should not be all same value"
        );
    }

    #[test]
    fn test_generate_commitment_randomness_typical_lengths() {
        let mut rng = ChaCha20Rng::from_seed([0x22; 32]);

        // Test typical lengths used in age verification
        let bits_192 = generate_commitment_randomness(&mut rng, 192);
        let bits_256 = generate_commitment_randomness(&mut rng, 256);

        assert_eq!(bits_192.len(), 192);
        assert_eq!(bits_256.len(), 256);

        // Both should have reasonable distributions (generous bounds for
        // seeded output).
        let true_count_192 = bits_192.iter().filter(|&&b| b).count();
        let true_count_256 = bits_256.iter().filter(|&&b| b).count();

        assert!(
            true_count_192 > 40 && true_count_192 < 150,
            "192-bit distribution off: {true_count_192}"
        );
        assert!(
            true_count_256 > 60 && true_count_256 < 200,
            "256-bit distribution off: {true_count_256}"
        );
    }

    #[test]
    fn test_generate_commitment_randomness_consecutive_calls_different() {
        let mut rng = ChaCha20Rng::from_seed([0x33; 32]);

        let bits1 = generate_commitment_randomness(&mut rng, 256);
        let bits2 = generate_commitment_randomness(&mut rng, 256);

        // Consecutive calls on the same seeded RNG produce different output
        // because the internal state advances.
        assert_ne!(bits1, bits2);
    }

    /* ========================================================================== */
    /*                    VALIDATE_COMMITMENT_RANDOMNESS TESTS                   */
    /* ========================================================================== */

    #[test]
    fn test_validate_entropy_sufficient() {
        let mut rng = ChaCha20Rng::from_seed([0x44; 32]);
        let r_bits = generate_commitment_randomness(&mut rng, 256);
        let result = validate_commitment_randomness(&r_bits);
        assert!(result.is_ok());
        assert_eq!(r_bits.len(), 256);
        assert!(!r_bits.iter().all(|&b| b), "output must not be all true");
        assert!(!r_bits.iter().all(|&b| !b), "output must not be all false");
    }

    #[test]
    fn test_validate_entropy_all_zeros_fails() {
        let r_bits = vec![false; 256];
        assert!(validate_commitment_randomness(&r_bits).is_err());
    }

    #[test]
    fn test_validate_entropy_all_ones_fails() {
        let r_bits = vec![true; 256];
        assert!(validate_commitment_randomness(&r_bits).is_err());
    }

    #[test]
    fn test_validate_entropy_too_short_fails() {
        let r_bits = vec![true, false, true];
        assert!(validate_commitment_randomness(&r_bits).is_err());
    }

    /* ========================================================================== */
    /*                    INTEGRATION TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_full_commitment_flow() -> Result<(), Error> {
        // Test the full flow: generate randomness -> commit -> compute nullifier
        let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
        let dob_days = 7300i32;

        let r_bits = generate_commitment_randomness(&mut rng, 192);
        let commitment = pedersen_commit_dob_validated(dob_days, &r_bits)?;
        let nullifier = pedersen_nullifier(&commitment);

        assert_eq!(commitment.len(), 32);
        assert_eq!(nullifier.len(), 32);
        assert_ne!(commitment, nullifier);
        Ok(())
    }

    #[test]
    fn test_same_dob_different_randomness_different_nullifiers() -> Result<(), Error> {
        let mut rng = ChaCha20Rng::from_seed([0x66; 32]);
        let dob_days = 7300i32;

        let r_bits1 = generate_commitment_randomness(&mut rng, 192);
        let commitment1 = pedersen_commit_dob_validated(dob_days, &r_bits1)?;
        let nullifier1 = pedersen_nullifier(&commitment1);

        let r_bits2 = generate_commitment_randomness(&mut rng, 192);
        let commitment2 = pedersen_commit_dob_validated(dob_days, &r_bits2)?;
        let nullifier2 = pedersen_nullifier(&commitment2);

        // Same dob but different randomness should produce different commitments and nullifiers
        assert_ne!(commitment1, commitment2);
        assert_ne!(nullifier1, nullifier2);
        Ok(())
    }

    #[test]
    fn test_different_dob_same_randomness_different_nullifiers() -> Result<(), Error> {
        let r_bits = fixed_r_bits(0xF1, 192);

        let commitment1 = pedersen_commit_dob_validated(7300, &r_bits)?;
        let nullifier1 = pedersen_nullifier(&commitment1);

        let commitment2 = pedersen_commit_dob_validated(9125, &r_bits)?;
        let nullifier2 = pedersen_nullifier(&commitment2);

        // Different dob with same randomness should produce different commitments and nullifiers
        assert_ne!(commitment1, commitment2);
        assert_ne!(nullifier1, nullifier2);
        Ok(())
    }

    /* ========================================================================== */
    /*                    REFERENCE VALUE TESTS                                  */
    /* ========================================================================== */

    /// PC-081: Pedersen commitment reference comparison.
    /// Computes a Pedersen commitment for a known, deterministic input and
    /// asserts the output matches a hardcoded reference value. This pins the
    /// commitment output against unintentional changes in the underlying
    /// generator points or hash algorithm.
    #[test]
    fn test_pedersen_commit_reference_value() -> Result<(), Error> {
        // Fixed inputs: dob_days = 7300 (approx 20 years), seed 0xAA for r_bits
        let dob_days = 7300i32;
        let r_bits = fixed_r_bits(0xAA, 192);

        let commitment = pedersen_commit_dob_validated(dob_days, &r_bits)?;

        // Pin the output. If this changes, the Pedersen generator set or
        // bias_for_circuit logic has been modified (breaking change).
        assert_eq!(
            hex::encode(commitment),
            "cf8221945b032a363adb8d8da22b68e4493b71243760297092a86cc9af310c45",
            "Pedersen commitment output changed; verify generator points are intact"
        );
        Ok(())
    }

    /// PC-081 (variant): Pin nullifier output for a known commitment.
    #[test]
    fn test_pedersen_nullifier_reference_value() {
        let c_bytes = [0x42u8; 32];
        let nullifier = pedersen_nullifier(&c_bytes);

        assert_eq!(
            hex::encode(nullifier),
            "d9411a795bd030d7dcb58e08f1d816d70abf3378ecb6ce40acfb58f3d7f515be",
            "Pedersen nullifier output changed; verify MerkleTree(0) personalization is intact"
        );
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    use proptest::prelude::*;

    /// Helper to convert errors into proptest failures.
    fn fail<E: std::fmt::Debug>(e: E) -> TestCaseError {
        TestCaseError::fail(format!("{e:?}"))
    }

    proptest! {
        /// Property: pedersen_commit_dob_validated is deterministic
        #[test]
        fn prop_pedersen_commit_dob_deterministic(
            dob_days in -25000i32..50000,
            r_bits in prop::collection::vec(any::<bool>(), 192)
        ) {
            prop_assume!(validate_commitment_randomness(&r_bits).is_ok());

            let commitment1 = pedersen_commit_dob_validated(dob_days, &r_bits).map_err(fail)?;
            let commitment2 = pedersen_commit_dob_validated(dob_days, &r_bits).map_err(fail)?;

            prop_assert_eq!(commitment1, commitment2);
            prop_assert_eq!(commitment1.len(), 32, "Commitment must be 32 bytes");
        }

        /// Property: hiding (different randomness produces different commitment)
        #[test]
        fn prop_pedersen_commit_dob_hiding_property(
            dob_days in -25000i32..50000,
            r_bits1 in prop::collection::vec(any::<bool>(), 192),
            r_bits2 in prop::collection::vec(any::<bool>(), 192)
        ) {
            prop_assume!(r_bits1 != r_bits2);
            prop_assume!(validate_commitment_randomness(&r_bits1).is_ok());
            prop_assume!(validate_commitment_randomness(&r_bits2).is_ok());

            let commitment1 = pedersen_commit_dob_validated(dob_days, &r_bits1).map_err(fail)?;
            let commitment2 = pedersen_commit_dob_validated(dob_days, &r_bits2).map_err(fail)?;

            prop_assert_ne!(commitment1, commitment2, "Different randomness must produce different commitments (hiding property)");
        }

        /// Property: binding (different dob produces different commitment)
        #[test]
        fn prop_pedersen_commit_dob_binding_property(
            dob_days1 in -25000i32..50000,
            dob_days2 in -25000i32..50000,
            r_bits in prop::collection::vec(any::<bool>(), 192)
        ) {
            prop_assume!(dob_days1 != dob_days2);
            prop_assume!(validate_commitment_randomness(&r_bits).is_ok());

            let commitment1 = pedersen_commit_dob_validated(dob_days1, &r_bits).map_err(fail)?;
            let commitment2 = pedersen_commit_dob_validated(dob_days2, &r_bits).map_err(fail)?;

            prop_assert_ne!(commitment1, commitment2, "Different dob values must produce different commitments (binding property)");
        }

        /// Property: pedersen_nullifier is deterministic
        #[test]
        fn prop_pedersen_nullifier_deterministic(
            commitment in any::<[u8; 32]>()
        ) {
            let nullifier1 = pedersen_nullifier(&commitment);
            let nullifier2 = pedersen_nullifier(&commitment);

            prop_assert_eq!(nullifier1, nullifier2);
            prop_assert_eq!(nullifier1.len(), 32, "Nullifier must be 32 bytes");
        }

        /// Property: different commitments produce different nullifiers
        #[test]
        fn prop_different_commitments_different_nullifiers(
            commitment1 in any::<[u8; 32]>(),
            commitment2 in any::<[u8; 32]>()
        ) {
            prop_assume!(commitment1 != commitment2);

            let nullifier1 = pedersen_nullifier(&commitment1);
            let nullifier2 = pedersen_nullifier(&commitment2);

            prop_assert_ne!(nullifier1, nullifier2, "Different commitments must produce different nullifiers");
        }

        /// Property: generate_commitment_randomness produces correct length
        #[test]
        fn prop_generate_commitment_randomness_length(
            num_bits in 0usize..512,
            seed in any::<[u8; 32]>()
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let bits = generate_commitment_randomness(&mut rng, num_bits);

            prop_assert_eq!(bits.len(), num_bits, "Generated randomness must have exactly {} bits", num_bits);
        }
    }
}
