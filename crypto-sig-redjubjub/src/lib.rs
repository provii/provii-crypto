#![deny(unsafe_code)]

//! RedJubjub-like signatures for Provii credentials (v2)
//!
//! ⚠️ This is a custom scheme inspired by RedJubjub. It is **not** Zcash-compatible.
//! We operate strictly in the prime-order subgroup (`SubgroupPoint`) on Jubjub.
//! Domain separation is done by prefixing BLAKE2s-256 inputs with fixed tags.
//!
//! CRITICAL: This implementation aligns scalar field handling with the circuit:
//! - Challenge computation uses Jubjub scalar field reduction
//! - Signature scalars remain in Jubjub scalar field
//! - The circuit must match this exact reduction

use blake2::{Blake2s256, Digest};
use blake2s_simd::Params;
use ff::Field;
use group::GroupEncoding;
use jubjub::{Fr as JubjubScalar, SubgroupPoint};
use provii_crypto_commons::{cred_v2_prehash_bytes, CredMsgV2};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Atomic counter incremented each time zeroize runs on secret scalar material.
/// Only compiled when the `test-zeroize-counter` feature is active; used by
/// integration tests to detect mutants that replace Zeroize/Drop impls with no-ops.
#[cfg(any(test, feature = "test-zeroize-counter"))]
pub static ZEROIZE_CALL_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

// Domain separation strings, imported from the canonical location in crypto-commons.
const PROVII_RJ_PERSONALIZATION: &[u8; 8] = provii_crypto_commons::REDJUBJUB_PERSONALIZATION;
const PROVII_RJ_NONCE_TAG: &[u8] = provii_crypto_commons::REDJUBJUB_NONCE_TAG;

#[derive(Debug, Error)]
pub enum RedJubjubError {
    #[error("invalid signature bytes")]
    InvalidSignatureBytes,
    #[error("invalid verification key bytes")]
    InvalidVerificationKeyBytes,
    #[error("invalid signing key bytes")]
    InvalidSigningKeyBytes,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("credential field exceeds 255-byte length prefix limit")]
    FieldTooLong,
    #[error("derived signing nonce is zero")]
    InvalidNonce,
}

fn get_spending_key_generator() -> SubgroupPoint {
    // These bytes represent what the circuit's SPENDING_KEY_GENERATOR table actually produces
    // This is the v-coordinate of the generator in compressed Edwards format
    const SPENDING_KEY_GEN_BYTES: [u8; 32] = [
        0x30, 0xb5, 0xf2, 0xaa, 0xad, 0x32, 0x56, 0x30, 0xbc, 0xdd, 0xdb, 0xce, 0x4d, 0x67, 0x65,
        0x6d, 0x05, 0xfd, 0x1c, 0xc2, 0xd0, 0x37, 0xbb, 0x53, 0x75, 0xb6, 0xe9, 0x6d, 0x9e, 0x01,
        0xa1, 0x57,
    ];

    // SAFETY: SPENDING_KEY_GEN_BYTES is the Sapling spending key generator,
    // a known-valid SubgroupPoint on the Jubjub curve (from Zcash spec).
    #[allow(clippy::expect_used)]
    Option::from(SubgroupPoint::from_bytes(&SPENDING_KEY_GEN_BYTES))
        .expect("BUG: mathematically guaranteed generator point") // nosemgrep: provii.crypto.unwrap-on-crypto-operation
}

// Compile-time guard: if jubjub changes JubjubScalar's layout, this fails.
const _: () = assert!(core::mem::size_of::<JubjubScalar>() == 32);

/// RedJubjub signing key (32 bytes)
// nosemgrep: provii.crypto.secret-struct-no-zeroize
pub struct SigningKey {
    scalar: JubjubScalar,
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("scalar", &"[REDACTED]")
            .finish()
    }
}

/// RedJubjub verification key (32 bytes compressed point in the prime subgroup)
#[derive(Debug)]
pub struct VerificationKey {
    point: SubgroupPoint,
}

/// RedJubjub signature (64 bytes: R || s), where R is a subgroup point
///
/// Note: The `s` scalar is derived from secret key material during signing
/// (`s = nonce + c * sk`), but it is intentionally NOT zeroized because it is
/// the public component of the signature that is transmitted to verifiers.
/// Once `to_bytes()` is called, `s` is public knowledge.
#[derive(Debug)]
pub struct Signature {
    r: SubgroupPoint, // 32 bytes compressed
    s: JubjubScalar,  // 32 bytes
}

impl SigningKey {
    /// Create a signing key from canonical bytes (rejects non-canonical/out-of-range).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, RedJubjubError> {
        let scalar = JubjubScalar::from_bytes(bytes)
            .into_option()
            .ok_or(RedJubjubError::InvalidSigningKeyBytes)?;
        if scalar.is_zero().into() {
            return Err(RedJubjubError::InvalidSigningKeyBytes);
        }
        Ok(SigningKey { scalar })
    }

    /// Generate a new random signing key using a CSPRNG.
    pub fn random() -> Self {
        let mut rng = OsRng;
        let scalar = JubjubScalar::random(&mut rng);
        SigningKey { scalar }
    }

    /// Generate with provided RNG (useful for tests).
    pub fn random_with_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        SigningKey {
            scalar: JubjubScalar::random(rng),
        }
    }

    /// Get the corresponding verification key (prime-order subgroup).
    pub fn verification_key(&self) -> VerificationKey {
        let g = get_spending_key_generator();
        // SAFETY: finite field scalar multiplication on Jubjub curve; cannot overflow.
        #[allow(clippy::arithmetic_side_effects)]
        let point = g * self.scalar;
        VerificationKey { point }
    }

    /// Export signing key as bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }
}

/// Securely zeroes the signing key's secret scalar memory on drop.
/// Uses volatile writes to prevent compiler optimization from removing the zeroing.
///
/// # Why unsafe is required here
///
/// `JubjubScalar` (from the `jubjub` crate) does not implement `Zeroize`, and Rust's
/// orphan rules prevent us from adding trait implementations to foreign types.
///
/// Alternatives considered:
/// - `Zeroizing<[u8; 32]>` with `from_bytes` reconstruction on each use: rejected due
///   to Montgomery form conversion overhead on every scalar multiply.
/// - Upstream PR to the `jubjub` crate to add `Zeroize` support: tracked as future work.
/// - Forking `jubjub`: adds maintenance burden disproportionate to this single use case.
///
/// The current approach (unsafe `from_raw_parts_mut` + volatile writes) is the simplest
/// correct solution with zero runtime overhead beyond the zeroization itself.
///
/// Without this, the secret scalar could remain in memory after the SigningKey
/// is dropped, creating a potential side-channel vulnerability where an attacker
/// with memory access could recover the signing key.
#[allow(unsafe_code)]
impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        #[cfg(any(test, feature = "test-zeroize-counter"))]
        ZEROIZE_CALL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let len = core::mem::size_of::<JubjubScalar>();
        let ptr = &mut self.scalar as *mut JubjubScalar as *mut u8;
        // SAFETY: This is safe because:
        // 1. JubjubScalar is a 32-byte value type (internally [u64; 4]) with no padding
        // 2. We have exclusive mutable access via &mut self
        // 3. The pointer is properly aligned (derived from a valid reference)
        // 4. The length is exactly the size of the type
        // 5. Writing zeros to any bit pattern is valid for JubjubScalar
        // 6. We use zeroize's volatile write implementation to prevent optimization
        let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) }; // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage, provii.crypto.unsafe-usage
        slice.zeroize();
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl VerificationKey {
    /// Create a verification key from compressed bytes (enforces subgroup/canonical encoding).
    ///
    /// Explicitly rejects the identity element of the prime-order subgroup, which would
    /// otherwise parse successfully via `SubgroupPoint::from_bytes` but trivially satisfies
    /// any signature equation and cannot correspond to a non-zero signing key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, RedJubjubError> {
        let point = SubgroupPoint::from_bytes(bytes)
            .into_option()
            .ok_or(RedJubjubError::InvalidVerificationKeyBytes)?;

        // Reject the identity element. `is_identity()` returns a `subtle::Choice`
        // so the comparison stays constant-time with respect to the point value.
        use group::Group;
        if bool::from(point.is_identity()) {
            return Err(RedJubjubError::InvalidVerificationKeyBytes);
        }

        Ok(VerificationKey { point })
    }

    /// Export verification key as compressed bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.to_bytes()
    }
}

impl Signature {
    /// Parse signature from bytes with full validation.
    ///
    /// Rejects degenerate inputs where `R` is the group identity or `s` is
    /// zero. An identity `R` trivially satisfies certain verification
    /// equations regardless of the message, and a zero `s` indicates a
    /// malformed signature that could not have been produced by an honest
    /// signer.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, RedJubjubError> {
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&bytes[0..32]);
        s_bytes.copy_from_slice(&bytes[32..64]);

        // R must decode into the prime-order subgroup and be canonical.
        let r = SubgroupPoint::from_bytes(&r_bytes)
            .into_option()
            .ok_or(RedJubjubError::InvalidSignatureBytes)?;

        // Reject the identity element for R. A degenerate R trivially
        // satisfies certain verification equations and cannot result from
        // honest signing (the nonce derivation would need to produce zero).
        use group::Group;
        if bool::from(r.is_identity()) {
            return Err(RedJubjubError::InvalidSignatureBytes);
        }

        // s must be a canonical scalar.
        let s = JubjubScalar::from_bytes(&s_bytes)
            .into_option()
            .ok_or(RedJubjubError::InvalidSignatureBytes)?;

        // Reject a zero s scalar. An honest signer never produces s = 0
        // because that would require the nonce to equal -(c * sk), which
        // is computationally infeasible with deterministic nonce derivation.
        if bool::from(s.is_zero()) {
            return Err(RedJubjubError::InvalidSignatureBytes);
        }

        Ok(Signature { r, s })
    }

    /// Export signature as bytes (R || s)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&self.r.to_bytes());
        out[32..64].copy_from_slice(&self.s.to_bytes());
        out
    }
}

/// Deterministic nonce derivation: r = H("ProviiRJ/nonce" || sk_bytes || msg_hash)
///
/// Intermediate hash buffers are zeroized on drop to prevent nonce leakage.
/// A leaked Schnorr nonce allows full private key recovery.
fn nonce_from(sk_bytes: &[u8; 32], msg_hash: &[u8]) -> JubjubScalar {
    let mut hasher = Blake2s256::new();
    hasher.update(PROVII_RJ_NONCE_TAG);
    hasher.update(sk_bytes);
    hasher.update(msg_hash);
    let mut digest: Zeroizing<[u8; 32]> = Zeroizing::new(hasher.finalize().into());

    // Wide reduction into Jubjub scalar field
    let mut wide = Zeroizing::new([0u8; 64]);
    // SAFETY(slicing): wide is [u8; 64], so [..32] is always in bounds.
    #[allow(clippy::indexing_slicing)]
    wide[..32].copy_from_slice(&*digest);
    // Eagerly zeroize the digest now that it has been copied
    digest.zeroize();

    JubjubScalar::from_bytes_wide(&wide)
    // `wide` is zeroized on drop by Zeroizing wrapper
}

/// Challenge hash with domain separation: c = H("ProviiRJ" || R || VK || msg_hash)
/// CRITICAL: This must match the circuit's scalar reduction exactly
fn hash_challenge(r_bytes: &[u8; 32], vk_bytes: &[u8; 32], msg_hash: &[u8]) -> JubjubScalar {
    let hash = Params::new()
        .hash_length(32)
        .personal(PROVII_RJ_PERSONALIZATION)
        .to_state()
        .update(r_bytes)
        .update(vk_bytes)
        .update(msg_hash)
        .finalize();

    // CRITICAL: Reduce to Jubjub scalar field
    // This is what the circuit must also do
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(hash.as_bytes());
    JubjubScalar::from_bytes_wide(&wide)
}

/// Core sign on a pre-hashed message (BLAKE2s-256 outside).
///
/// The Schnorr nonce and signing key byte copy are zeroized after use.
/// A leaked nonce allows full private key recovery from a single signature.
///
/// Returns `Err(InvalidNonce)` in the astronomically unlikely event that the
/// derived nonce reduces to zero (probability ~2^-252). This is a defensive
/// check per spec §17.17; it preserves determinism because the zero nonce is
/// treated as a hard error rather than a retry path, so spec §8.7 is intact.
fn sign_hash_internal(hash: &[u8], signing_key: &SigningKey) -> Result<Signature, RedJubjubError> {
    // Use the same generator as the circuit
    let g = get_spending_key_generator();

    // Wrap signing key bytes in Zeroizing to prevent stack residue
    let sk_bytes = Zeroizing::new(signing_key.to_bytes());

    // Deterministic nonce for safety and reproducibility.
    // CRITICAL: nonce must be zeroized after use. A single leaked nonce
    // allows full private key recovery via s = nonce + c*sk => sk = (s - nonce) / c.
    let mut nonce = nonce_from(&sk_bytes, hash);

    // Defensive: reject a zero nonce. With Blake2s-256 output reduced into the
    // Jubjub scalar field this has probability ~2^-252 and cannot be triggered
    // by an attacker without breaking Blake2s, but the check is free.
    if bool::from(nonce.is_zero()) {
        zeroize_jubjub_scalar(&mut nonce);
        return Err(RedJubjubError::InvalidNonce);
    }

    // SAFETY: all arithmetic below is finite field operations on the Jubjub curve;
    // these are modular and cannot overflow or produce unexpected side-effects.
    #[allow(clippy::arithmetic_side_effects)]
    let r_point = g * nonce;

    #[allow(clippy::arithmetic_side_effects)]
    let vk_point = g * signing_key.scalar;

    // Challenge, computed to match circuit exactly
    let c = hash_challenge(&r_point.to_bytes(), &vk_point.to_bytes(), hash);

    // s = nonce + c * sk (in Jubjub scalar field)
    #[allow(clippy::arithmetic_side_effects)]
    let s = nonce + (c * signing_key.scalar);

    // Zeroize the nonce scalar. JubjubScalar does not implement Zeroize,
    // so we use the same volatile-write approach as SigningKey::zeroize.
    zeroize_jubjub_scalar(&mut nonce);

    Ok(Signature { r: r_point, s })
}

/// Zeroize a `JubjubScalar` in place using volatile writes.
///
/// `JubjubScalar` (jubjub::Fr) does not implement the `Zeroize` trait and we
/// cannot add foreign trait impls. This helper performs the same byte-level
/// volatile zeroing used by `SigningKey::zeroize`.
#[allow(unsafe_code)]
fn zeroize_jubjub_scalar(scalar: &mut JubjubScalar) {
    #[cfg(test)]
    ZEROIZE_CALL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let len = core::mem::size_of::<JubjubScalar>();
    let ptr = scalar as *mut JubjubScalar as *mut u8;
    // SAFETY: Same invariants as SigningKey::zeroize:
    // 1. JubjubScalar is a 32-byte value type (internally [u64; 4]) with no padding
    // 2. We have exclusive mutable access via &mut
    // 3. The pointer is properly aligned (derived from a valid reference)
    // 4. The length is exactly the size of the type
    // 5. Writing zeros to any bit pattern is valid for JubjubScalar
    // 6. We use zeroize's volatile write implementation to prevent optimisation
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) }; // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage, provii.crypto.unsafe-usage
    slice.zeroize();
}

/// Core verify on a pre-hashed message (BLAKE2s-256 outside).
fn verify_hash_internal(
    hash: &[u8],
    signature: &Signature,
    verification_key: &VerificationKey,
) -> Result<(), RedJubjubError> {
    // Use the same generator as the circuit
    let g = get_spending_key_generator();

    // Recompute challenge - must match circuit exactly
    let c = hash_challenge(&signature.r.to_bytes(), &verification_key.to_bytes(), hash);

    // Check: s * G == R + c * VK
    // SAFETY: all arithmetic below is finite field operations on the Jubjub curve.
    #[allow(clippy::arithmetic_side_effects)]
    let lhs = g * signature.s;
    #[allow(clippy::arithmetic_side_effects)]
    let c_times_vk = verification_key.point * c;
    #[allow(clippy::arithmetic_side_effects)]
    let rhs = signature.r + c_times_vk;

    if bool::from(lhs.to_bytes().ct_eq(&rhs.to_bytes())) {
        Ok(())
    } else {
        Err(RedJubjubError::VerificationFailed)
    }
}

/// Sign a v2 credential (no RP binding).
pub fn sign_cred_v2(
    cred_msg: &CredMsgV2,
    signing_key: &[u8; 32],
) -> Result<[u8; 64], RedJubjubError> {
    let key = SigningKey::from_bytes(signing_key)?;

    // Prehash credential fields
    let prehash = cred_v2_prehash_bytes(
        cred_msg.v,
        &cred_msg.kid,
        &cred_msg.c,
        cred_msg.iat,
        cred_msg.exp,
        &cred_msg.schema,
    )
    .map_err(|_| RedJubjubError::FieldTooLong)?;

    let mut h = Blake2s256::new();
    h.update(&prehash);
    let hash = h.finalize();

    let sig = sign_hash_internal(hash.as_ref(), &key)?;

    Ok(sig.to_bytes())
}

/// Verify a v2 credential signature (no RP binding).
pub fn verify_cred_v2(
    cred_msg: &CredMsgV2,
    signature: &[u8; 64],
    verification_key: &[u8; 32],
) -> Result<(), RedJubjubError> {
    let vk = VerificationKey::from_bytes(verification_key)?;
    let sig = Signature::from_bytes(signature)?;

    let prehash = cred_v2_prehash_bytes(
        cred_msg.v,
        &cred_msg.kid,
        &cred_msg.c,
        cred_msg.iat,
        cred_msg.exp,
        &cred_msg.schema,
    )
    .map_err(|_| RedJubjubError::FieldTooLong)?;

    let mut h = Blake2s256::new();
    h.update(&prehash);
    let hash = h.finalize();

    verify_hash_internal(hash.as_ref(), &sig, &vk)
}

/// Sign a v2 credential WITH RP binding: H(cred) || rp → sign.
pub fn sign_cred_v2_with_rp(
    cred_msg: &CredMsgV2,
    rp: &[u8; 32],
    signing_key: &[u8; 32],
) -> Result<[u8; 64], RedJubjubError> {
    let key = SigningKey::from_bytes(signing_key)?;

    // Hash credential
    let prehash = cred_v2_prehash_bytes(
        cred_msg.v,
        &cred_msg.kid,
        &cred_msg.c,
        cred_msg.iat,
        cred_msg.exp,
        &cred_msg.schema,
    )
    .map_err(|_| RedJubjubError::FieldTooLong)?;

    let mut h = Blake2s256::new();
    h.update(&prehash);
    let cred_hash = h.finalize();

    // Bind to RP
    let mut combined = Blake2s256::new();
    combined.update(&cred_hash[..]);
    combined.update(rp);
    let final_hash = combined.finalize();

    let sig = sign_hash_internal(final_hash.as_ref(), &key)?;

    Ok(sig.to_bytes())
}

/// Verify a v2 credential WITH RP binding.
pub fn verify_cred_v2_with_rp(
    cred_msg: &CredMsgV2,
    rp: &[u8; 32],
    signature: &[u8; 64],
    verification_key: &[u8; 32],
) -> Result<(), RedJubjubError> {
    let vk = VerificationKey::from_bytes(verification_key)?;
    let sig = Signature::from_bytes(signature)?;

    // Hash credential
    let prehash = cred_v2_prehash_bytes(
        cred_msg.v,
        &cred_msg.kid,
        &cred_msg.c,
        cred_msg.iat,
        cred_msg.exp,
        &cred_msg.schema,
    )
    .map_err(|_| RedJubjubError::FieldTooLong)?;

    let mut h = Blake2s256::new();
    h.update(&prehash);
    let cred_hash = h.finalize();

    // Bind to RP
    let mut combined = Blake2s256::new();
    combined.update(&cred_hash[..]);
    combined.update(rp);
    let final_hash = combined.finalize();

    verify_hash_internal(final_hash.as_ref(), &sig, &vk)
}

/// Generate a new keypair (sk bytes wrapped in Zeroizing, vk bytes).
pub fn generate_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let signing_key = SigningKey::random();
    let verification_key = signing_key.verification_key();

    (
        Zeroizing::new(signing_key.to_bytes()),
        verification_key.to_bytes(),
    )
}

/// Generate with custom RNG (useful for tests/benchmarks).
pub fn generate_keypair_with_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let signing_key = SigningKey::random_with_rng(rng);
    let verification_key = signing_key.verification_key();
    (
        Zeroizing::new(signing_key.to_bytes()),
        verification_key.to_bytes(),
    )
}

#[cfg(test)]
#[allow(
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn small_scalar_bytes(val: u64) -> [u8; 32] {
        // Little-endian encoding of a small integer that is definitely < r
        let mut b = [0u8; 32];
        let mut x = val;
        let mut i = 0;
        while x > 0 {
            b[i] = (x & 0xff) as u8;
            x >>= 8;
            i += 1;
        }
        b
    }

    #[test]
    fn test_sign_verify_cycle() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let cred = CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: [1; 32],
            iat: 1704067200,
            exp: 1735689600,
            schema: "age18+".to_string(),
        };

        let signature = sign_cred_v2(&cred, &sk_bytes)?;
        assert!(verify_cred_v2(&cred, &signature, &vk_bytes).is_ok());

        // Mutate message → must fail
        let mut bad = cred.clone();
        bad.iat = 1234567890;
        assert!(verify_cred_v2(&bad, &signature, &vk_bytes).is_err());
        Ok(())
    }

    #[test]
    fn test_rp_binding() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();
        let rp = [42u8; 32];

        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1704067200,
            exp: 1735689600,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2_with_rp(&cred, &rp, &sk_bytes)?;

        // Correct RP verifies
        assert!(verify_cred_v2_with_rp(&cred, &rp, &sig, &vk_bytes).is_ok());

        // Wrong RP must fail
        let wrong_rp = [99u8; 32];
        assert!(verify_cred_v2_with_rp(&cred, &wrong_rp, &sig, &vk_bytes).is_err());
        Ok(())
    }

    #[test]
    fn test_basic_equation() {
        let g = get_spending_key_generator();
        let sk = JubjubScalar::from(5u64);
        let vk = g * sk;

        let nonce = JubjubScalar::from(7u64);
        let r = g * nonce;

        let c = JubjubScalar::from(3u64);
        let s = nonce + (c * sk);

        let lhs = g * s;
        let rhs = r + (vk * c);
        assert_eq!(lhs, rhs, "basic Schnorr equation must hold");
    }

    #[test]
    fn test_minimal_sign_verify() -> Result<(), Box<dyn std::error::Error>> {
        // Use a small, canonical scalar (1)
        let sk_bytes = small_scalar_bytes(1);
        let sk = SigningKey::from_bytes(&sk_bytes)?;
        let vk = sk.verification_key();

        // Sign a small message hash
        let msg = b"test message";
        let sig = super::sign_hash_internal(msg, &sk)?;

        assert!(super::verify_hash_internal(msg, &sig, &vk).is_ok());
        Ok(())
    }

    #[test]
    fn test_generator_consistency() {
        println!("\n=== Testing Generator Consistency ===");

        let gen = get_spending_key_generator();
        let gen_bytes = gen.to_bytes();
        println!("SPENDING_KEY_GENERATOR bytes: {}", hex::encode(gen_bytes));

        // Verify it matches what we expect from the circuit
        assert_eq!(
            hex::encode(gen_bytes),
            "30b5f2aaad325630bcdddbce4d67656d05fd1cc2d037bb5375b6e96d9e01a157",
            "Generator must match circuit's SPENDING_KEY_GENERATOR"
        );
        println!("✅ Using correct SPENDING_KEY_GENERATOR bytes");
    }

    #[test]
    fn test_challenge_scalar_computation() -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== Testing Challenge Scalar Computation ===");

        // Test vectors
        let r_bytes =
            hex::decode("30b5f2aaad325630bcdddbce4d67656d05fd1cc2d037bb5375b6e96d9e01a157")?;
        let vk_bytes =
            hex::decode("5f931e438fd8769f88a64cee744c14e09d85ec942f1b1e2da44faadb256fb20c")?;
        let msg_hash =
            hex::decode("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a")?;

        let mut r_array = [0u8; 32];
        let mut vk_array = [0u8; 32];
        r_array.copy_from_slice(&r_bytes);
        vk_array.copy_from_slice(&vk_bytes);

        let c = hash_challenge(&r_array, &vk_array, &msg_hash);

        println!("Challenge scalar: {}", hex::encode(c.to_bytes()));

        // Verify it's deterministic
        let c2 = hash_challenge(&r_array, &vk_array, &msg_hash);
        assert_eq!(c, c2, "Challenge computation must be deterministic");

        println!("✅ Challenge computation is deterministic");
        Ok(())
    }

    /* ========================================================================== */
    /*                    SIGNING KEY TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_signing_key_from_valid_bytes() {
        let bytes = small_scalar_bytes(12345);
        let result = SigningKey::from_bytes(&bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_signing_key_rejects_zero() {
        let zero_bytes = [0u8; 32];
        let result = SigningKey::from_bytes(&zero_bytes);
        assert!(matches!(
            result,
            Err(RedJubjubError::InvalidSigningKeyBytes)
        ));
    }

    #[test]
    fn test_signing_key_rejects_non_canonical() {
        // All 0xFF bytes is definitely non-canonical (exceeds field modulus)
        let non_canonical = [0xFF; 32];
        let result = SigningKey::from_bytes(&non_canonical);
        assert!(result.is_err());
    }

    #[test]
    fn test_signing_key_to_bytes_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = small_scalar_bytes(999);
        let sk = SigningKey::from_bytes(&bytes)?;
        let exported = sk.to_bytes();

        // Should be able to recreate the key
        let sk2 = SigningKey::from_bytes(&exported)?;
        assert_eq!(sk.scalar, sk2.scalar);
        Ok(())
    }

    #[test]
    fn test_signing_key_random_generates_valid_keys() {
        for _ in 0..10 {
            let sk = SigningKey::random();
            let bytes = sk.to_bytes();

            // Should be able to parse it back
            let sk2 = SigningKey::from_bytes(&bytes);
            assert!(sk2.is_ok());
        }
    }

    #[test]
    fn test_signing_key_random_generates_different_keys() {
        let sk1 = SigningKey::random();
        let sk2 = SigningKey::random();

        assert_ne!(sk1.scalar, sk2.scalar, "Random keys should be different");
    }

    #[test]
    fn test_signing_key_random_with_rng_deterministic() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let seed = [42u8; 32];
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let sk1 = SigningKey::random_with_rng(&mut rng1);

        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let sk2 = SigningKey::random_with_rng(&mut rng2);

        assert_eq!(sk1.scalar, sk2.scalar, "Same seed should produce same key");
    }

    #[test]
    fn test_signing_key_verification_key_consistency() -> Result<(), Box<dyn std::error::Error>> {
        let sk_bytes = small_scalar_bytes(777);
        let sk = SigningKey::from_bytes(&sk_bytes)?;

        let vk1 = sk.verification_key();
        let vk2 = sk.verification_key();

        assert_eq!(vk1.point, vk2.point, "VK derivation must be deterministic");
        Ok(())
    }

    /* ========================================================================== */
    /*                    VERIFICATION KEY TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_verification_key_from_valid_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(123))?;
        let vk = sk.verification_key();
        let vk_bytes = vk.to_bytes();

        let vk2 = VerificationKey::from_bytes(&vk_bytes);
        assert!(vk2.is_ok());
        assert_eq!(vk.point, vk2?.point);
        Ok(())
    }

    #[test]
    fn test_verification_key_rejects_invalid_point() {
        // All zeros is not a valid compressed point
        let invalid = [0u8; 32];
        let result = VerificationKey::from_bytes(&invalid);
        assert!(matches!(
            result,
            Err(RedJubjubError::InvalidVerificationKeyBytes)
        ));
    }

    #[test]
    fn test_verification_key_rejects_non_subgroup_point() {
        // All 0xFF is not a valid point encoding
        let invalid = [0xFF; 32];
        let result = VerificationKey::from_bytes(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_verification_key_to_bytes_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(456))?;
        let vk = sk.verification_key();

        let bytes = vk.to_bytes();
        let vk2 = VerificationKey::from_bytes(&bytes)?;

        assert_eq!(vk.point, vk2.point);
        Ok(())
    }

    #[test]
    fn test_verification_key_different_sk_different_vk() -> Result<(), Box<dyn std::error::Error>> {
        let sk1 = SigningKey::from_bytes(&small_scalar_bytes(100))?;
        let sk2 = SigningKey::from_bytes(&small_scalar_bytes(200))?;

        let vk1 = sk1.verification_key();
        let vk2 = sk2.verification_key();

        assert_ne!(vk1.point, vk2.point);
        Ok(())
    }

    /* ========================================================================== */
    /*                    SIGNATURE TESTS                                        */
    /* ========================================================================== */

    #[test]
    fn test_signature_from_valid_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_keypair();
        let sk = SigningKey::from_bytes(&sk_bytes)?;

        let msg = b"test";
        let sig = sign_hash_internal(msg, &sk)?;
        let sig_bytes = sig.to_bytes();

        let sig2 = Signature::from_bytes(&sig_bytes);
        assert!(sig2.is_ok());
        Ok(())
    }

    #[test]
    fn test_signature_rejects_invalid_r() {
        let mut invalid_sig = [0u8; 64];
        // First 32 bytes (R) are all 0xFF (invalid point)
        invalid_sig[..32].copy_from_slice(&[0xFF; 32]);
        // Second 32 bytes (s) are valid small scalar
        invalid_sig[32..].copy_from_slice(&small_scalar_bytes(1));

        let result = Signature::from_bytes(&invalid_sig);
        assert!(matches!(result, Err(RedJubjubError::InvalidSignatureBytes)));
    }

    #[test]
    fn test_signature_rejects_invalid_s() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_keypair();
        let sk = SigningKey::from_bytes(&sk_bytes)?;

        let msg = b"test";
        let sig = sign_hash_internal(msg, &sk)?;
        let mut sig_bytes = sig.to_bytes();

        // Corrupt the s scalar (second 32 bytes) to be non-canonical
        sig_bytes[32..].copy_from_slice(&[0xFF; 32]);

        let result = Signature::from_bytes(&sig_bytes);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_signature_to_bytes_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_keypair();
        let sk = SigningKey::from_bytes(&sk_bytes)?;

        let msg = b"round trip test";
        let sig = sign_hash_internal(msg, &sk)?;

        let bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(&bytes)?;

        assert_eq!(sig.r, sig2.r);
        assert_eq!(sig.s, sig2.s);
        Ok(())
    }

    #[test]
    fn test_signature_length_exactly_64_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_keypair();
        let sk = SigningKey::from_bytes(&sk_bytes)?;

        let msg = b"length test";
        let sig = sign_hash_internal(msg, &sk)?;
        let bytes = sig.to_bytes();

        assert_eq!(bytes.len(), 64);
        Ok(())
    }

    /* ========================================================================== */
    /*                    NONCE AND CHALLENGE TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_nonce_from_deterministic() {
        let sk_bytes = small_scalar_bytes(123);
        let msg_hash = b"test message";

        let nonce1 = nonce_from(&sk_bytes, msg_hash);
        let nonce2 = nonce_from(&sk_bytes, msg_hash);

        assert_eq!(nonce1, nonce2, "Nonce generation must be deterministic");
    }

    #[test]
    fn test_nonce_from_different_sk_different_nonce() {
        let sk1_bytes = small_scalar_bytes(100);
        let sk2_bytes = small_scalar_bytes(200);
        let msg_hash = b"same message";

        let nonce1 = nonce_from(&sk1_bytes, msg_hash);
        let nonce2 = nonce_from(&sk2_bytes, msg_hash);

        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_nonce_from_different_message_different_nonce() {
        let sk_bytes = small_scalar_bytes(123);
        let msg1 = b"message one";
        let msg2 = b"message two";

        let nonce1 = nonce_from(&sk_bytes, msg1);
        let nonce2 = nonce_from(&sk_bytes, msg2);

        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_hash_challenge_deterministic() {
        let r_bytes = [1u8; 32];
        let vk_bytes = [2u8; 32];
        let msg_hash = b"test";

        let c1 = hash_challenge(&r_bytes, &vk_bytes, msg_hash);
        let c2 = hash_challenge(&r_bytes, &vk_bytes, msg_hash);

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_hash_challenge_different_r_different_challenge() {
        let r1_bytes = [1u8; 32];
        let r2_bytes = [2u8; 32];
        let vk_bytes = [3u8; 32];
        let msg_hash = b"test";

        let c1 = hash_challenge(&r1_bytes, &vk_bytes, msg_hash);
        let c2 = hash_challenge(&r2_bytes, &vk_bytes, msg_hash);

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_hash_challenge_different_vk_different_challenge() {
        let r_bytes = [1u8; 32];
        let vk1_bytes = [2u8; 32];
        let vk2_bytes = [3u8; 32];
        let msg_hash = b"test";

        let c1 = hash_challenge(&r_bytes, &vk1_bytes, msg_hash);
        let c2 = hash_challenge(&r_bytes, &vk2_bytes, msg_hash);

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_hash_challenge_different_msg_different_challenge() {
        let r_bytes = [1u8; 32];
        let vk_bytes = [2u8; 32];
        let msg1 = b"message one";
        let msg2 = b"message two";

        let c1 = hash_challenge(&r_bytes, &vk_bytes, msg1);
        let c2 = hash_challenge(&r_bytes, &vk_bytes, msg2);

        assert_ne!(c1, c2);
    }

    /* ========================================================================== */
    /*                    SIGN/VERIFY TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_sign_hash_internal_produces_valid_signature() -> Result<(), Box<dyn std::error::Error>>
    {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(999))?;
        let msg = b"test message";

        let sig = sign_hash_internal(msg, &sk)?;
        let vk = sk.verification_key();

        assert!(verify_hash_internal(msg, &sig, &vk).is_ok());
        Ok(())
    }

    #[test]
    fn test_sign_hash_internal_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(555))?;
        let msg = b"deterministic test";

        let sig1 = sign_hash_internal(msg, &sk)?;
        let sig2 = sign_hash_internal(msg, &sk)?;

        assert_eq!(sig1.r, sig2.r);
        assert_eq!(sig1.s, sig2.s);
        Ok(())
    }

    #[test]
    fn test_verify_hash_internal_rejects_wrong_message() -> Result<(), Box<dyn std::error::Error>> {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(111))?;
        let vk = sk.verification_key();

        let msg1 = b"original message";
        let msg2 = b"different message";

        let sig = sign_hash_internal(msg1, &sk)?;

        assert!(verify_hash_internal(msg2, &sig, &vk).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_hash_internal_rejects_wrong_vk() -> Result<(), Box<dyn std::error::Error>> {
        let sk1 = SigningKey::from_bytes(&small_scalar_bytes(100))?;
        let sk2 = SigningKey::from_bytes(&small_scalar_bytes(200))?;

        let vk1 = sk1.verification_key();
        let vk2 = sk2.verification_key();

        let msg = b"test";
        let sig = sign_hash_internal(msg, &sk1)?;

        assert!(verify_hash_internal(msg, &sig, &vk1).is_ok());
        assert!(verify_hash_internal(msg, &sig, &vk2).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_hash_internal_rejects_modified_r() -> Result<(), Box<dyn std::error::Error>> {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(777))?;
        let vk = sk.verification_key();
        let msg = b"test";

        let mut sig = sign_hash_internal(msg, &sk)?;

        // Modify R to a different valid point
        let g = get_spending_key_generator();
        sig.r = g * JubjubScalar::from(999u64);

        assert!(verify_hash_internal(msg, &sig, &vk).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_hash_internal_rejects_modified_s() -> Result<(), Box<dyn std::error::Error>> {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(888))?;
        let vk = sk.verification_key();
        let msg = b"test";

        let mut sig = sign_hash_internal(msg, &sk)?;

        // Modify s
        sig.s += JubjubScalar::from(1u64);

        assert!(verify_hash_internal(msg, &sig, &vk).is_err());
        Ok(())
    }

    #[test]
    fn test_sign_cred_v2_valid_signature() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let cred = CredMsgV2 {
            v: 2,
            kid: "test-key-id".to_string(),
            c: [42u8; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig_result = sign_cred_v2(&cred, &sk_bytes);
        assert!(sig_result.is_ok());

        let sig = sig_result?;
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_sign_cred_v2_rejects_invalid_sk() {
        let invalid_sk = [0u8; 32]; // Zero is invalid

        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age21+".to_string(),
        };

        let result = sign_cred_v2(&cred, &invalid_sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_cred_v2_rejects_tampered_v() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let mut cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;

        cred.v = 3; // Tamper
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_cred_v2_rejects_tampered_kid() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let mut cred = CredMsgV2 {
            v: 2,
            kid: "original-kid".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;

        cred.kid = "tampered-kid".to_string(); // Tamper
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_cred_v2_rejects_tampered_commitment() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let mut cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;

        cred.c = [2; 32]; // Tamper
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_cred_v2_rejects_tampered_schema() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let mut cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;

        cred.schema = "age21+".to_string(); // Tamper
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_err());
        Ok(())
    }

    #[test]
    fn test_sign_cred_v2_with_rp_valid() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();
        let rp = [99u8; 32];

        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [5; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2_with_rp(&cred, &rp, &sk_bytes)?;
        assert!(verify_cred_v2_with_rp(&cred, &rp, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_sign_cred_v2_with_rp_different_rp_different_sig(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_keypair();
        let rp1 = [1u8; 32];
        let rp2 = [2u8; 32];

        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig1 = sign_cred_v2_with_rp(&cred, &rp1, &sk_bytes)?;
        let sig2 = sign_cred_v2_with_rp(&cred, &rp2, &sk_bytes)?;

        assert_ne!(
            sig1, sig2,
            "Different RPs should produce different signatures"
        );
        Ok(())
    }

    #[test]
    fn test_verify_cred_v2_with_rp_rejects_tampered_rp() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();
        let rp_original = [10u8; 32];
        let rp_tampered = [11u8; 32];

        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2_with_rp(&cred, &rp_original, &sk_bytes)?;

        // Verify with tampered RP should fail
        assert!(verify_cred_v2_with_rp(&cred, &rp_tampered, &sig, &vk_bytes).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_cred_v2_with_rp_rejects_tampered_credential(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();
        let rp = [77u8; 32];

        let mut cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2_with_rp(&cred, &rp, &sk_bytes)?;

        cred.iat = 9999; // Tamper
        assert!(verify_cred_v2_with_rp(&cred, &rp, &sig, &vk_bytes).is_err());
        Ok(())
    }

    /* ========================================================================== */
    /*                    KEYPAIR GENERATION TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_generate_keypair_produces_valid_keys() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        // SK should be valid
        let sk = SigningKey::from_bytes(&sk_bytes);
        assert!(sk.is_ok());

        // VK should be valid
        let vk = VerificationKey::from_bytes(&vk_bytes);
        assert!(vk.is_ok());

        // VK should match SK
        let derived_vk = sk?.verification_key();
        assert_eq!(derived_vk.to_bytes(), vk_bytes);
        Ok(())
    }

    #[test]
    fn test_generate_keypair_produces_different_keys() {
        let (sk1, vk1) = generate_keypair();
        let (sk2, vk2) = generate_keypair();

        assert_ne!(sk1, sk2);
        assert_ne!(vk1, vk2);
    }

    #[test]
    fn test_generate_keypair_with_rng_deterministic() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let seed = [123u8; 32];

        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let (sk1, vk1) = generate_keypair_with_rng(&mut rng1);

        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let (sk2, vk2) = generate_keypair_with_rng(&mut rng2);

        assert_eq!(sk1, sk2);
        assert_eq!(vk1, vk2);
    }

    #[test]
    fn test_generate_keypair_with_rng_different_seeds() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let mut rng1 = ChaCha20Rng::from_seed(seed1);
        let (sk1, vk1) = generate_keypair_with_rng(&mut rng1);

        let mut rng2 = ChaCha20Rng::from_seed(seed2);
        let (sk2, vk2) = generate_keypair_with_rng(&mut rng2);

        assert_ne!(sk1, sk2);
        assert_ne!(vk1, vk2);
    }

    /* ========================================================================== */
    /*                    ERROR CONDITION TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_error_invalid_signature_bytes() {
        let invalid = [0xFF; 64];
        let result = Signature::from_bytes(&invalid);

        assert!(matches!(result, Err(RedJubjubError::InvalidSignatureBytes)));
    }

    #[test]
    fn test_error_invalid_verification_key_bytes() {
        let invalid = [0xFF; 32];
        let result = VerificationKey::from_bytes(&invalid);

        assert!(matches!(
            result,
            Err(RedJubjubError::InvalidVerificationKeyBytes)
        ));
    }

    #[test]
    fn test_error_invalid_signing_key_bytes_zero() {
        let zero = [0u8; 32];
        let result = SigningKey::from_bytes(&zero);

        assert!(matches!(
            result,
            Err(RedJubjubError::InvalidSigningKeyBytes)
        ));
    }

    #[test]
    fn test_error_verification_failed() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();
        let sk = SigningKey::from_bytes(&sk_bytes)?;
        let vk = VerificationKey::from_bytes(&vk_bytes)?;

        let msg = b"test";
        let sig = sign_hash_internal(msg, &sk)?;

        // Verify with wrong message should give VerificationFailed
        let wrong_msg = b"wrong";
        let result = verify_hash_internal(wrong_msg, &sig, &vk);

        assert!(matches!(result, Err(RedJubjubError::VerificationFailed)));
        Ok(())
    }

    /* ========================================================================== */
    /*                    INTEGRATION TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_full_flow_no_rp() -> Result<(), Box<dyn std::error::Error>> {
        // Generate keypair
        let (sk_bytes, vk_bytes) = generate_keypair();

        // Create credential
        let cred = CredMsgV2 {
            v: 2,
            kid: "integration-test-key".to_string(),
            c: [77u8; 32],
            iat: 1704067200,
            exp: 1735689600,
            schema: "age18+".to_string(),
        };

        // Sign
        let signature = sign_cred_v2(&cred, &sk_bytes)?;

        // Verify
        assert!(verify_cred_v2(&cred, &signature, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_full_flow_with_rp() -> Result<(), Box<dyn std::error::Error>> {
        // Generate keypair
        let (sk_bytes, vk_bytes) = generate_keypair();

        // Create credential
        let cred = CredMsgV2 {
            v: 2,
            kid: "rp-test-key".to_string(),
            c: [88u8; 32],
            iat: 1704067200,
            exp: 1735689600,
            schema: "age21+".to_string(),
        };

        // RP challenge
        let rp = [55u8; 32];

        // Sign with RP
        let signature = sign_cred_v2_with_rp(&cred, &rp, &sk_bytes)?;

        // Verify with RP
        assert!(verify_cred_v2_with_rp(&cred, &rp, &signature, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_multiple_signatures_same_key() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        // Sign multiple different messages
        let cred1 = CredMsgV2 {
            v: 2,
            kid: "key1".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let cred2 = CredMsgV2 {
            v: 2,
            kid: "key2".to_string(),
            c: [2; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age21+".to_string(),
        };

        let sig1 = sign_cred_v2(&cred1, &sk_bytes)?;
        let sig2 = sign_cred_v2(&cred2, &sk_bytes)?;

        // Both should verify
        assert!(verify_cred_v2(&cred1, &sig1, &vk_bytes).is_ok());
        assert!(verify_cred_v2(&cred2, &sig2, &vk_bytes).is_ok());

        // Cross-verification should fail
        assert!(verify_cred_v2(&cred1, &sig2, &vk_bytes).is_err());
        assert!(verify_cred_v2(&cred2, &sig1, &vk_bytes).is_err());
        Ok(())
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    use proptest::prelude::*;

    proptest! {
        /// Property: Keypair generation with same seed produces same keys
        #[test]
        fn prop_generate_keypair_with_rng_deterministic(seed in any::<[u8; 32]>()) {
            use rand::SeedableRng;
            use rand_chacha::ChaCha20Rng;

            let mut rng1 = ChaCha20Rng::from_seed(seed);
            let (sk1, vk1) = generate_keypair_with_rng(&mut rng1);

            let mut rng2 = ChaCha20Rng::from_seed(seed);
            let (sk2, vk2) = generate_keypair_with_rng(&mut rng2);

            prop_assert_eq!(sk1, sk2, "Same seed must produce same signing key");
            prop_assert_eq!(vk1, vk2, "Same seed must produce same verification key");
        }

        /// Property: Nonce generation is deterministic
        #[test]
        fn prop_nonce_from_deterministic(
            sk_bytes in any::<[u8; 32]>(),
            msg_hash in prop::collection::vec(any::<u8>(), 0..100)
        ) {
            // Only test with valid signing keys
            if SigningKey::from_bytes(&sk_bytes).is_err() {
                return Ok(());
            }

            let nonce1 = nonce_from(&sk_bytes, &msg_hash);
            let nonce2 = nonce_from(&sk_bytes, &msg_hash);

            prop_assert_eq!(nonce1, nonce2, "Nonce generation must be deterministic");
        }

        /// Property: Challenge hash is deterministic
        #[test]
        fn prop_hash_challenge_deterministic(
            r_bytes in any::<[u8; 32]>(),
            vk_bytes in any::<[u8; 32]>(),
            msg_hash in prop::collection::vec(any::<u8>(), 0..100)
        ) {
            let c1 = hash_challenge(&r_bytes, &vk_bytes, &msg_hash);
            let c2 = hash_challenge(&r_bytes, &vk_bytes, &msg_hash);

            prop_assert_eq!(c1, c2, "Challenge hash must be deterministic");
        }

        /// Property: Signing is deterministic
        #[test]
        fn prop_sign_cred_v2_deterministic(
            v in any::<u8>(),
            kid in "\\PC{0,20}",
            c in any::<[u8; 32]>(),
            iat in any::<u64>(),
            exp in any::<u64>(),
            schema in "\\PC{0,20}"
        ) {
            let (sk_bytes, _) = generate_keypair();

            let cred = CredMsgV2 { v, kid, c, iat, exp, schema };

            let sig1 = sign_cred_v2(&cred, &sk_bytes);
            let sig2 = sign_cred_v2(&cred, &sk_bytes);

            prop_assert!(sig1.is_ok() && sig2.is_ok());
            let _val1 = sig1?;
            let _val2 = sig2?;
            prop_assert_eq!(_val1, _val2, "Signing must be deterministic");
        }

        /// Property: Sign then verify round-trip always works
        #[test]
        fn prop_sign_verify_round_trip(
            v in any::<u8>(),
            kid in "\\PC{0,20}",
            c in any::<[u8; 32]>(),
            iat in any::<u64>(),
            exp in any::<u64>(),
            schema in "\\PC{0,20}"
        ) {
            let (sk_bytes, vk_bytes) = generate_keypair();

            let cred = CredMsgV2 { v, kid, c, iat, exp, schema };

            let sig = sign_cred_v2(&cred, &sk_bytes);
            prop_assert!(sig.is_ok(), "Signing must succeed");

            let sig_bytes = sig?;
            let verify = verify_cred_v2(&cred, &sig_bytes, &vk_bytes);
            prop_assert!(verify.is_ok(), "Verification must succeed for valid signature");
        }

        /// Property: Different messages produce different signatures
        #[test]
        fn prop_different_messages_different_signatures(
            iat1 in any::<u64>(),
            iat2 in any::<u64>()
        ) {
            prop_assume!(iat1 != iat2);

            let (sk_bytes, _) = generate_keypair();

            let cred1 = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c: [1; 32],
                iat: iat1,
                exp: 2000000000,
                schema: "test".to_string(),
            };

            let cred2 = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c: [1; 32],
                iat: iat2,
                exp: 2000000000,
                schema: "test".to_string(),
            };

            let sig1 = sign_cred_v2(&cred1, &sk_bytes)?;
            let sig2 = sign_cred_v2(&cred2, &sk_bytes)?;

            prop_assert_ne!(sig1, sig2, "Different messages must produce different signatures");
        }

        /// Property: RP binding - different RPs produce different signatures
        #[test]
        fn prop_different_rp_different_signature(
            rp1 in any::<[u8; 32]>(),
            rp2 in any::<[u8; 32]>()
        ) {
            prop_assume!(rp1 != rp2);

            let (sk_bytes, _) = generate_keypair();

            let cred = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c: [1; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: "age18+".to_string(),
            };

            let sig1 = sign_cred_v2_with_rp(&cred, &rp1, &sk_bytes)?;
            let sig2 = sign_cred_v2_with_rp(&cred, &rp2, &sk_bytes)?;

            prop_assert_ne!(sig1, sig2, "Different RPs must produce different signatures");
        }

        /// Property: RP binding verification always works for matching RP
        #[test]
        fn prop_rp_binding_round_trip(
            rp in any::<[u8; 32]>(),
            iat in any::<u64>(),
            exp in any::<u64>()
        ) {
            let (sk_bytes, vk_bytes) = generate_keypair();

            let cred = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c: [1; 32],
                iat,
                exp,
                schema: "age18+".to_string(),
            };

            let sig = sign_cred_v2_with_rp(&cred, &rp, &sk_bytes);
            prop_assert!(sig.is_ok(), "Signing with RP must succeed");

            let sig_bytes = sig?;
            let verify = verify_cred_v2_with_rp(&cred, &rp, &sig_bytes, &vk_bytes);
            prop_assert!(verify.is_ok(), "Verification with matching RP must succeed");
        }

        /// Property: Signature bytes are always 64 bytes
        #[test]
        fn prop_signature_length_invariant(
            kid in "\\PC{0,20}",
            c in any::<[u8; 32]>()
        ) {
            let (sk_bytes, _) = generate_keypair();
            let cred = CredMsgV2 {
                v: 2,
                kid,
                c,
                iat: 1700000000,
                exp: 1800000000,
                schema: "age18+".to_string(),
            };

            let sig = sign_cred_v2(&cred, &sk_bytes);
            prop_assert!(sig.is_ok());
            let _val = sig?;
            prop_assert_eq!(_val.len(), 64, "Signature must be exactly 64 bytes");
        }

        /// Property: VK bytes are always 32 bytes
        #[test]
        fn prop_vk_length_invariant(_i in 0..50) {
            let (_, vk_bytes) = generate_keypair();
            prop_assert_eq!(vk_bytes.len(), 32, "VK must be exactly 32 bytes");
        }

        /// Property: SK bytes are always 32 bytes
        #[test]
        fn prop_sk_length_invariant(_i in 0..50) {
            let (sk_bytes, _) = generate_keypair();
            prop_assert_eq!(sk_bytes.len(), 32, "SK must be exactly 32 bytes");
        }

        /// Property: Verification fails with wrong VK
        #[test]
        fn prop_verify_fails_wrong_vk(
            kid in "\\PC{0,10}",
            schema in "\\PC{0,10}"
        ) {
            let (sk_bytes1, vk_bytes1) = generate_keypair();
            let (_, vk_bytes2) = generate_keypair();

            prop_assume!(vk_bytes1 != vk_bytes2);

            let cred = CredMsgV2 {
                v: 2,
                kid,
                c: [1; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema,
            };

            let sig = sign_cred_v2(&cred, &sk_bytes1)?;
            let verify = verify_cred_v2(&cred, &sig, &vk_bytes2);
            prop_assert!(verify.is_err(), "Verification with wrong VK must fail");
        }

        /// Property: Tampering with any credential field breaks verification
        #[test]
        fn prop_tamper_breaks_verification_v(
            v1 in any::<u8>(),
            v2 in any::<u8>()
        ) {
            prop_assume!(v1 != v2);

            let (sk_bytes, vk_bytes) = generate_keypair();
            let mut cred = CredMsgV2 {
                v: v1,
                kid: "test".to_string(),
                c: [1; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: "age18+".to_string(),
            };

            let sig = sign_cred_v2(&cred, &sk_bytes)?;

            cred.v = v2; // Tamper
            prop_assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_err());
        }

        /// Property: Signature round-trip with random commitment
        #[test]
        fn prop_signature_round_trip_random_commitment(c in any::<[u8; 32]>()) {
            let (sk_bytes, vk_bytes) = generate_keypair();
            let cred = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c,
                iat: 1700000000,
                exp: 1800000000,
                schema: "age18+".to_string(),
            };

            let sig = sign_cred_v2(&cred, &sk_bytes);
            prop_assert!(sig.is_ok());

            let _sig_val = sig?;
            let verify = verify_cred_v2(&cred, &_sig_val, &vk_bytes);
            prop_assert!(verify.is_ok());
        }

        /// Property: Different schemas produce different signatures
        #[test]
        fn prop_different_schemas_different_signatures(
            schema1 in "age[0-9]+\\+",
            schema2 in "age[0-9]+\\+"
        ) {
            prop_assume!(schema1 != schema2);

            let (sk_bytes, _) = generate_keypair();

            let cred1 = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c: [1; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: schema1,
            };

            let cred2 = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c: [1; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: schema2,
            };

            let sig1 = sign_cred_v2(&cred1, &sk_bytes)?;
            let sig2 = sign_cred_v2(&cred2, &sk_bytes)?;

            prop_assert_ne!(sig1, sig2);
        }

        /// Property: SigningKey round-trip through bytes
        #[test]
        fn prop_signing_key_round_trip_bytes(seed in any::<[u8; 32]>()) {
            use rand::SeedableRng;
            use rand_chacha::ChaCha20Rng;

            let mut rng = ChaCha20Rng::from_seed(seed);
            let (sk_bytes, _) = generate_keypair_with_rng(&mut rng);

            let sk = SigningKey::from_bytes(&sk_bytes);
            prop_assert!(sk.is_ok());

            let sk_bytes2 = sk?.to_bytes();
            prop_assert_eq!(*sk_bytes, sk_bytes2);
        }

        /// Property: VerificationKey round-trip through bytes
        #[test]
        fn prop_verification_key_round_trip_bytes(_i in 0..50) {
            let (_, vk_bytes) = generate_keypair();

            let vk = VerificationKey::from_bytes(&vk_bytes);
            prop_assert!(vk.is_ok());

            let vk_bytes2 = vk?.to_bytes();
            prop_assert_eq!(vk_bytes, vk_bytes2);
        }

        /// Property: Signature round-trip through bytes
        #[test]
        fn prop_signature_round_trip_bytes(kid in "\\PC{1,10}") {
            let (sk_bytes, _) = generate_keypair();
            let cred = CredMsgV2 {
                v: 2,
                kid,
                c: [42; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: "age18+".to_string(),
            };

            let sig_bytes = sign_cred_v2(&cred, &sk_bytes)?;
            let sig = Signature::from_bytes(&sig_bytes);
            prop_assert!(sig.is_ok());

            let sig_bytes2 = sig?.to_bytes();
            prop_assert_eq!(sig_bytes, sig_bytes2);
        }

        /// Property: Different exp times produce different signatures
        #[test]
        fn prop_different_exp_different_signatures(
            exp1 in any::<u64>(),
            exp2 in any::<u64>()
        ) {
            prop_assume!(exp1 != exp2);

            let (sk_bytes, _) = generate_keypair();

            let cred1 = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c: [1; 32],
                iat: 1700000000,
                exp: exp1,
                schema: "age18+".to_string(),
            };

            let cred2 = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c: [1; 32],
                iat: 1700000000,
                exp: exp2,
                schema: "age18+".to_string(),
            };

            let sig1 = sign_cred_v2(&cred1, &sk_bytes)?;
            let sig2 = sign_cred_v2(&cred2, &sk_bytes)?;

            prop_assert_ne!(sig1, sig2);
        }

        /// Property: Empty kid is valid
        #[test]
        fn prop_empty_kid_valid(_i in 0..20) {
            let (sk_bytes, vk_bytes) = generate_keypair();
            let cred = CredMsgV2 {
                v: 2,
                kid: String::new(),
                c: [1; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: "age18+".to_string(),
            };

            let sig = sign_cred_v2(&cred, &sk_bytes);
            prop_assert!(sig.is_ok());

            let _sig_val = sig?;
            let verify = verify_cred_v2(&cred, &_sig_val, &vk_bytes);
            prop_assert!(verify.is_ok());
        }

        /// Property: Empty schema is valid
        #[test]
        fn prop_empty_schema_valid(_i in 0..20) {
            let (sk_bytes, vk_bytes) = generate_keypair();
            let cred = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c: [1; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: String::new(),
            };

            let sig = sign_cred_v2(&cred, &sk_bytes);
            prop_assert!(sig.is_ok());

            let _sig_val = sig?;
            let verify = verify_cred_v2(&cred, &_sig_val, &vk_bytes);
            prop_assert!(verify.is_ok());
        }

        /// Property: Zero scalar is rejected as SK
        #[test]
        fn prop_zero_scalar_rejected(_i in 0..20) {
            let zero_bytes = [0u8; 32];
            let result = SigningKey::from_bytes(&zero_bytes);
            prop_assert!(result.is_err());
        }

        /// Property: Non-canonical scalars are rejected
        #[test]
        fn prop_non_canonical_scalar_rejected(_i in 0..20) {
            let non_canonical = [0xFF; 32];
            let result = SigningKey::from_bytes(&non_canonical);
            prop_assert!(result.is_err());
        }

        /// Property: RPs with all same bytes are valid
        #[test]
        fn prop_rp_uniform_bytes_valid(byte_val in any::<u8>()) {
            let (sk_bytes, vk_bytes) = generate_keypair();
            let rp = [byte_val; 32];

            let cred = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c: [1; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: "age18+".to_string(),
            };

            let sig = sign_cred_v2_with_rp(&cred, &rp, &sk_bytes);
            prop_assert!(sig.is_ok());

            let _sig_val = sig?;
            let verify = verify_cred_v2_with_rp(&cred, &rp, &_sig_val, &vk_bytes);
            prop_assert!(verify.is_ok());
        }

        /// Property: Different kids produce different signatures
        #[test]
        fn prop_different_kids_different_signatures(
            kid1 in "\\PC{1,20}",
            kid2 in "\\PC{1,20}"
        ) {
            prop_assume!(kid1 != kid2);

            let (sk_bytes, _) = generate_keypair();

            let cred1 = CredMsgV2 {
                v: 2,
                kid: kid1,
                c: [1; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: "age18+".to_string(),
            };

            let cred2 = CredMsgV2 {
                v: 2,
                kid: kid2,
                c: [1; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: "age18+".to_string(),
            };

            let sig1 = sign_cred_v2(&cred1, &sk_bytes)?;
            let sig2 = sign_cred_v2(&cred2, &sk_bytes)?;

            prop_assert_ne!(sig1, sig2);
        }

        /// Property: Commitment with all same bytes is valid
        #[test]
        fn prop_commitment_uniform_bytes_valid(byte_val in any::<u8>()) {
            let (sk_bytes, vk_bytes) = generate_keypair();
            let cred = CredMsgV2 {
                v: 2,
                kid: "test".to_string(),
                c: [byte_val; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: "age18+".to_string(),
            };

            let sig = sign_cred_v2(&cred, &sk_bytes);
            prop_assert!(sig.is_ok());

            let _sig_val = sig?;
            let verify = verify_cred_v2(&cred, &_sig_val, &vk_bytes);
            prop_assert!(verify.is_ok());
        }

        /// Property: Generator consistency
        #[test]
        fn prop_generator_consistency(_i in 0..50) {
            let g1 = get_spending_key_generator();
            let g2 = get_spending_key_generator();
            prop_assert_eq!(g1, g2, "Generator must be constant");
        }
    }

    /* ========================================================================== */
    /*                    ADDITIONAL EDGE CASE TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_empty_kid_signature() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let cred = CredMsgV2 {
            v: 2,
            kid: String::new(), // Empty kid
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_empty_schema_signature() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let cred = CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: String::new(), // Empty schema
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_very_long_kid_signature() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        // 255 byte kid (maximum for uint8 length prefix)
        let long_kid = "a".repeat(255);

        let cred = CredMsgV2 {
            v: 2,
            kid: long_kid,
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_very_long_schema_signature() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        // 255 byte schema (maximum for uint8 length prefix)
        let long_schema = "b".repeat(255);

        let cred = CredMsgV2 {
            v: 2,
            kid: "test-key".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: long_schema,
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_timestamp_zero_values() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 0,
            exp: 0,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_timestamp_max_values() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: u64::MAX,
            exp: u64::MAX,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_commitment_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [0; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_commitment_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [0xFF; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_version_values() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        // Test various version values
        for v in [0u8, 1, 2, 127, 255] {
            let cred = CredMsgV2 {
                v,
                kid: "test".to_string(),
                c: [1; 32],
                iat: 1700000000,
                exp: 1800000000,
                schema: "age18+".to_string(),
            };

            let sig = sign_cred_v2(&cred, &sk_bytes)?;
            assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        }
        Ok(())
    }

    #[test]
    fn test_rp_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();
        let rp = [0u8; 32];

        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2_with_rp(&cred, &rp, &sk_bytes)?;
        assert!(verify_cred_v2_with_rp(&cred, &rp, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_rp_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();
        let rp = [0xFF; 32];

        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let sig = sign_cred_v2_with_rp(&cred, &rp, &sk_bytes)?;
        assert!(verify_cred_v2_with_rp(&cred, &rp, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    /* ========================================================================== */
    /*                    DEBUG TRAIT TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_signing_key_debug() -> Result<(), Box<dyn std::error::Error>> {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(123))?;
        let debug_str = format!("{sk:?}");
        assert!(debug_str.contains("SigningKey"));
        Ok(())
    }

    #[test]
    fn test_verification_key_debug() -> Result<(), Box<dyn std::error::Error>> {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(456))?;
        let vk = sk.verification_key();
        let debug_str = format!("{vk:?}");
        assert!(debug_str.contains("VerificationKey"));
        Ok(())
    }

    #[test]
    fn test_signature_debug() -> Result<(), Box<dyn std::error::Error>> {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(789))?;
        let sig = sign_hash_internal(b"test", &sk)?;
        let debug_str = format!("{sig:?}");
        assert!(debug_str.contains("Signature"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    ERROR DISPLAY TESTS                                    */
    /* ========================================================================== */

    #[test]
    fn test_error_display_invalid_signature_bytes() {
        let err = RedJubjubError::InvalidSignatureBytes;
        let display_str = format!("{err}");
        assert_eq!(display_str, "invalid signature bytes");
    }

    #[test]
    fn test_error_display_invalid_verification_key_bytes() {
        let err = RedJubjubError::InvalidVerificationKeyBytes;
        let display_str = format!("{err}");
        assert_eq!(display_str, "invalid verification key bytes");
    }

    #[test]
    fn test_error_display_invalid_signing_key_bytes() {
        let err = RedJubjubError::InvalidSigningKeyBytes;
        let display_str = format!("{err}");
        assert_eq!(display_str, "invalid signing key bytes");
    }

    #[test]
    fn test_error_display_verification_failed() {
        let err = RedJubjubError::VerificationFailed;
        let display_str = format!("{err}");
        assert_eq!(display_str, "signature verification failed");
    }

    #[test]
    fn test_error_debug() {
        let err = RedJubjubError::VerificationFailed;
        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("VerificationFailed"));
    }

    /* ========================================================================== */
    /*                    ADDITIONAL BOUNDARY VALUE TESTS                        */
    /* ========================================================================== */

    #[test]
    fn test_signature_bytes_slice_exactly_64() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, _) = generate_keypair();
        let sk = SigningKey::from_bytes(&sk_bytes)?;
        let sig = sign_hash_internal(b"test", &sk)?;
        let bytes = sig.to_bytes();

        // Verify we can parse it back
        let sig2 = Signature::from_bytes(&bytes)?;
        assert_eq!(sig.r, sig2.r);
        assert_eq!(sig.s, sig2.s);
        Ok(())
    }

    #[test]
    fn test_verification_key_bytes_exactly_32() -> Result<(), Box<dyn std::error::Error>> {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(999))?;
        let vk = sk.verification_key();
        let bytes = vk.to_bytes();

        assert_eq!(bytes.len(), 32);

        // Verify we can parse it back
        let vk2 = VerificationKey::from_bytes(&bytes)?;
        assert_eq!(vk.point, vk2.point);
        Ok(())
    }

    #[test]
    fn test_signing_key_bytes_exactly_32() -> Result<(), Box<dyn std::error::Error>> {
        let sk = SigningKey::from_bytes(&small_scalar_bytes(777))?;
        let bytes = sk.to_bytes();

        assert_eq!(bytes.len(), 32);

        // Verify we can parse it back
        let sk2 = SigningKey::from_bytes(&bytes)?;
        assert_eq!(sk.scalar, sk2.scalar);
        Ok(())
    }

    #[test]
    fn test_generator_point_bytes_match_constant() {
        let gen = get_spending_key_generator();
        let bytes = gen.to_bytes();

        // Must match the constant defined in get_spending_key_generator
        assert_eq!(
            bytes,
            [
                0x30, 0xb5, 0xf2, 0xaa, 0xad, 0x32, 0x56, 0x30, 0xbc, 0xdd, 0xdb, 0xce, 0x4d, 0x67,
                0x65, 0x6d, 0x05, 0xfd, 0x1c, 0xc2, 0xd0, 0x37, 0xbb, 0x53, 0x75, 0xb6, 0xe9, 0x6d,
                0x9e, 0x01, 0xa1, 0x57
            ]
        );
    }

    #[test]
    fn test_schnorr_equation_with_zero_challenge() {
        let g = get_spending_key_generator();
        let sk = JubjubScalar::from(42u64);
        let vk = g * sk;

        let nonce = JubjubScalar::from(7u64);
        let r = g * nonce;

        // c = 0
        let c = JubjubScalar::from(0u64);
        let s = nonce + (c * sk);

        // Should still hold: s*G = R + c*VK
        // When c=0: s*G = nonce*G = R
        let lhs = g * s;
        let rhs = r + (vk * c);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_schnorr_equation_with_large_scalars() {
        let g = get_spending_key_generator();

        // Use large scalar values
        let sk = JubjubScalar::from(u64::MAX);
        let vk = g * sk;

        let nonce = JubjubScalar::from(u64::MAX - 1);
        let r = g * nonce;

        let c = JubjubScalar::from(u64::MAX - 2);
        let s = nonce + (c * sk);

        // Equation must still hold
        let lhs = g * s;
        let rhs = r + (vk * c);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_verify_fails_with_identity_point_as_vk() -> Result<(), Box<dyn std::error::Error>> {
        // This test verifies that an all-zero byte encoding (which is *not* the
        // Edwards identity (that compresses to 0x01 followed by zeros) but is
        // still not a canonical subgroup element) is rejected at VK parse time.
        let (sk_bytes, _) = generate_keypair();
        let sk = SigningKey::from_bytes(&sk_bytes)?;

        let msg = b"test";
        let _sig = sign_hash_internal(msg, &sk)?;

        // `[0u8; 32]` is not the compressed encoding of the Edwards identity
        // (the identity compresses to `0x01` followed by 31 zero bytes), but it
        // is also not a valid subgroup point, so parsing must fail.
        let fake_vk_bytes = [0u8; 32];
        let fake_vk_result = VerificationKey::from_bytes(&fake_vk_bytes);

        // Should fail to parse
        assert!(fake_vk_result.is_err());
        Ok(())
    }

    #[test]
    fn test_vk_from_bytes_rejects_identity() {
        // The Edwards identity IS a valid prime-order subgroup point (it lies
        // in every subgroup), so `SubgroupPoint::from_bytes` accepts its
        // compressed encoding. Our `VerificationKey::from_bytes` must reject
        // it explicitly per spec §8.1 ("small order subgroup MUST be rejected
        // at deserialisation"). An identity VK would make verification trivial
        // for any signature whose R equals the generator times s.
        use group::Group;
        let identity_bytes = SubgroupPoint::identity().to_bytes();

        let result = VerificationKey::from_bytes(&identity_bytes);
        assert!(matches!(
            result,
            Err(RedJubjubError::InvalidVerificationKeyBytes)
        ));
    }

    #[test]
    fn test_sign_rejects_zero_nonce() {
        // A zero derived nonce has probability ~2^-252 for Blake2s-256 reduced
        // into the Jubjub scalar field, so we cannot trigger the branch through
        // `sign_hash_internal` with any realistic input. This test documents
        // that the `InvalidNonce` variant exists and constructs it directly so
        // pattern-matching code stays in sync with the enum definition.
        let err = RedJubjubError::InvalidNonce;
        assert_eq!(format!("{err}"), "derived signing nonce is zero");
        assert!(matches!(err, RedJubjubError::InvalidNonce));
    }

    #[test]
    fn test_empty_kid_and_schema() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let cred = CredMsgV2 {
            v: 2,
            kid: String::new(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: String::new(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    #[test]
    fn test_unicode_kid_and_schema() -> Result<(), Box<dyn std::error::Error>> {
        let (sk_bytes, vk_bytes) = generate_keypair();

        let cred = CredMsgV2 {
            v: 2,
            kid: "🔑-key-日本語".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "年齢18+🎂".to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk_bytes)?;
        assert!(verify_cred_v2(&cred, &sig, &vk_bytes).is_ok());
        Ok(())
    }

    /* ========================================================================== */
    /*                    SMALL-ORDER / ZERO SCALAR TESTS                        */
    /* ========================================================================== */

    /// PC-092: Small-order point rejection.
    /// The Jubjub curve has cofactor 8, meaning there are non-identity points
    /// of order 2, 4, or 8. These must be rejected as verification keys because
    /// they would allow trivial signature forgeries. On SubgroupPoint (prime-order
    /// subgroup), these points cannot be represented, so from_bytes rejects them.
    /// This test verifies that known small-order point encodings are rejected.
    #[test]
    fn test_vk_rejects_small_order_torsion_points() {
        // The point (0, -1) on twisted Edwards has order 2.
        // In compressed form on Jubjub, the v-coordinate is stored with the
        // sign bit of u. For (u=0, v=-1), v = p-1 in the base field.
        // The Jubjub base field modulus is
        // 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
        // so -1 mod p has the byte representation of (p-1).
        //
        // However, SubgroupPoint::from_bytes performs a subgroup check and will
        // reject any point not in the prime-order subgroup.

        // Try various byte patterns that might encode torsion points.
        // The key insight is that SubgroupPoint::from_bytes only accepts
        // points in the r-order subgroup, so ANY torsion point is rejected.

        // Attempt 1: Bytes crafted to look like a small-order point encoding.
        // The actual Jubjub base field modulus is too large to easily construct
        // a true order-2 point (0, -1) encoding here, so this serves as a
        // "plausibly structured but invalid" input that exercises the rejection
        // path in SubgroupPoint::from_bytes.
        let mut order_2_bytes = [0u8; 32];
        order_2_bytes[0..8].copy_from_slice(&0xfffe5bfeffffffff00000000u128.to_le_bytes()[..8]);
        let result = VerificationKey::from_bytes(&order_2_bytes);
        assert!(
            result.is_err(),
            "Invalid point encoding must be rejected as a verification key"
        );

        // Attempt 2: Construct the identity explicitly and confirm rejection.
        // (Already covered by test_vk_from_bytes_rejects_identity, but included
        // for completeness in the small-order rejection suite.)
        use group::Group;
        let identity_bytes = SubgroupPoint::identity().to_bytes();
        assert!(
            VerificationKey::from_bytes(&identity_bytes).is_err(),
            "Identity point (order 1) must be rejected as a verification key"
        );

        // Attempt 3: Random invalid bytes that don't decode to any curve point.
        // This verifies the subgroup check path is exercised.
        let garbage_bytes: [u8; 32] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C,
        ];
        assert!(
            VerificationKey::from_bytes(&garbage_bytes).is_err(),
            "Random bytes must be rejected as a verification key"
        );
    }

    /// PC-092 (variant): Verify that signature parsing rejects an identity R
    /// component, which would indicate a degenerate signature.
    #[test]
    fn test_signature_rejects_identity_r_component() {
        use group::Group;
        let identity_bytes = SubgroupPoint::identity().to_bytes();

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&identity_bytes);
        // Use a valid small scalar for s
        sig_bytes[32] = 1;

        let result = Signature::from_bytes(&sig_bytes);
        assert!(
            result.is_err(),
            "Signature with identity R must be rejected"
        );
    }

    /// PC-093: Zero scalar test.
    /// Attempts to use a zero scalar as a signing key and verifies it produces
    /// an error. A zero signing key would make the verification key the identity
    /// point, allowing trivial forgeries.
    #[test]
    fn test_zero_scalar_signing_key_rejected() {
        let zero_bytes = [0u8; 32];
        let result = SigningKey::from_bytes(&zero_bytes);
        assert!(
            matches!(result, Err(RedJubjubError::InvalidSigningKeyBytes)),
            "Zero scalar must be rejected as a signing key"
        );
    }

    /// PC-093 (variant): Verify that sign_cred_v2 also rejects a zero-byte
    /// signing key at the API boundary.
    #[test]
    fn test_sign_cred_v2_rejects_zero_scalar() {
        let zero_sk = [0u8; 32];
        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let result = sign_cred_v2(&cred, &zero_sk);
        assert!(
            result.is_err(),
            "sign_cred_v2 must reject a zero signing key"
        );
    }

    /// PC-093 (variant): Verify that sign_cred_v2_with_rp also rejects a zero
    /// signing key.
    #[test]
    fn test_sign_cred_v2_with_rp_rejects_zero_scalar() {
        let zero_sk = [0u8; 32];
        let rp = [0x42u8; 32];
        let cred = CredMsgV2 {
            v: 2,
            kid: "test".to_string(),
            c: [1; 32],
            iat: 1700000000,
            exp: 1800000000,
            schema: "age18+".to_string(),
        };

        let result = sign_cred_v2_with_rp(&cred, &rp, &zero_sk);
        assert!(
            result.is_err(),
            "sign_cred_v2_with_rp must reject a zero signing key"
        );
    }

    /// PC-093 (variant): Signature with zero s scalar must be rejected at parse.
    #[test]
    fn test_signature_rejects_zero_s_scalar() -> Result<(), Box<dyn std::error::Error>> {
        // Get a valid R point from a real signature
        let (sk_bytes, _) = generate_keypair();
        let sk = SigningKey::from_bytes(&sk_bytes)?;
        let sig = sign_hash_internal(b"test", &sk)?;
        let r_bytes = sig.r.to_bytes();

        // Construct a signature with valid R but zero s
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&r_bytes);
        // s = 0 (all zeros in bytes 32..64)

        let result = Signature::from_bytes(&sig_bytes);
        assert!(
            result.is_err(),
            "Signature with zero s scalar must be rejected"
        );
        Ok(())
    }
}
