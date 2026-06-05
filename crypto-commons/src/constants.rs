//! Constants used across the Provii crypto system.

// Domain separation tags.

/// Credential v2 prehash domain separation tag, prefixed to the credential
/// fields before Blake2s hashing in `cred_v2_prehash_bytes`.
pub const CRED_DST: &[u8] = b"provii.cred.v0";

/// Challenge domain separation tag, appended to `origin || nonce` in
/// `crypto-protocol::rp_challenge` before SHA-256 hashing.
pub const CHALLENGE_DST: &[u8] = b"provii.challenge.v0";
/// Nullifier domain separation tag for Pedersen-based nullifier computation.
///
/// Used in both the in-circuit nullifier gadget (`crypto-circuit-age/gadgets/pedersen.rs`)
/// and the off-circuit host implementation (`crypto-commit`).
pub const NULLIFIER_DST: &[u8] = b"provii.nullifier.pedersen.v0";

/// Challenge signature DST, used in `crypto-protocol/challenge.rs` for
/// hashing the challenge message before signature verification.
pub const CHALLENGE_SIG_DST: &[u8] = b"PROVII_CHALLENGE_V0";

/// Challenge ID DST, used in `crypto-protocol/challenge.rs` for deriving
/// the deterministic challenge identifier from origin + nonce.
pub const CHALLENGE_ID_DST: &[u8] = b"challenge_id_v0";

/// RedJubjub personalisation tag, used in both the off-circuit
/// `crypto-sig-redjubjub` signer/verifier and the in-circuit
/// Blake2s gadget in `crypto-circuit-age/gadgets/redjubjub.rs`.
pub const REDJUBJUB_PERSONALIZATION: &[u8; 8] = b"ProviiRJ";

/// RedJubjub nonce derivation tag, used in the deterministic nonce
/// derivation inside `crypto-sig-redjubjub`.
pub const REDJUBJUB_NONCE_TAG: &[u8] = b"ProviiRJ/nonce";

/// Issuance consent domain separator for the wallet consent message
/// hash in `crypto-protocol`.
pub const ISSUANCE_CONSENT_DST: &[u8] = b"provii:issuance-consent:v0";

// Serialization size limits.
pub const CREDENTIAL_ID_SIZE: usize = 32;
pub const MAX_CREDENTIAL_SIZE: usize = 8192;
pub const MAX_RANGE_PROOF_SIZE: usize = 1024;
pub const MAX_CREDENTIAL_SIGNATURE_SIZE: usize = 512;
pub const MAX_WALLET_SIGNATURE_SIZE: usize = 128;
pub const NONCE_SIZE: usize = 32;

// Time constants.
pub const CHALLENGE_EXPIRY_SECONDS: u64 = 300; // Challenge validity window (5 minutes).
pub const CLOCK_SKEW_TOLERANCE_SECONDS: u64 = 30;
/// Upper-bound clock-skew tolerance when an Ed25519 attestation timestamp is ahead
/// of the verifying server's wall clock. Wider than `CLOCK_SKEW_TOLERANCE_SECONDS`
/// because attestation timestamps cross a trust boundary (IdP clock vs Issuance
/// Server clock). Consumed by `Attestation::verify_with_timestamp`.
pub const ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS: u64 = 60;
pub const SESSION_TIMEOUT_MS: u64 = 120_000; // Session timeout (2 minutes).

// Sign-magnitude bias for mapping signed i32 day counts to unsigned u32 values
// while preserving ordering for the ZK circuit's unsigned comparison gadget.
pub const SIGN_BIAS: u32 = 0x8000_0000;

/// Map a signed day count to an unsigned biased value for circuit input.
///
/// XORing with `SIGN_BIAS` flips the sign bit, mapping signed ordering to
/// unsigned ordering: `bias(-3652) < bias(0) < bias(13880)` when compared
/// as `u32`.
///
/// Uses byte-level reinterpretation rather than `as` casts to make the
/// intent explicit and satisfy clippy sign-loss / wrap checks.
#[inline]
pub fn bias_for_circuit(days: i32) -> u32 {
    // SAFETY: finite field arithmetic, intentional bitwise reinterpretation
    u32::from_ne_bytes(days.to_ne_bytes()) ^ SIGN_BIAS
}

/// Reverse the bias applied by `bias_for_circuit`.
#[inline]
pub fn unbias_from_circuit(biased: u32) -> i32 {
    // SAFETY: finite field arithmetic, intentional bitwise reinterpretation
    i32::from_ne_bytes((biased ^ SIGN_BIAS).to_ne_bytes())
}
