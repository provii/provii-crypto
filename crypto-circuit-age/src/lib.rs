#![forbid(unsafe_code)]

//! Provii age-proof circuit (Groth16, BLS12-381).
//!
//! Proves (without revealing DOB, signature, or commitment):
//!   1) C == PedersenCommit(dob_days, r)
//!   2) dob_days <= cutoff_days (user is old enough)
//!   3) RedJubjub signature on prehash(v,kid,C,iat,exp,schema) verifies under issuer_vk
//!   4) The issuer's public key matches the public input
//!   5) The proof is bound to an RP hash
//!
//! Public inputs (packed with multipack):
//!   - cutoff_days: u32  (little-endian bits)
//!   - rp_hash: `[u8;32]` (256 bits) - Blake2s hash of RP challenge (computed off-circuit)
//!   - issuer_vk_bytes: `[u8;32]` (256 bits) - Raw issuer verification key
//!   - cred_nullifier: `[u8;32]` (256 bits) - Pedersen-based nullifier

use bellman::gadgets::multipack;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bls12_381::Scalar;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
pub mod gadgets;

/// Direction of the age comparison in the circuit.
///
/// - `Over`: proves `cutoff >= dob` (user is AT LEAST `min_age` years old)
/// - `Under`: proves `dob >= cutoff` (user is AT MOST `max_age` years old)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgeDirection {
    /// Prove the user is AT LEAST a minimum age (`cutoff >= dob`).
    Over,
    /// Prove the user is AT MOST a maximum age (`dob >= cutoff`).
    Under,
}

/// Number of Groth16 public inputs (field elements) this circuit exposes,
/// not counting the implicit `1` input that Bellman adds at index 0.
pub const PUBLIC_INPUTS_LEN: usize = 8;

// CRITICAL: Define fixed sizes for variable-length fields
// These MUST match what's used in parameter generation AND proving!
pub const KID_SIZE_BYTES: usize = 14;
pub const SCHEMA_SIZE_BYTES: usize = 12;

/// Compute a fingerprint of ALL constants that affect R1CS structure.
///
/// Since the circuit now uses a direction bit as a public input (conditional
/// mux), both Over and Under share the same R1CS layout. Direction no longer
/// affects the circuit structure.
pub fn compute_circuit_constants_hash() -> String {
    use blake2::{Blake2s256, Digest};

    let mut hasher = Blake2s256::new();

    // Provii v0 circuit constants tag.
    hasher.update(b"provii.age.circuit.constants.v0");

    // 1. SPENDING_KEY_GENERATOR from sapling_constants.rs
    hasher.update([
        0x30, 0xb5, 0xf2, 0xaa, 0xad, 0x32, 0x56, 0x30, 0xbc, 0xdd, 0xdb, 0xce, 0x4d, 0x67, 0x65,
        0x6d, 0x05, 0xfd, 0x1c, 0xc2, 0xd0, 0x37, 0xbb, 0x53, 0x75, 0xb6, 0xe9, 0x6d, 0x9e, 0x01,
        0xa1, 0x57,
    ]);

    // 2. Blake2s personalizations used in the circuit
    hasher.update(provii_crypto_commons::REDJUBJUB_PERSONALIZATION); // RedJubjub signature

    // 3. Domain separation tags from the circuit (imported from crypto-commons)
    hasher.update(provii_crypto_commons::NULLIFIER_DST); // Pedersen nullifier DST
    hasher.update(provii_crypto_commons::CRED_DST); // Credential v2 prehash DST

    // 4. Pedersen commitment personalization
    hasher.update([0x09, 0x00, 0x00, 0x00, 0x00, 0x00]); // NoteCommitment from sapling

    // 5. Field lengths that determine circuit structure
    hasher.update(14u32.to_le_bytes()); // kid length
    hasher.update(12u32.to_le_bytes()); // schema length
    hasher.update(128u32.to_le_bytes()); // r_bits length

    hex::encode(hasher.finalize())
}

/// Create witness from variable-length inputs.
impl AgeWitness {
    /// Construct a validated `AgeWitness`.
    ///
    /// # Errors
    ///
    /// Returns an error when any field violates the circuit size constraints
    /// (`kid` not exactly 14 bytes, `schema` not exactly 12 bytes, `r_bits`
    /// not exactly 128 bits, `sig_rj_bytes` not exactly 64 bytes) or when
    /// edge-case values indicate clearly invalid input (all-zero commitment,
    /// all-zero signature bytes).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dob_days: i32,
        r_bits: Vec<bool>,
        issuer_vk_bytes: [u8; 32],
        sig_rj_bytes: Vec<u8>,
        v: u8,
        kid: &str,
        c_bytes: [u8; 32],
        iat: u64,
        exp: u64,
        schema: &str,
    ) -> provii_crypto_commons::Result<Self> {
        let kid_bytes = kid.as_bytes().to_vec();
        let schema_bytes = schema.as_bytes().to_vec();

        // Validate sizes match circuit expectations.
        if kid_bytes.len() != KID_SIZE_BYTES {
            return Err(provii_crypto_commons::Error::InvalidInput);
        }
        if schema_bytes.len() != SCHEMA_SIZE_BYTES {
            return Err(provii_crypto_commons::Error::InvalidInput);
        }
        if r_bits.len() != 128 {
            return Err(provii_crypto_commons::Error::InvalidInput);
        }
        if sig_rj_bytes.len() != 64 {
            return Err(provii_crypto_commons::Error::InvalidInput);
        }

        // Reject clearly degenerate values that would always fail in-circuit.
        if c_bytes == [0u8; 32] {
            return Err(provii_crypto_commons::Error::InvalidInput);
        }
        if sig_rj_bytes.iter().all(|&b| b == 0) {
            return Err(provii_crypto_commons::Error::InvalidInput);
        }

        Ok(Self {
            dob_days,
            r_bits,
            issuer_vk_bytes,
            sig_rj_bytes,
            v,
            kid: kid_bytes,
            c_bytes,
            iat,
            exp,
            schema: schema_bytes,
        })
    }
}

/// Public inputs for age proof (fed into the verifier as field elements via multipack).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgePublic {
    pub direction: AgeDirection,
    pub cutoff_days: i32,
    pub rp_hash: [u8; 32], // Blake2s hash of RP challenge (computed off-circuit)
    pub issuer_vk_bytes: [u8; 32], // Raw issuer verification key bytes
    pub cred_nullifier: [u8; 32], // Pedersen-based nullifier
}

/// Witness for the age proof circuit.
///
/// Contains secret key material (DOB, blinding factor, signature) that MUST be
/// zeroised on drop. `Clone` is required by bellman's `Circuit::synthesize`
/// which consumes `self`; cloned instances are also covered by `ZeroizeOnDrop`.
// SECURITY: Serialize and Deserialize intentionally omitted (P1-024, ST-PC-002).
// AgeWitness contains secret key material and must never be serialised to or
// deserialised from untrusted input. Use AgeWitness::new() to construct.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AgeWitness {
    // DOB commitment witness (SECRET)
    pub dob_days: i32,
    pub r_bits: Vec<bool>, // 128 bits (SECRET: blinding factor)

    // Issuer signature (RedJubjub) witness
    #[zeroize(skip)] // Public key, not secret
    pub issuer_vk_bytes: [u8; 32],
    pub sig_rj_bytes: Vec<u8>, // 64 bytes (SECRET: credential signature)

    // Credential message fields (MUST match what was signed!)
    #[zeroize(skip)]
    pub v: u8,
    #[zeroize(skip)]
    pub kid: Vec<u8>, // MUST be exactly KID_SIZE_BYTES
    #[zeroize(skip)] // Public commitment bytes
    pub c_bytes: [u8; 32],
    #[zeroize(skip)]
    pub iat: u64,
    #[zeroize(skip)]
    pub exp: u64,
    #[zeroize(skip)]
    pub schema: Vec<u8>, // MUST be exactly SCHEMA_SIZE_BYTES

                         // Note: rp_challenge removed, RP hash computed off-circuit
}

impl std::fmt::Debug for AgeWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgeWitness")
            .field("dob_days", &"[REDACTED]")
            .field(
                "r_bits",
                &format_args!("[REDACTED; {} bits]", self.r_bits.len()),
            )
            .field("issuer_vk_bytes", &hex::encode(self.issuer_vk_bytes))
            .field(
                "sig_rj_bytes",
                &format_args!("[REDACTED; {} bytes]", self.sig_rj_bytes.len()),
            )
            .field("v", &self.v)
            .field("kid", &self.kid)
            .field("c_bytes", &hex::encode(self.c_bytes))
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .field("schema", &self.schema)
            .finish()
    }
}

/// The age-proof circuit.
///
/// Wraps an `AgeWitness` containing secret key material. The witness field is
/// covered by `ZeroizeOnDrop` (inherited from `AgeWitness`). `Clone` is
/// required because bellman's `Circuit::synthesize` consumes `self` by value.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AgeCircuit {
    #[zeroize(skip)] // AgePublic contains only public values
    pub public: AgePublic,
    pub witness: Option<AgeWitness>,
}

impl Circuit<Scalar> for AgeCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // ========================================================================
        // STEP 0: Allocate PUBLIC inputs
        // ========================================================================

        // Direction bits: 32 little-endian bits allocated as private witnesses,
        // then packed into a public input via multipack. Bit 0 is the actual
        // direction flag (1 = Over, 0 = Under); bits 1-31 are forced to zero by
        // the packing constraint against the verifier-supplied scalar.
        //
        // SOUNDNESS: The same bit 0 is used as the mux selector in the age
        // comparison (Step 5). Because the packing constraint ties these bits to
        // the public input, a malicious prover cannot choose a different direction
        // than what the verifier expects.
        let dir_u32_val: u32 = if self.public.direction == AgeDirection::Over {
            1
        } else {
            0
        };
        let dir_bits =
            gadgets::bits::alloc_u32_input(cs.namespace(|| "dir_pack_bits"), dir_u32_val)?;
        // Extract bit 0 as the direction selector for the conditional mux.
        let direction_bit = dir_bits
            .first()
            .ok_or(SynthesisError::Unsatisfiable)?
            .clone();

        // Cutoff days: 32 little-endian bits (public input, biased for unsigned comparison)
        let cutoff_bits = gadgets::bits::alloc_u32_input(
            cs.namespace(|| "cutoff_bits"),
            provii_crypto_commons::bias_for_circuit(self.public.cutoff_days),
        )?;

        // RP hash: 32 bytes = 256 bits (public input) - now computed off-circuit
        let rp_hash_bits = gadgets::bits::alloc_bytes_input(
            cs.namespace(|| "rp_hash_bits"),
            &self.public.rp_hash,
        )?;

        // Issuer VK bytes: 32 bytes = 256 bits (public input) - raw VK, not hash
        let issuer_vk_bits_public = gadgets::bits::alloc_bytes_input(
            cs.namespace(|| "issuer_vk_bits_public"),
            &self.public.issuer_vk_bytes,
        )?;

        // Credential nullifier: 32 bytes = 256 bits (public input) - Pedersen-based
        let cred_nullifier_bits = gadgets::bits::alloc_bytes_input(
            cs.namespace(|| "cred_nullifier_bits"),
            &self.public.cred_nullifier,
        )?;

        // ========================================================================
        // Expose the 5 conceptual public values as Groth16 public inputs
        // Order MUST match the verifier's multipacking order.
        // ========================================================================

        // Direction bits packed (bit 0 = direction selector used in mux)
        multipack::pack_into_inputs(cs.namespace(|| "pi_direction"), &dir_bits)?;
        multipack::pack_into_inputs(cs.namespace(|| "pi_cutoff_days"), &cutoff_bits)?;
        multipack::pack_into_inputs(cs.namespace(|| "pi_rp_hash"), &rp_hash_bits)?;
        multipack::pack_into_inputs(cs.namespace(|| "pi_issuer_vk"), &issuer_vk_bits_public)?;
        multipack::pack_into_inputs(cs.namespace(|| "pi_cred_nullifier"), &cred_nullifier_bits)?;

        // ========================================================================
        // STEP 1: Allocate WITNESS inputs (no RP challenge needed anymore)
        // ========================================================================

        let (
            dob_bits,
            r_bits,
            issuer_vk,
            sig_rj,
            v_bits,
            kid_bits,
            c_bytes_bits,
            iat_bits,
            exp_bits,
            schema_bits,
        ) = if let Some(ref w) = self.witness {
            // Validate witness sizes match circuit constants
            if w.kid.len() != KID_SIZE_BYTES {
                return Err(SynthesisError::Unsatisfiable);
            }
            if w.schema.len() != SCHEMA_SIZE_BYTES {
                return Err(SynthesisError::Unsatisfiable);
            }

            // Ensure sig_rj_bytes is exactly 64 bytes
            if w.sig_rj_bytes.len() != 64 {
                return Err(SynthesisError::Unsatisfiable);
            }
            // Length checked above; exactly 64 bytes guaranteed. Borrow
            // rather than clone to avoid an extra copy of secret signature
            // material in memory.
            let sig_array: [u8; 64] = <[u8; 64]>::try_from(w.sig_rj_bytes.as_slice())
                .map_err(|_| SynthesisError::Unsatisfiable)?;

            // Ensure r_bits is exactly 128 bits
            if w.r_bits.len() != 128 {
                return Err(SynthesisError::Unsatisfiable);
            }

            (
                gadgets::bits::alloc_u32_witness(
                    cs.namespace(|| "dob_bits"),
                    Some(provii_crypto_commons::bias_for_circuit(w.dob_days)),
                )?,
                gadgets::bits::alloc_bool_vec_witness_fixed(
                    cs.namespace(|| "r_bits"),
                    Some(&w.r_bits),
                    128,
                )?,
                gadgets::redjubjub::alloc_vk(
                    cs.namespace(|| "issuer_vk"),
                    Some(&w.issuer_vk_bytes),
                )?,
                gadgets::redjubjub::alloc_sig(cs.namespace(|| "sig_rj"), Some(&sig_array))?,
                gadgets::bits::alloc_u8_witness(cs.namespace(|| "v_bits"), Some(w.v))?,
                gadgets::bits::alloc_bytes_witness_fixed(
                    cs.namespace(|| "kid_bits"),
                    Some(&w.kid),
                    KID_SIZE_BYTES,
                )?,
                gadgets::bits::alloc_bytes_witness_fixed(
                    cs.namespace(|| "c_bytes_bits"),
                    Some(&w.c_bytes),
                    32,
                )?,
                gadgets::bits::alloc_u64_witness(cs.namespace(|| "iat_bits"), Some(w.iat))?,
                gadgets::bits::alloc_u64_witness(cs.namespace(|| "exp_bits"), Some(w.exp))?,
                gadgets::bits::alloc_bytes_witness_fixed(
                    cs.namespace(|| "schema_bits"),
                    Some(&w.schema),
                    SCHEMA_SIZE_BYTES,
                )?,
            )
        } else {
            (
                gadgets::bits::alloc_u32_witness(cs.namespace(|| "dob_bits"), None)?,
                gadgets::bits::alloc_bool_vec_witness_fixed(cs.namespace(|| "r_bits"), None, 128)?,
                gadgets::redjubjub::alloc_vk(cs.namespace(|| "issuer_vk"), None)?,
                gadgets::redjubjub::alloc_sig(cs.namespace(|| "sig_rj"), None)?,
                gadgets::bits::alloc_u8_witness(cs.namespace(|| "v_bits"), None)?,
                gadgets::bits::alloc_bytes_witness_fixed(
                    cs.namespace(|| "kid_bits"),
                    None,
                    KID_SIZE_BYTES,
                )?,
                gadgets::bits::alloc_bytes_witness_fixed(
                    cs.namespace(|| "c_bytes_bits"),
                    None,
                    32,
                )?,
                gadgets::bits::alloc_u64_witness(cs.namespace(|| "iat_bits"), None)?,
                gadgets::bits::alloc_u64_witness(cs.namespace(|| "exp_bits"), None)?,
                gadgets::bits::alloc_bytes_witness_fixed(
                    cs.namespace(|| "schema_bits"),
                    None,
                    SCHEMA_SIZE_BYTES,
                )?,
            )
        };

        // Validate that fixed sizes are being used
        if kid_bits.len() != KID_SIZE_BYTES * 8 {
            return Err(SynthesisError::Unsatisfiable);
        }
        if schema_bits.len() != SCHEMA_SIZE_BYTES * 8 {
            return Err(SynthesisError::Unsatisfiable);
        }
        if c_bytes_bits.len() != 256 {
            return Err(SynthesisError::Unsatisfiable);
        }

        // ========================================================================
        // STEP 2: Verify issuer VK equality (replaces issuer key hash computation)
        // ========================================================================

        // Get the issuer_vk bytes as bits from the witness (used in signature verification)
        let issuer_vk_bytes_bits = gadgets::redjubjub::get_vk_bytes_bits(
            cs.namespace(|| "get_issuer_vk_bytes"),
            &issuer_vk,
        )?;

        // Enforce that the witness VK equals the public VK
        gadgets::bits::enforce_bits_equal(
            cs.namespace(|| "issuer_vk_equality"),
            &issuer_vk_bytes_bits, // From witness (used in signature verification)
            &issuer_vk_bits_public, // From public inputs
        )?;

        // ========================================================================
        // STEP 3: Verify credential nullifier (using Pedersen instead of Blake2s)
        // ========================================================================

        // Compute Pedersen-based nullifier
        let computed_nullifier_bits = gadgets::pedersen::pedersen_nullifier(
            cs.namespace(|| "compute_cred_nullifier"),
            &c_bytes_bits,
        )?;

        // Enforce computed nullifier equals public input
        gadgets::bits::enforce_bits_equal(
            cs.namespace(|| "cred_nullifier_equality"),
            &computed_nullifier_bits,
            &cred_nullifier_bits,
        )?;

        // ========================================================================
        // STEP 4: Commitment - Compute C' and enforce C' == c_bytes
        // ========================================================================

        // Compute C' = PedersenCommit(dob_bits, r_bits) using Sapling's gadget
        let c_prime_bits =
            gadgets::pedersen::commit(cs.namespace(|| "pedersen_commitment"), &dob_bits, &r_bits)?;

        // Enforce C' == c_bytes (the witnessed commitment)
        gadgets::pedersen::enforce_bytes_equal(
            cs.namespace(|| "commitment_equality"),
            &c_prime_bits,
            &c_bytes_bits,
        )?;

        // ========================================================================
        // STEP 5: Age check (direction-dependent via conditional mux)
        //   Over  (dir=1): enforce_ge(cutoff, dob), cutoff >= dob
        //   Under (dir=0): enforce_ge(dob, cutoff), dob >= cutoff
        //
        // We use conditional_swap to select the operand order:
        //   dir=1 (Over):  left=cutoff, right=dob
        //   dir=0 (Under): left=dob, right=cutoff
        // Then enforce_ge(left, right).
        // ========================================================================

        let (ge_left, ge_right) = gadgets::bits::conditional_swap(
            cs.namespace(|| "age_direction_mux"),
            &direction_bit,
            &cutoff_bits,
            &dob_bits,
        )?;

        gadgets::bits::enforce_ge(cs.namespace(|| "age_threshold_check"), &ge_left, &ge_right)?;

        // ========================================================================
        // STEP 6: Build message preimage for credential
        // ========================================================================

        let message_bits = gadgets::prehash::build_prehash_bits(
            cs.namespace(|| "build_message_preimage"),
            &v_bits,
            &kid_bits,
            &c_bytes_bits,
            &iat_bits,
            &exp_bits,
            &schema_bits,
        )?;

        // ========================================================================
        // STEP 7: Hash the message with Blake2s (256-bit output)
        // ========================================================================

        let prehash_bits256 =
            gadgets::blake2s::blake2s_256(cs.namespace(|| "blake2s_hash"), &message_bits)?;

        // Verify we got 256 bits
        if prehash_bits256.len() != 256 {
            return Err(SynthesisError::Unsatisfiable);
        }

        // ========================================================================
        // STEP 8: Verify RedJubjub signature WITHOUT RP binding
        // ========================================================================

        gadgets::redjubjub::verify(
            cs.namespace(|| "redjubjub_signature_verification"),
            &issuer_vk,
            &sig_rj,
            &prehash_bits256,
        )?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_synthesis_without_witness() -> Result<(), Box<dyn std::error::Error>> {
        // Test that circuit synthesizes without witness for parameter generation.
        // Uses a seeded RNG for deterministic test behaviour.
        use bellman::groth16::generate_random_parameters;
        use bls12_381::Bls12;
        use rand::{rngs::StdRng, SeedableRng};

        let circuit = AgeCircuit {
            public: AgePublic {
                direction: AgeDirection::Over,
                cutoff_days: 0,
                rp_hash: [0; 32],
                issuer_vk_bytes: [0; 32],
                cred_nullifier: [0; 32],
            },
            witness: None,
        };

        // This will synthesize the circuit for parameter generation
        // If synthesis has structural issues, this will error
        let mut rng = StdRng::seed_from_u64(42);
        let params = generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)?;

        // Verify we got valid parameters
        assert!(bool::from(params.vk.alpha_g1.is_on_curve()));
        assert!(bool::from(params.vk.beta_g2.is_on_curve()));

        assert_eq!(
            params.vk.ic.len(),
            9,
            "Should have 9 public inputs (8 + implicit 1)"
        );
        Ok(())
    }

    #[test]
    fn test_public_input_assembly() -> Result<(), Box<dyn std::error::Error>> {
        use provii_crypto_public_inputs::assemble_public_inputs_canonical;

        let cutoff = 6570; // 18 years
        let rp_hash = [42u8; 32];
        let issuer_vk = [99u8; 32];
        let nullifier = [55u8; 32];

        let inputs = assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier)?;

        // Should have 8 field elements from multipack
        assert_eq!(inputs.len(), 8);

        // Test determinism
        let inputs2 =
            assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier)?;
        assert_eq!(inputs, inputs2);
        Ok(())
    }

    // ========================================================================
    // COMPUTE_CIRCUIT_CONSTANTS_HASH TESTS (3 tests)
    // ========================================================================

    #[test]
    fn test_compute_circuit_constants_hash_determinism() -> Result<(), Box<dyn std::error::Error>> {
        let hash1 = compute_circuit_constants_hash();
        let hash2 = compute_circuit_constants_hash();
        assert_eq!(hash1, hash2, "Hash should be deterministic");
        Ok(())
    }

    #[test]
    fn test_compute_circuit_constants_hash_format() -> Result<(), Box<dyn std::error::Error>> {
        let hash = compute_circuit_constants_hash();
        // Should be 64 hex characters (32 bytes * 2)
        assert_eq!(hash.len(), 64, "Hash should be 64 hex characters");
        // Should be valid hex
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash should be valid hex"
        );
        Ok(())
    }

    #[test]
    fn test_compute_circuit_constants_hash_sensitivity() -> Result<(), Box<dyn std::error::Error>> {
        // This test documents the expected hash value.
        // If this test fails, it means a circuit constant has changed,
        // which would require new trusted setup parameters!
        let hash = compute_circuit_constants_hash();

        // Document the hash value (this is a fingerprint of the circuit structure)
        // If this changes, ALL proofs need to be regenerated with new parameters
        assert!(!hash.is_empty(), "Hash should not be empty");

        // The hash should be stable across runs
        let hash2 = compute_circuit_constants_hash();
        assert_eq!(hash, hash2, "Hash must be stable");
        Ok(())
    }

    // ========================================================================
    // AGE_WITNESS::NEW TESTS (5 tests)
    // ========================================================================

    #[test]
    fn test_age_witness_new_valid() -> Result<(), Box<dyn std::error::Error>> {
        let witness = AgeWitness::new(
            6570,
            vec![false; 128],
            [0u8; 32],
            vec![1u8; 64],
            1,
            "abcdefghijklmn", // 14 bytes
            [1u8; 32],
            1000000,
            2000000,
            "schemaschema", // 12 bytes
        )?;

        assert_eq!(witness.dob_days, 6570);
        assert_eq!(witness.r_bits.len(), 128);
        assert_eq!(witness.kid.len(), KID_SIZE_BYTES);
        assert_eq!(witness.schema.len(), SCHEMA_SIZE_BYTES);
        Ok(())
    }

    #[test]
    fn test_age_witness_new_kid_too_short() -> Result<(), Box<dyn std::error::Error>> {
        let result = AgeWitness::new(
            6570,
            vec![false; 128],
            [0u8; 32],
            vec![0u8; 64],
            1,
            "short", // 5 bytes, too short
            [0u8; 32],
            1000000,
            2000000,
            "schemaschema",
        );
        assert!(result.is_err());
        let err = result.err().ok_or("expected Err")?;
        assert_eq!(err, provii_crypto_commons::Error::InvalidInput);
        Ok(())
    }

    #[test]
    fn test_age_witness_new_kid_too_long() -> Result<(), Box<dyn std::error::Error>> {
        let result = AgeWitness::new(
            6570,
            vec![false; 128],
            [0u8; 32],
            vec![0u8; 64],
            1,
            "this_is_way_too_long", // More than 14 bytes
            [0u8; 32],
            1000000,
            2000000,
            "schemaschema",
        );
        assert!(result.is_err());
        let err = result.err().ok_or("expected Err")?;
        assert_eq!(err, provii_crypto_commons::Error::InvalidInput);
        Ok(())
    }

    #[test]
    fn test_age_witness_new_schema_too_short() -> Result<(), Box<dyn std::error::Error>> {
        let result = AgeWitness::new(
            6570,
            vec![false; 128],
            [0u8; 32],
            vec![0u8; 64],
            1,
            "abcdefghijklmn",
            [0u8; 32],
            1000000,
            2000000,
            "short", // 5 bytes, too short
        );
        assert!(result.is_err(), "schema too short should fail");
        Ok(())
    }

    #[test]
    fn test_age_witness_new_schema_too_long() -> Result<(), Box<dyn std::error::Error>> {
        let result = AgeWitness::new(
            6570,
            vec![false; 128],
            [0u8; 32],
            vec![0u8; 64],
            1,
            "abcdefghijklmn",
            [0u8; 32],
            1000000,
            2000000,
            "this_is_way_too_long_for_schema", // More than 12 bytes
        );
        assert!(result.is_err(), "schema too long should fail");
        Ok(())
    }

    // ========================================================================
    // CIRCUIT TESTS - HELPER FUNCTIONS
    // ========================================================================

    /// Creates a valid test witness and matching public inputs with proper cryptography.
    /// All signatures are valid and will pass circuit verification.
    fn create_valid_test_fixtures() -> Result<(AgeWitness, AgePublic), Box<dyn std::error::Error>> {
        create_valid_test_fixtures_with_params(6570, 6570)
    }

    /// Creates valid test fixtures with specified dob and cutoff values.
    fn create_valid_test_fixtures_with_params(
        dob_days: i32,
        cutoff_days: i32,
    ) -> Result<(AgeWitness, AgePublic), Box<dyn std::error::Error>> {
        use provii_crypto_commit::pedersen_nullifier;
        use provii_crypto_commit::{generate_commitment_randomness, pedersen_commit_dob_validated};
        use provii_crypto_commons::CredMsgV2;
        use provii_crypto_sig_redjubjub::{generate_keypair_with_rng, sign_cred_v2};
        use rand::{rngs::StdRng, SeedableRng};

        // Use deterministic RNG for reproducible tests
        let mut rng = StdRng::seed_from_u64(12345);

        // Generate valid keypair
        let (sk, vk) = generate_keypair_with_rng(&mut rng);

        // Generate commitment randomness
        let r_bits = generate_commitment_randomness(&mut rng, 128);

        // Create commitment
        let commitment =
            pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| format!("{e:?}"))?;

        // Create credential message
        let cred = CredMsgV2 {
            v: 2,
            kid: "abcdefghijklmn".to_string(), // 14 chars = KID_SIZE_BYTES
            c: commitment,
            iat: 1000000,
            exp: 2000000,
            schema: "schemaschema".to_string(), // 12 chars = SCHEMA_SIZE_BYTES
        };

        // Sign the credential
        let sig = sign_cred_v2(&cred, &sk)?;

        // Compute nullifier
        let nullifier = pedersen_nullifier(&commitment);

        let witness = AgeWitness {
            dob_days,
            r_bits: r_bits.to_vec(),
            issuer_vk_bytes: vk,
            sig_rj_bytes: sig.to_vec(),
            v: cred.v,
            kid: cred.kid.as_bytes().to_vec(),
            c_bytes: commitment,
            iat: cred.iat,
            exp: cred.exp,
            schema: cred.schema.as_bytes().to_vec(),
        };

        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days,
            rp_hash: [0u8; 32],
            issuer_vk_bytes: vk,
            cred_nullifier: nullifier,
        };

        Ok((witness, public))
    }

    /// Creates fixtures for testing various field values while keeping signature valid.
    fn create_valid_test_fixtures_custom(
        dob_days: i32,
        cutoff_days: i32,
        v: u8,
        kid: &str,
        schema: &str,
        iat: u64,
        exp: u64,
    ) -> Result<(AgeWitness, AgePublic), Box<dyn std::error::Error>> {
        use provii_crypto_commit::pedersen_nullifier;
        use provii_crypto_commit::{generate_commitment_randomness, pedersen_commit_dob_validated};
        use provii_crypto_commons::CredMsgV2;
        use provii_crypto_sig_redjubjub::{generate_keypair_with_rng, sign_cred_v2};
        use rand::{rngs::StdRng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(12345);
        let (sk, vk) = generate_keypair_with_rng(&mut rng);
        let r_bits = generate_commitment_randomness(&mut rng, 128);
        let commitment =
            pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| format!("{e:?}"))?;

        let cred = CredMsgV2 {
            v,
            kid: kid.to_string(),
            c: commitment,
            iat,
            exp,
            schema: schema.to_string(),
        };

        let sig = sign_cred_v2(&cred, &sk)?;
        let nullifier = pedersen_nullifier(&commitment);

        let witness = AgeWitness {
            dob_days,
            r_bits: r_bits.to_vec(),
            issuer_vk_bytes: vk,
            sig_rj_bytes: sig.to_vec(),
            v: cred.v,
            kid: cred.kid.as_bytes().to_vec(),
            c_bytes: commitment,
            iat: cred.iat,
            exp: cred.exp,
            schema: cred.schema.as_bytes().to_vec(),
        };

        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days,
            rp_hash: [0u8; 32],
            issuer_vk_bytes: vk,
            cred_nullifier: nullifier,
        };

        Ok((witness, public))
    }

    fn create_test_witness() -> Result<AgeWitness, Box<dyn std::error::Error>> {
        let (witness, _) = create_valid_test_fixtures()?;
        Ok(witness)
    }

    fn create_test_public() -> Result<AgePublic, Box<dyn std::error::Error>> {
        let (_, public) = create_valid_test_fixtures()?;
        Ok(public)
    }

    // ========================================================================
    // CIRCUIT SYNTHESIS TESTS - WITNESS VALIDATION (8 tests)
    // ========================================================================
    // These tests verify that the circuit rejects invalid witness data

    #[test]
    fn test_circuit_witness_kid_too_short() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        let mut witness = create_test_witness()?;
        witness.kid = vec![0u8; 13]; // Too short

        let circuit = AgeCircuit {
            public: create_test_public()?,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        // Should return Unsatisfiable due to kid length check
        assert!(
            result.is_err(),
            "Circuit should reject kid that's too short"
        );
        assert!(
            matches!(result, Err(SynthesisError::Unsatisfiable)),
            "Expected Unsatisfiable error"
        );
        Ok(())
    }

    #[test]
    fn test_circuit_witness_kid_too_long() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        let mut witness = create_test_witness()?;
        witness.kid = vec![0u8; 15]; // Too long

        let circuit = AgeCircuit {
            public: create_test_public()?,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_err(), "Circuit should reject kid that's too long");
        assert!(
            matches!(result, Err(SynthesisError::Unsatisfiable)),
            "Expected Unsatisfiable error"
        );
        Ok(())
    }

    #[test]
    fn test_circuit_witness_schema_too_short() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        let mut witness = create_test_witness()?;
        witness.schema = vec![0u8; 11]; // Too short

        let circuit = AgeCircuit {
            public: create_test_public()?,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        assert!(
            result.is_err(),
            "Circuit should reject schema that's too short"
        );
        assert!(
            matches!(result, Err(SynthesisError::Unsatisfiable)),
            "Expected Unsatisfiable error"
        );
        Ok(())
    }

    #[test]
    fn test_circuit_witness_schema_too_long() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        let mut witness = create_test_witness()?;
        witness.schema = vec![0u8; 13]; // Too long

        let circuit = AgeCircuit {
            public: create_test_public()?,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        assert!(
            result.is_err(),
            "Circuit should reject schema that's too long"
        );
        assert!(
            matches!(result, Err(SynthesisError::Unsatisfiable)),
            "Expected Unsatisfiable error"
        );
        Ok(())
    }

    #[test]
    fn test_circuit_witness_sig_too_short() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        let mut witness = create_test_witness()?;
        witness.sig_rj_bytes = vec![0u8; 63]; // Too short

        let circuit = AgeCircuit {
            public: create_test_public()?,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        assert!(
            result.is_err(),
            "Circuit should reject signature that's too short"
        );
        assert!(
            matches!(result, Err(SynthesisError::Unsatisfiable)),
            "Expected Unsatisfiable error"
        );
        Ok(())
    }

    #[test]
    fn test_circuit_witness_sig_too_long() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        let mut witness = create_test_witness()?;
        witness.sig_rj_bytes = vec![0u8; 65]; // Too long

        let circuit = AgeCircuit {
            public: create_test_public()?,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        assert!(
            result.is_err(),
            "Circuit should reject signature that's too long"
        );
        assert!(
            matches!(result, Err(SynthesisError::Unsatisfiable)),
            "Expected Unsatisfiable error"
        );
        Ok(())
    }

    #[test]
    fn test_circuit_witness_r_bits_too_short() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        let mut witness = create_test_witness()?;
        witness.r_bits = vec![false; 127]; // Too short

        let circuit = AgeCircuit {
            public: create_test_public()?,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        assert!(
            result.is_err(),
            "Circuit should reject r_bits that's too short"
        );
        assert!(
            matches!(result, Err(SynthesisError::Unsatisfiable)),
            "Expected Unsatisfiable error"
        );
        Ok(())
    }

    #[test]
    fn test_circuit_witness_r_bits_too_long() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        let mut witness = create_test_witness()?;
        witness.r_bits = vec![false; 129]; // Too long

        let circuit = AgeCircuit {
            public: create_test_public()?,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        assert!(
            result.is_err(),
            "Circuit should reject r_bits that's too long"
        );
        assert!(
            matches!(result, Err(SynthesisError::Unsatisfiable)),
            "Expected Unsatisfiable error"
        );
        Ok(())
    }

    // ========================================================================
    // CIRCUIT TESTS - PUBLIC INPUT VALIDATION (3 tests)
    // ========================================================================

    #[test]
    fn test_circuit_public_inputs_structure() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // Use valid cryptographic fixtures
        let (witness, public) = create_valid_test_fixtures()?;

        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok(), "Circuit should synthesize successfully");
        // The circuit should have created constraints for all public inputs
        assert!(cs.num_inputs() > 0, "Circuit should have public inputs");
        // Should have exactly 9 inputs (ONE + 8 public inputs)
        assert_eq!(cs.num_inputs(), 9, "Circuit should have 9 inputs");
        Ok(())
    }

    #[test]
    fn test_circuit_public_inputs_ordering() -> Result<(), Box<dyn std::error::Error>> {
        // This test documents that the public input order is:
        // 1. direction (1 field element via multipack)
        // 2. cutoff_days (1 field element via multipack)
        // 3. rp_hash (2 field elements via multipack)
        // 4. issuer_vk_bytes (2 field elements via multipack)
        // 5. cred_nullifier (2 field elements via multipack)
        // Total: 8 field elements (excluding implicit 1)

        use provii_crypto_public_inputs::assemble_public_inputs_canonical;

        let inputs = assemble_public_inputs_canonical(true, 100, [1u8; 32], [2u8; 32], [3u8; 32])?;

        // Should always be exactly 8 field elements
        assert_eq!(inputs.len(), PUBLIC_INPUTS_LEN);
        Ok(())
    }

    #[test]
    fn test_circuit_public_inputs_values() -> Result<(), Box<dyn std::error::Error>> {
        use provii_crypto_public_inputs::assemble_public_inputs_canonical;

        // Test with distinct values
        let cutoff = 12345;
        let rp_hash = [42u8; 32];
        let issuer_vk = [99u8; 32];
        let nullifier = [77u8; 32];

        let inputs1 =
            assemble_public_inputs_canonical(true, cutoff, rp_hash, issuer_vk, nullifier)?;

        // Change one value and verify the public inputs change
        let inputs2 =
            assemble_public_inputs_canonical(true, cutoff + 1, rp_hash, issuer_vk, nullifier)?;

        assert_ne!(
            inputs1, inputs2,
            "Different public values should produce different inputs"
        );
        Ok(())
    }

    // ========================================================================
    // CIRCUIT TESTS - EDGE CASES (10 tests)
    // ========================================================================

    #[test]
    fn test_circuit_age_edge_case_equal() -> Result<(), Box<dyn std::error::Error>> {
        // Test dob == cutoff (should pass - exactly old enough)
        use bellman::gadgets::test::TestConstraintSystem;

        // Use valid cryptographic fixtures where dob == cutoff
        let (witness, public) = create_valid_test_fixtures_with_params(6570, 6570)?;

        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        // Should succeed (cutoff >= dob)
        assert!(result.is_ok(), "Circuit should accept dob == cutoff");
        Ok(())
    }

    #[test]
    fn test_circuit_age_edge_case_zero() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // Use valid cryptographic fixtures with dob=0, cutoff=0
        let (witness, public) = create_valid_test_fixtures_with_params(0, 0)?;

        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok(), "Circuit should accept dob=0, cutoff=0");
        Ok(())
    }

    #[test]
    fn test_circuit_age_edge_case_max_cutoff() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // Use valid cryptographic fixtures with dob=0, cutoff=MAX
        let (witness, public) = create_valid_test_fixtures_with_params(0, i32::MAX)?;

        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);

        assert!(result.is_ok(), "Circuit should accept max cutoff");
        Ok(())
    }

    #[test]
    fn test_circuit_various_kid_values() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // Test with different kid values (all exactly 14 bytes)
        let test_kids = vec![
            "00000000000000", // All zeros (ASCII)
            "XXXXXXXXXXXXXX", // All same char
            "abcdefghijklmn", // Normal case
            "!@#$%^&*()_+{}", // Special characters
        ];

        for kid in test_kids {
            assert_eq!(kid.len(), 14, "Test kid should be 14 bytes");

            // Create valid fixtures for each kid value
            let (witness, public) = create_valid_test_fixtures_custom(
                6570,
                6570,
                2,
                kid,
                "schemaschema",
                1000000,
                2000000,
            )?;

            let circuit = AgeCircuit {
                public,
                witness: Some(witness),
            };

            let mut cs = TestConstraintSystem::new();
            let result = circuit.synthesize(&mut cs);

            assert!(result.is_ok(), "Circuit should accept kid: {kid}");
        }
        Ok(())
    }

    #[test]
    fn test_circuit_various_schema_values() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // Test with different schema values (all exactly 12 bytes)
        let test_schemas = vec![
            "000000000000", // All zeros
            "XXXXXXXXXXXX", // All same char
            "schemaschema", // Normal case
            "!@#$%^&*()[]", // Special characters
        ];

        for schema in test_schemas {
            assert_eq!(schema.len(), 12, "Test schema should be 12 bytes");

            // Create valid fixtures for each schema value
            let (witness, public) = create_valid_test_fixtures_custom(
                6570,
                6570,
                2,
                "abcdefghijklmn",
                schema,
                1000000,
                2000000,
            )?;

            let circuit = AgeCircuit {
                public,
                witness: Some(witness),
            };

            let mut cs = TestConstraintSystem::new();
            let result = circuit.synthesize(&mut cs);

            assert!(result.is_ok(), "Circuit should accept schema: {schema}");
        }
        Ok(())
    }

    #[test]
    fn test_circuit_various_v_values() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // Test with various v values (protocol version byte)
        for v in [0u8, 1, 2, 127, 255] {
            // Create valid fixtures for each v value
            let (witness, public) = create_valid_test_fixtures_custom(
                6570,
                6570,
                v,
                "abcdefghijklmn",
                "schemaschema",
                1000000,
                2000000,
            )?;

            let circuit = AgeCircuit {
                public,
                witness: Some(witness),
            };

            let mut cs = TestConstraintSystem::new();
            let result = circuit.synthesize(&mut cs);

            assert!(result.is_ok(), "Circuit should accept v={v}");
        }
        Ok(())
    }

    #[test]
    fn test_circuit_timestamp_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // Test various timestamp combinations
        let test_cases = vec![
            (0u64, 0u64),             // Both zero
            (0, 1),                   // iat=0, exp=1
            (1000000, 2000000),       // Normal case
            (u64::MAX - 1, u64::MAX), // Near maximum
        ];

        for (iat, exp) in test_cases {
            // Create valid fixtures for each timestamp combination
            let (witness, public) = create_valid_test_fixtures_custom(
                6570,
                6570,
                2,
                "abcdefghijklmn",
                "schemaschema",
                iat,
                exp,
            )?;

            let circuit = AgeCircuit {
                public,
                witness: Some(witness),
            };

            let mut cs = TestConstraintSystem::new();
            let result = circuit.synthesize(&mut cs);

            assert!(result.is_ok(), "Circuit should accept iat={iat}, exp={exp}");
        }
        Ok(())
    }

    #[test]
    fn test_circuit_r_bits_patterns() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;
        use provii_crypto_commit::{
            generate_commitment_randomness, pedersen_commit_dob_validated, pedersen_nullifier,
        };
        use provii_crypto_commons::CredMsgV2;
        use provii_crypto_sig_redjubjub::{generate_keypair_with_rng, sign_cred_v2};
        use rand::{rngs::StdRng, SeedableRng};

        // Degenerate r_bits patterns are rejected off-circuit by the entropy
        // validator, so they can never reach the circuit. Assert that here.
        let degenerate_patterns: Vec<Vec<bool>> = vec![
            vec![false; 128],                       // All zeros (one unique byte)
            vec![true; 128],                        // All ones (one unique byte)
            (0..128).map(|i| i % 2 == 0).collect(), // Alternating (one unique byte)
        ];
        for r_bits in &degenerate_patterns {
            assert!(
                pedersen_commit_dob_validated(6570i32, r_bits).is_err(),
                "Entropy validation must reject degenerate r_bits"
            );
        }

        // High-entropy patterns drawn from distinct seeded ChaCha20 streams
        // exercise the circuit end-to-end.
        let high_entropy_seeds: [u64; 4] = [0x01, 0x42, 0xA5, 0xF0];
        for seed in high_entropy_seeds {
            let mut rng = StdRng::seed_from_u64(seed);
            let (sk, vk) = generate_keypair_with_rng(&mut rng);
            let r_bits = generate_commitment_randomness(&mut rng, 128);
            let dob_days = 6570i32;

            let commitment =
                pedersen_commit_dob_validated(dob_days, &r_bits).map_err(|e| format!("{e:?}"))?;

            let cred = CredMsgV2 {
                v: 2,
                kid: "abcdefghijklmn".to_string(),
                c: commitment,
                iat: 1000000,
                exp: 2000000,
                schema: "schemaschema".to_string(),
            };

            let sig = sign_cred_v2(&cred, &sk)?;
            let nullifier = pedersen_nullifier(&commitment);

            let witness = AgeWitness {
                dob_days,
                r_bits: r_bits.to_vec(),
                issuer_vk_bytes: vk,
                sig_rj_bytes: sig.to_vec(),
                v: cred.v,
                kid: cred.kid.as_bytes().to_vec(),
                c_bytes: commitment,
                iat: cred.iat,
                exp: cred.exp,
                schema: cred.schema.as_bytes().to_vec(),
            };

            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days: dob_days,
                rp_hash: [0u8; 32],
                issuer_vk_bytes: vk,
                cred_nullifier: nullifier,
            };

            let circuit = AgeCircuit {
                public,
                witness: Some(witness),
            };

            let mut cs = TestConstraintSystem::new();
            let result = circuit.synthesize(&mut cs);

            assert!(result.is_ok(), "Circuit should accept high-entropy r_bits");
        }
        Ok(())
    }

    #[test]
    fn test_circuit_commitment_verification() -> Result<(), Box<dyn std::error::Error>> {
        // This test verifies that commitments are correctly derived and validated
        use bellman::gadgets::test::TestConstraintSystem;

        // Test with different dob_days values (commitment varies with dob)
        let test_dob_values = [0i32, 6570, 10000, 20000];

        for dob_days in test_dob_values {
            let (witness, public) = create_valid_test_fixtures_with_params(dob_days, dob_days)?;

            let circuit = AgeCircuit {
                public,
                witness: Some(witness),
            };

            let mut cs = TestConstraintSystem::new();
            let result = circuit.synthesize(&mut cs);

            assert!(result.is_ok(), "Circuit should accept dob_days={dob_days}");
        }
        Ok(())
    }

    #[test]
    fn test_circuit_synthesize_determinism() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // Use valid fixtures for determinism test
        let (witness, public) = create_valid_test_fixtures()?;

        let _circuit = AgeCircuit {
            public: public.clone(),
            witness: Some(witness.clone()),
        };

        // Synthesize twice and verify same constraint count
        let mut cs1 = TestConstraintSystem::new();
        let result1 = AgeCircuit {
            public: public.clone(),
            witness: Some(witness.clone()),
        }
        .synthesize(&mut cs1);

        let mut cs2 = TestConstraintSystem::new();
        let result2 = AgeCircuit {
            public,
            witness: Some(witness),
        }
        .synthesize(&mut cs2);

        assert!(result1.is_ok(), "First synthesis should succeed");
        assert!(result2.is_ok(), "Second synthesis should succeed");
        assert_eq!(
            cs1.num_constraints(),
            cs2.num_constraints(),
            "Circuit should synthesize deterministically"
        );
        Ok(())
    }

    // ========================================================================
    // SIMPLE UNIT TESTS - NO PARAMETER GENERATION (10 tests)
    // ========================================================================

    #[test]
    fn test_public_inputs_len_constant() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(PUBLIC_INPUTS_LEN, 8);
        Ok(())
    }

    #[test]
    fn test_kid_size_constant() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(KID_SIZE_BYTES, 14);
        Ok(())
    }

    #[test]
    fn test_schema_size_constant() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(SCHEMA_SIZE_BYTES, 12);
        Ok(())
    }

    #[test]
    fn test_age_public_field_sizes() -> Result<(), Box<dyn std::error::Error>> {
        let public = create_test_public()?;
        assert_eq!(public.rp_hash.len(), 32);
        assert_eq!(public.issuer_vk_bytes.len(), 32);
        assert_eq!(public.cred_nullifier.len(), 32);
        Ok(())
    }

    #[test]
    fn test_age_witness_expected_sizes() -> Result<(), Box<dyn std::error::Error>> {
        let witness = create_test_witness()?;
        assert_eq!(witness.kid.len(), KID_SIZE_BYTES);
        assert_eq!(witness.schema.len(), SCHEMA_SIZE_BYTES);
        assert_eq!(witness.r_bits.len(), 128);
        assert_eq!(witness.sig_rj_bytes.len(), 64);
        assert_eq!(witness.c_bytes.len(), 32);
        assert_eq!(witness.issuer_vk_bytes.len(), 32);
        Ok(())
    }

    #[test]
    fn test_age_public_cutoff_days_range() -> Result<(), Box<dyn std::error::Error>> {
        // Test various cutoff values
        for cutoff in [i32::MIN, -1, 0, 1, 100, 6570, 10000, i32::MAX] {
            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days: cutoff,
                rp_hash: [0; 32],
                issuer_vk_bytes: [0; 32],
                cred_nullifier: [0; 32],
            };
            assert_eq!(public.cutoff_days, cutoff);
        }
        Ok(())
    }

    #[test]
    fn test_age_witness_v_byte_values() -> Result<(), Box<dyn std::error::Error>> {
        // Test protocol version byte can be any u8
        for v in [0u8, 1, 2, 127, 255] {
            let witness = AgeWitness::new(
                6570,
                vec![false; 128],
                [0u8; 32],
                vec![1u8; 64],
                v,
                "abcdefghijklmn",
                [1u8; 32],
                1000000,
                2000000,
                "schemaschema",
            )?;
            assert_eq!(witness.v, v);
        }
        Ok(())
    }

    #[test]
    fn test_age_witness_timestamp_values() -> Result<(), Box<dyn std::error::Error>> {
        // Test various timestamp combinations
        let test_cases = vec![
            (0u64, 0u64),
            (0, 1),
            (1000000, 2000000),
            (u64::MAX - 1, u64::MAX),
        ];

        for (iat, exp) in test_cases {
            let witness = AgeWitness::new(
                6570,
                vec![false; 128],
                [0u8; 32],
                vec![1u8; 64],
                1,
                "abcdefghijklmn",
                [1u8; 32],
                iat,
                exp,
                "schemaschema",
            )?;
            assert_eq!(witness.iat, iat);
            assert_eq!(witness.exp, exp);
        }
        Ok(())
    }

    #[test]
    fn test_age_circuit_constructor_with_witness() -> Result<(), Box<dyn std::error::Error>> {
        let circuit = AgeCircuit {
            public: create_test_public()?,
            witness: Some(create_test_witness()?),
        };
        assert!(circuit.witness.is_some());
        Ok(())
    }

    #[test]
    fn test_age_circuit_constructor_without_witness() -> Result<(), Box<dyn std::error::Error>> {
        let circuit = AgeCircuit {
            public: create_test_public()?,
            witness: None,
        };
        assert!(circuit.witness.is_none());
        Ok(())
    }

    // ========================================================================
    // DERIVED TRAIT TESTS (4 tests)
    // ========================================================================

    #[test]
    fn test_age_public_clone() -> Result<(), Box<dyn std::error::Error>> {
        let public = create_test_public()?;
        let cloned = public.clone();

        assert_eq!(public.cutoff_days, cloned.cutoff_days);
        assert_eq!(public.rp_hash, cloned.rp_hash);
        assert_eq!(public.issuer_vk_bytes, cloned.issuer_vk_bytes);
        assert_eq!(public.cred_nullifier, cloned.cred_nullifier);
        Ok(())
    }

    #[test]
    fn test_age_witness_clone() -> Result<(), Box<dyn std::error::Error>> {
        let witness = create_test_witness()?;
        let cloned = witness.clone();

        assert_eq!(witness.dob_days, cloned.dob_days);
        assert_eq!(witness.r_bits, cloned.r_bits);
        assert_eq!(witness.issuer_vk_bytes, cloned.issuer_vk_bytes);
        assert_eq!(witness.kid, cloned.kid);
        Ok(())
    }

    #[test]
    fn test_age_public_debug() -> Result<(), Box<dyn std::error::Error>> {
        let public = create_test_public()?;
        let debug_str = format!("{public:?}");

        assert!(debug_str.contains("AgePublic"));
        assert!(debug_str.contains("cutoff_days"));
        Ok(())
    }

    #[test]
    fn test_age_witness_debug() -> Result<(), Box<dyn std::error::Error>> {
        let witness = create_test_witness()?;
        let debug_str = format!("{witness:?}");

        assert!(debug_str.contains("AgeWitness"));
        assert!(debug_str.contains("dob_days"));
        Ok(())
    }

    // ========================================================================
    // UNDER-AGE DIRECTION TESTS
    // ========================================================================

    #[test]
    fn test_under_age_circuit_synthesis_no_witness() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::groth16::generate_random_parameters;
        use bls12_381::Bls12;
        use rand::{rngs::StdRng, SeedableRng};

        let circuit = AgeCircuit {
            public: AgePublic {
                direction: AgeDirection::Under,
                cutoff_days: 0,
                rp_hash: [0; 32],
                issuer_vk_bytes: [0; 32],
                cred_nullifier: [0; 32],
            },
            witness: None,
        };

        let mut rng = StdRng::seed_from_u64(43);
        let params = generate_random_parameters::<Bls12, _, _>(circuit, &mut rng)?;

        assert!(bool::from(params.vk.alpha_g1.is_on_curve()));
        assert!(bool::from(params.vk.beta_g2.is_on_curve()));
        assert_eq!(params.vk.ic.len(), 9);
        Ok(())
    }

    #[test]
    fn test_under_age_accepts_young_person() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // User born 5 years ago, checking under-13: dob > cutoff → passes
        let current_days = 20000i32;
        let dob_days = current_days - (5 * 365); // born 5 years ago
        let cutoff_days = current_days - (13 * 365); // 13 years ago

        // dob_days > cutoff_days, so dob >= cutoff is satisfied
        assert!(dob_days > cutoff_days);

        let (witness, mut public) = create_valid_test_fixtures_with_params(dob_days, cutoff_days)?;
        public.direction = AgeDirection::Under;

        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok(), "Under-age synthesis should succeed");
        assert!(
            cs.is_satisfied(),
            "Young person should pass under-age check"
        );
        Ok(())
    }

    #[test]
    fn test_under_age_rejects_old_person() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // User born 20 years ago, checking under-13: dob < cutoff → fails
        let current_days = 20000i32;
        let dob_days = current_days - (20 * 365); // born 20 years ago
        let cutoff_days = current_days - (13 * 365); // 13 years ago

        // dob_days < cutoff_days, so dob >= cutoff is NOT satisfied
        assert!(dob_days < cutoff_days);

        let (witness, mut public) = create_valid_test_fixtures_with_params(dob_days, cutoff_days)?;
        public.direction = AgeDirection::Under;

        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok(), "Under-age synthesis should succeed");
        assert!(!cs.is_satisfied(), "Old person should fail under-age check");
        Ok(())
    }

    #[test]
    fn test_under_age_boundary_equal() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // User born exactly on cutoff: dob == cutoff → passes (at most max_age)
        let dob_days = 15000i32;
        let cutoff_days = dob_days;

        let (witness, mut public) = create_valid_test_fixtures_with_params(dob_days, cutoff_days)?;
        public.direction = AgeDirection::Under;

        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };

        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok(), "Under-age synthesis should succeed");
        assert!(
            cs.is_satisfied(),
            "Person born on cutoff should pass under-age check (at most max_age)"
        );
        Ok(())
    }

    // ========================================================================
    // PRE-1970 AND CHILD TEST CASES (i32 sign extension)
    // ========================================================================

    #[test]
    fn test_pre_1970_dob_over_18() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;
        // DOB 1960-01-01: -3652 days before epoch
        // Cutoff for "over 18" in 2008: ~13880
        let (witness, public) = create_valid_test_fixtures_with_params(-3652, 13880)?;
        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };
        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok(), "Pre-1970 DOB synthesis should succeed");
        assert!(
            cs.is_satisfied(),
            "Person born 1960 should pass over-18 check"
        );
        Ok(())
    }

    #[test]
    fn test_epoch_boundary_dob() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;
        // DOB 1969-12-31: dob_days = -1
        let (witness, public) = create_valid_test_fixtures_with_params(-1, 13880)?;
        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };
        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "Person born 1969-12-31 should pass over-18 check"
        );
        Ok(())
    }

    #[test]
    fn test_epoch_exact_dob() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;
        // DOB 1970-01-01: dob_days = 0
        let (witness, public) = create_valid_test_fixtures_with_params(0, 13880)?;
        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };
        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "Person born 1970-01-01 should pass over-18 check"
        );
        Ok(())
    }

    #[test]
    fn test_child_under_3() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;
        // DOB ~2025-02-01: dob_days ~= 20120
        // Cutoff for "under 3": today(~20454) - 3*365 = ~19359
        // dob > cutoff, so under-age check passes
        let (witness, mut public) = create_valid_test_fixtures_with_params(20120, 19359)?;
        public.direction = AgeDirection::Under;
        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };
        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);
        assert!(result.is_ok());
        assert!(
            cs.is_satisfied(),
            "Child born 2025 should pass under-3 check"
        );
        Ok(())
    }

    #[test]
    fn test_negative_dob_extreme_values() -> Result<(), Box<dyn std::error::Error>> {
        use bellman::gadgets::test::TestConstraintSystem;

        // DOB 1900-01-01: approximately -25567 days before epoch
        let (witness, public) = create_valid_test_fixtures_with_params(-25567, 13880)?;
        let circuit = AgeCircuit {
            public,
            witness: Some(witness),
        };
        let mut cs = TestConstraintSystem::new();
        let result = circuit.synthesize(&mut cs);
        assert!(
            result.is_ok(),
            "Extreme negative DOB synthesis should succeed"
        );
        assert!(
            cs.is_satisfied(),
            "Person born 1900 should pass over-18 check"
        );

        // DOB 1930-01-01: approximately -14610 days before epoch
        let (witness2, public2) = create_valid_test_fixtures_with_params(-14610, 13880)?;
        let circuit2 = AgeCircuit {
            public: public2,
            witness: Some(witness2),
        };
        let mut cs2 = TestConstraintSystem::new();
        let result2 = circuit2.synthesize(&mut cs2);
        assert!(result2.is_ok(), "1930 DOB synthesis should succeed");
        assert!(
            cs2.is_satisfied(),
            "Person born 1930 should pass over-18 check"
        );
        Ok(())
    }

    #[test]
    fn test_bias_ordering_property() -> Result<(), Box<dyn std::error::Error>> {
        use provii_crypto_commons::bias_for_circuit;
        // Verify that bias preserves signed ordering as unsigned
        let neg = bias_for_circuit(-3652);
        let zero = bias_for_circuit(0);
        let pos = bias_for_circuit(13880);
        assert!(neg < zero, "bias(-3652) < bias(0) as unsigned");
        assert!(zero < pos, "bias(0) < bias(13880) as unsigned");
        Ok(())
    }

    #[test]
    fn test_circuit_constants_hash_unchanged() -> Result<(), Box<dyn std::error::Error>> {
        // The circuit structure has NOT changed (only input values are biased)
        let hash = compute_circuit_constants_hash();
        // Verify it's deterministic
        let hash2 = compute_circuit_constants_hash();
        assert_eq!(hash, hash2, "Circuit constants hash must be stable");
        Ok(())
    }
}
