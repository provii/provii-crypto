//! Groth16 proof generation for age proofs with comprehensive debugging.
//!
//! This crate uses `eprintln!` for debug logging on non-Android platforms,
//! gated by `DebugLevel` configuration. This is intentional diagnostic output
//! for proof generation debugging.

#![forbid(unsafe_code)]
#![allow(clippy::print_stderr)]

use bellman::groth16::{
    create_random_proof, prepare_verifying_key, verify_proof, Parameters, Proof,
};
use bellman::{Circuit, SynthesisError};
// Use `bls12_381` for both pairing and scalar operations.
use bls12_381::{Bls12, Scalar};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

// Import diagnostic public-input helpers.
use provii_crypto_public_inputs::{
    assemble_public_inputs_diagnostic, assemble_public_inputs_manual,
};
// AgeCircuit is parameterized over the scalar type; ensure compatibility with `bls12_381::Scalar`.
use blake2::{Blake2s256, Digest};
use ff::PrimeField;
use provii_crypto_circuit_age::{AgeCircuit, AgeDirection, AgePublic, AgeWitness};
use provii_crypto_commit::pedersen_nullifier;
use provii_crypto_commons::{Error, Result};

// Use `rand` 0.8, which is compatible with `rand_core` 0.6.
use rand::rngs::OsRng;

// Thread-safe runtime configuration state.
lazy_static::lazy_static! {
    static ref RUNTIME_CONFIG: Arc<Mutex<RuntimeConfig>> = Arc::new(Mutex::new(RuntimeConfig::new()));
    static ref DEBUG_LOGGER: Arc<Mutex<DebugLogger>> = Arc::new(Mutex::new(DebugLogger::new()));
}

static INIT: Once = Once::new();

#[derive(Debug, Clone)]
struct RuntimeConfig {
    is_mobile: bool,
    max_threads: usize,
    debug_level: DebugLevel,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DebugLevel {
    None,
    Basic,
    Verbose,
    Extreme,
}

impl RuntimeConfig {
    fn new() -> Self {
        // Derive the debug level from the environment, defaulting to the production-safe value.
        let debug_level = if cfg!(debug_assertions) {
            std::env::var("PROVER_DEBUG_LEVEL")
                .ok()
                .and_then(|s| match s.to_lowercase().as_str() {
                    "none" => Some(DebugLevel::None),
                    "basic" => Some(DebugLevel::Basic),
                    "verbose" => Some(DebugLevel::Verbose),
                    "extreme" => Some(DebugLevel::Extreme),
                    _ => None,
                })
                .unwrap_or(DebugLevel::Basic)
        } else {
            DebugLevel::None
        };

        Self {
            is_mobile: false,
            max_threads: 1,
            debug_level,
        }
    }
}

struct DebugLogger {
    logs: Vec<String>,
    start_time: Option<Instant>,
}

impl DebugLogger {
    fn new() -> Self {
        Self {
            logs: Vec::new(),
            start_time: None,
        }
    }

    fn start_session(&mut self) {
        self.logs.clear();
        self.start_time = Some(Instant::now());
    }

    fn dump_all(&self) -> String {
        self.logs.join("\n")
    }

    fn log(&mut self, level: DebugLevel, msg: String) {
        let config = RUNTIME_CONFIG
            .lock()
            .map(|c| c.clone())
            .unwrap_or_else(|_| RuntimeConfig::new());

        if level as u8 > config.debug_level as u8 {
            return; // Skip logs above the current level.
        }

        let timestamp = self
            .start_time
            .map(|t| t.elapsed().as_millis())
            .unwrap_or(0);

        let log_entry = format!("[{timestamp:>6}ms] {msg}");

        // Forward to Android logcat on Android platforms; otherwise log to stderr.
        #[cfg(target_os = "android")]
        {
            match level {
                DebugLevel::None => { /* drop */ }
                DebugLevel::Basic => log::info!("{}", log_entry),
                DebugLevel::Verbose => log::debug!("{}", log_entry),
                DebugLevel::Extreme => log::trace!("{}", log_entry),
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            if level as u8 <= config.debug_level as u8 {
                eprintln!("{log_entry}"); // nosemgrep: provii.crypto.debug-output-in-lib
            }
        }

        self.logs.push(log_entry);
    }
}

macro_rules! debug_log {
    ($level:expr, $($arg:tt)*) => {
        if let Ok(mut logger) = DEBUG_LOGGER.lock() {
            logger.log($level, format!($($arg)*));
        }
    };
}

/// Initialize the prover runtime with platform-specific optimizations.
fn init_prover_runtime() {
    INIT.call_once(|| {
        let is_mobile = cfg!(target_os = "ios")
            || cfg!(target_os = "android")
            || cfg!(target_arch = "wasm32")
            || cfg!(target_arch = "aarch64");

        let max_threads = if cfg!(test) {
            // Run single-threaded during tests to avoid Rayon thread-pool conflicts.
            1
        } else if is_mobile {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2)
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get().min(4))
                .unwrap_or(2)
        };

        // Update configuration based on the detected platform.
        if let Ok(mut config) = RUNTIME_CONFIG.lock() {
            *config = RuntimeConfig {
                is_mobile,
                max_threads,
                debug_level: config.debug_level, // Preserve the configured debug level.
            };
        }

        // Build the Rayon global thread pool to respect the computed `max_threads`.
        if rayon::ThreadPoolBuilder::new()
            .num_threads(max_threads)
            .build_global()
            .is_err()
        {
            // Ignore errors when the global pool has already been constructed.
        }

        // Install a custom panic hook for richer error reporting.
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            let loc = panic_info.location();

            #[cfg(target_os = "android")]
            {
                log::error!("=== PANIC DETECTED ===");
                log::error!("Location: {:?}", loc);

                if let Some(s) = panic_info.payload().downcast_ref::<String>() {
                    log::error!("Panic message (String): {}", s);
                } else if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
                    log::error!("Panic message (&str): {}", s);
                } else {
                    log::error!("Panic payload type: unknown");
                }

                if let Ok(logger) = DEBUG_LOGGER.lock() {
                    log::error!("=== DEBUG LOG DUMP ===");
                    for line in &logger.logs {
                        log::error!("[prover-dump] {}", line);
                    }
                }
            }

            #[cfg(not(target_os = "android"))]
            {
                // nosemgrep: provii.crypto.debug-output-in-lib -- intentional panic handler diagnostics
                eprintln!("=== PANIC DETECTED ===");
                eprintln!("Location: {loc:?}"); // nosemgrep: provii.crypto.debug-output-in-lib

                if let Some(s) = panic_info.payload().downcast_ref::<String>() {
                    eprintln!("Panic message (String): {s}"); // nosemgrep: provii.crypto.debug-output-in-lib
                } else if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
                    eprintln!("Panic message (&str): {s}"); // nosemgrep: provii.crypto.debug-output-in-lib
                } else {
                    eprintln!("Panic payload type: unknown"); // nosemgrep: provii.crypto.debug-output-in-lib
                }

                if let Ok(logger) = DEBUG_LOGGER.lock() {
                    eprintln!("=== DEBUG LOG DUMP ==="); // nosemgrep: provii.crypto.debug-output-in-lib
                    eprintln!("{}", logger.dump_all()); // nosemgrep: provii.crypto.debug-output-in-lib
                }
            }

            default_hook(panic_info);
        }));

        debug_log!(DebugLevel::Basic, "[prover] Runtime initialized:");
        debug_log!(DebugLevel::Basic, "  - Platform: {}", get_platform_string());
        debug_log!(DebugLevel::Basic, "  - Mobile: {}", is_mobile);
        debug_log!(DebugLevel::Basic, "  - Max threads: {}", max_threads);
        debug_log!(
            DebugLevel::Basic,
            "  - Architecture: {}",
            std::env::consts::ARCH
        );
        debug_log!(DebugLevel::Basic, "  - OS: {}", std::env::consts::OS);
    });
}

/// Load proving parameters from bytes with validation.
///
/// `bytes` must be a valid serialised `Parameters<Bls12>` as produced by
/// `Parameters::write`. Empty slices and malformed data are rejected with
/// `Error::InvalidFormat`. The function never panics on invalid input.
///
/// Typically called once at application startup. The returned parameters
/// are then passed to [`prove_age_snark`] for proof generation.
pub fn load_proving_key(bytes: &[u8]) -> Result<Parameters<Bls12>> {
    debug_log!(
        DebugLevel::Basic,
        "[prover] Loading proving key, size: {} bytes",
        bytes.len()
    );

    if bytes.is_empty() {
        debug_log!(DebugLevel::Basic, "[prover] ERROR: Empty proving key bytes");
        return Err(Error::InvalidFormat);
    }

    use std::io::Cursor;
    let mut cursor = Cursor::new(bytes);

    let start = Instant::now();
    let result = Parameters::read(&mut cursor, false);
    let elapsed = start.elapsed();

    match result {
        Ok(params) => {
            debug_log!(
                DebugLevel::Basic,
                "[prover] Successfully loaded proving key in {:?}",
                elapsed
            );
            debug_log!(
                DebugLevel::Verbose,
                "[prover] Parameters loaded, checking structure..."
            );

            Ok(params)
        }
        Err(e) => {
            debug_log!(
                DebugLevel::Basic,
                "[prover] ERROR: Failed to load proving key: {:?}",
                e
            );
            debug_log!(DebugLevel::Verbose, "[prover] Error details: {}", e);
            Err(Error::InvalidFormat)
        }
    }
}

/// Extended proof structure with issuer VK bytes and credential nullifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgeSnarkProofV2Extended {
    /// Format version carried alongside the proof.
    pub v: u8,
    /// Versioned identifier of the issuer verifying key.
    pub vk: u32,
    /// Blake2s hash of the relying-party challenge.
    pub rp_hash: [u8; 32],
    /// Age cutoff represented in days (negative for pre-1970 dates).
    pub cutoff: i32,
    /// Raw issuer verification key bytes committed in the proof.
    pub issuer_vk_bytes: [u8; 32],
    /// Pedersen-based nullifier that prevents credential reuse.
    pub cred_nullifier: [u8; 32],
    /// Direction of the age comparison (over-age or under-age).
    pub direction: AgeDirection,
    /// Serialized Groth16 proof bytes.
    pub proof: Vec<u8>,
    /// Optional metadata for debugging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProofMetadata>,
    /// Detailed debug information captured during proving.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_info: Option<DebugInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetadata {
    pub generation_time_ms: u64,
    pub platform: String,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DebugInfo {
    pub validation_results: ValidationResults,
    pub circuit_stats: CircuitStats,
    pub error_trace: Vec<String>,
    pub full_debug_log: String,
    pub public_inputs_hex: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationResults {
    pub input_validation: bool,
    pub witness_validation: bool,
    pub constraint_satisfaction: Option<bool>,
    pub details: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitStats {
    pub num_constraints: Option<usize>,
    pub num_variables: Option<usize>,
    pub synthesis_time_ms: Option<u64>,
}

/// Generate a Groth16 proof for age verification with full error handling.
pub fn prove_age_snark(
    params: &Parameters<Bls12>,
    public: AgePublic,
    witness: AgeWitness,
    vk_id: u32,
) -> Result<AgeSnarkProofV2Extended> {
    // Start the scoped debug session.
    if let Ok(mut logger) = DEBUG_LOGGER.lock() {
        logger.start_session();
    }

    debug_log!(DebugLevel::Basic, "=== PROVE_AGE_SNARK STARTED ===");
    debug_log!(DebugLevel::Basic, "VK ID: {}", vk_id);

    // Log the VK fingerprint to confirm it matches the server-side reference.
    {
        use blake2::{Blake2s256, Digest};
        let mut vk_bytes = Vec::new();
        params.vk.write(&mut vk_bytes).map_err(|e| {
            debug_log!(DebugLevel::Basic, "ERROR: Failed to serialize VK: {:?}", e);
            Error::Internal
        })?;
        let fp = Blake2s256::digest(&vk_bytes);
        // SAFETY(slicing): Blake2s256 digest is always 32 bytes; [..16] is in bounds.
        #[allow(clippy::indexing_slicing)]
        let fp_hex = hex::encode(&fp[..16]);
        debug_log!(
            DebugLevel::Verbose,
            "Prover VK fingerprint (Blake2s): {}",
            fp_hex
        );
    }

    // Ensure the prover runtime is initialized.
    init_prover_runtime();

    use provii_crypto_circuit_age::compute_circuit_constants_hash;
    let constants_hash = compute_circuit_constants_hash();
    debug_log!(
        DebugLevel::Verbose,
        "Circuit constants hash: {}",
        constants_hash
    );

    debug_log!(DebugLevel::Verbose, "=== CIRCUIT SHAPE CHECK ===");

    // Prepare the PVK embedded in the proving parameters for verification.
    {
        let _pvk_from_pk = prepare_verifying_key(&params.vk);
        debug_log!(DebugLevel::Verbose, "PVK prepared from proving params");
    }

    // Log the verification key embedded in the proving parameters for traceability.
    {
        let mut vk_bytes = Vec::new();
        params
            .vk
            .write(&mut vk_bytes)
            .map_err(|_| Error::Internal)?;
        let vk_fp_full = Blake2s256::digest(&vk_bytes);
        debug_log!(
            DebugLevel::Verbose,
            "PK-embedded VK fingerprint (full): {}",
            hex::encode(vk_fp_full)
        );
    }

    let start = Instant::now();
    let config = RUNTIME_CONFIG
        .lock()
        .map_err(|e| {
            debug_log!(
                DebugLevel::Basic,
                "ERROR: Failed to lock runtime config: {}",
                e
            );
            Error::Internal
        })?
        .clone();

    debug_log!(DebugLevel::Verbose, "Runtime config acquired");

    // Emit detailed diagnostics for the public and witness inputs.
    log_detailed_inputs(&public, &witness);

    // Use the diagnostic assembly path and compare with manual packing.
    debug_log!(
        DebugLevel::Verbose,
        "=== ASSEMBLING PUBLIC INPUTS FOR VERIFICATION ==="
    );

    // Assemble with the diagnostic path to ensure bit 254 is preserved.
    let direction_bool = public.direction == AgeDirection::Over;
    let publics = assemble_public_inputs_diagnostic(
        direction_bool,
        public.cutoff_days,
        public.rp_hash,
        // Pass raw verification key bytes instead of hashing.
        public.issuer_vk_bytes,
        public.cred_nullifier,
    )
    .map_err(|_| Error::InvalidInput)?;

    // Assemble using the manual path for comparison.
    let publics_manual = assemble_public_inputs_manual(
        direction_bool,
        public.cutoff_days,
        public.rp_hash,
        public.issuer_vk_bytes,
        public.cred_nullifier,
    )
    .map_err(|_| Error::InvalidInput)?;

    // Compare both assembly outputs.
    debug_log!(DebugLevel::Verbose, "=== COMPARING PACKING METHODS ===");
    let mut use_manual = false;
    for (i, (mp, man)) in publics.iter().zip(publics_manual.iter()).enumerate() {
        if mp != man {
            debug_log!(DebugLevel::Basic, "MISMATCH at index {}", i);
            debug_log!(
                DebugLevel::Basic,
                "  multipack: {}",
                hex::encode(mp.to_repr())
            );
            debug_log!(
                DebugLevel::Basic,
                "  manual: {}",
                hex::encode(man.to_repr())
            );
            use_manual = true;
        }
    }

    // Fallback to the manual version if discrepancies appear.
    let publics_final = if use_manual {
        debug_log!(
            DebugLevel::Basic,
            "⚠️ Using MANUAL packing due to multipack bug"
        );
        publics_manual.clone()
    } else {
        debug_log!(DebugLevel::Verbose, "✅ Multipack and manual methods agree");
        publics.clone()
    };

    debug_log!(
        DebugLevel::Verbose,
        "Public inputs (final) count: {} (expected 8)",
        publics_final.len()
    );

    // Capture hexadecimal representations for debugging.
    let mut public_inputs_hex = Vec::new();
    for (i, s) in publics_final.iter().enumerate() {
        let hex_repr = hex::encode(s.to_repr());
        debug_log!(DebugLevel::Verbose, "pi[{}]={}", i, &hex_repr);
        public_inputs_hex.push(hex_repr.clone());
    }

    // Log the complete hexadecimal view for quick comparison.
    debug_log!(DebugLevel::Verbose, "Full PI vector for comparison:");
    for (i, hex) in public_inputs_hex.iter().enumerate() {
        debug_log!(DebugLevel::Verbose, "  [{}] = 0x{}", i, hex);
    }

    // Compute a fingerprint for the final public inputs.
    {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        for pi in &publics_final {
            hasher.update(pi.to_repr());
        }
        let fp = hasher.finalize();
        // SAFETY(slicing): Blake2s256 digest is always 32 bytes; [..8] is in bounds.
        #[allow(clippy::indexing_slicing)]
        let fp_short = hex::encode(&fp[..8]);
        debug_log!(
            DebugLevel::Verbose,
            "Public inputs fingerprint (Blake2s): {}",
            fp_short
        );
        debug_log!(
            DebugLevel::Extreme,
            "PI fingerprint (full): {}",
            hex::encode(fp)
        );
    }

    // Document how each public input maps to circuit values.
    debug_log!(DebugLevel::Verbose, "Public input mapping:");
    debug_log!(DebugLevel::Verbose, "  pi[0] = cutoff_days (packed)");
    debug_log!(
        DebugLevel::Verbose,
        "  pi[1-2] = rp_hash (packed from 256 bits)"
    );
    debug_log!(
        DebugLevel::Verbose,
        "  pi[3-4] = issuer_vk_bytes (packed from 256 bits)"
    );
    debug_log!(
        DebugLevel::Verbose,
        "  pi[5-6] = cred_nullifier (packed from 256 bits)"
    );

    // Run detailed validation on the provided inputs.
    let validation_results = validate_inputs_detailed(&public, &witness);
    if !validation_results.input_validation {
        debug_log!(DebugLevel::Basic, "ERROR: Input validation failed");
        for detail in &validation_results.details {
            debug_log!(DebugLevel::Basic, "  - {}", detail);
        }

        return Err(Error::InvalidInput);
    }

    debug_log!(DebugLevel::Verbose, "Input validation passed");

    // Evaluate circuit synthesis before generating the proof.
    let circuit_stats = test_circuit_synthesis(&public, &witness)?;

    // Generate the proof with panic protection and retry logic.
    debug_log!(DebugLevel::Basic, "Starting proof generation...");
    let proof = generate_proof_with_retry(params, &public, &witness, &config)?;

    // Verify the proof before serialization.
    {
        debug_log!(
            DebugLevel::Verbose,
            "Verifying proof BEFORE serialization..."
        );
        use bellman::groth16::{prepare_verifying_key, verify_proof};

        let pvk = prepare_verifying_key(&params.vk);
        // Dereference the vector to expose the required slice of scalars.
        match verify_proof(&pvk, &proof, &publics_final[..]) {
            Ok(()) => {
                debug_log!(DebugLevel::Basic, "✅ Proof verifies BEFORE serialization!");
            }
            Err(e) => {
                debug_log!(
                    DebugLevel::Basic,
                    "❌ Proof fails BEFORE serialization: {:?}",
                    e
                );
                debug_log!(
                    DebugLevel::Basic,
                    "The proof is BAD immediately after create_random_proof"
                );
                return Err(Error::ProverFailed);
            }
        }
    }

    // Serialize the proof for transport.
    debug_log!(DebugLevel::Verbose, "Serializing proof...");
    let mut proof_bytes = Vec::new();
    proof.write(&mut proof_bytes).map_err(|e| {
        debug_log!(
            DebugLevel::Basic,
            "ERROR: Failed to serialize proof: {:?}",
            e
        );
        Error::ProverFailed
    })?;

    // Perform a local verification check.
    {
        debug_log!(
            DebugLevel::Verbose,
            "Performing local verification of generated proof..."
        );

        // Use the PVK derived from the same parameters we used to prove.
        let pvk_from_pk = prepare_verifying_key(&params.vk);

        match Proof::<Bls12>::read(&proof_bytes[..]) {
            Ok(proof_to_verify) => {
                // Dereference the vector to expose the required slice of scalars.
                match verify_proof(&pvk_from_pk, &proof_to_verify, &publics_final[..]) {
                    Ok(()) => {
                        debug_log!(DebugLevel::Basic, "✅ Proof verifies with PK-embedded VK!");
                    }
                    Err(e) => {
                        debug_log!(
                            DebugLevel::Basic,
                            "❌ Proof STILL fails with PK-embedded VK"
                        );
                        debug_log!(DebugLevel::Basic, "Error: {:?}", e);
                        return Err(Error::ProverFailed);
                    }
                }
            }
            Err(e) => {
                debug_log!(
                    DebugLevel::Basic,
                    "ERROR: Could not deserialize proof: {:?}",
                    e
                );
                return Err(Error::ProverFailed);
            }
        }
    }

    debug_log!(
        DebugLevel::Verbose,
        "Proof serialized: {} bytes",
        proof_bytes.len()
    );
    {
        use blake2::{Blake2s256, Digest};
        let fp = Blake2s256::digest(&proof_bytes);
        // SAFETY(slicing): Blake2s256 digest is always 32 bytes; [..8] is in bounds.
        #[allow(clippy::indexing_slicing)]
        let fp_short = hex::encode(&fp[..8]);
        debug_log!(
            DebugLevel::Verbose,
            "Proof fingerprint (Blake2s): {}",
            fp_short
        );
    }

    // Validate the proof size (Groth16 proofs should be ~192 bytes).
    if proof_bytes.len() < 100 || proof_bytes.len() > 500 {
        debug_log!(
            DebugLevel::Basic,
            "WARNING: Unexpected proof size: {} bytes",
            proof_bytes.len()
        );
    }

    let generation_time = start.elapsed();
    debug_log!(DebugLevel::Basic, "=== PROOF GENERATION COMPLETE ===");
    debug_log!(DebugLevel::Basic, "Total time: {:?}", generation_time);

    // Gather debugging information for downstream consumers.
    let debug_info = if config.debug_level != DebugLevel::None {
        let debug_log = DEBUG_LOGGER
            .lock()
            .map(|l| l.dump_all())
            .unwrap_or_default();

        Some(DebugInfo {
            validation_results,
            circuit_stats,
            error_trace: vec![],
            full_debug_log: debug_log,
            public_inputs_hex,
        })
    } else {
        None
    };

    Ok(AgeSnarkProofV2Extended {
        v: 2,
        vk: vk_id,
        rp_hash: public.rp_hash,
        cutoff: public.cutoff_days,
        // Propagate the raw issuer verification key bytes.
        issuer_vk_bytes: public.issuer_vk_bytes,
        // Preserve the Pedersen-based credential nullifier.
        cred_nullifier: public.cred_nullifier,
        direction: public.direction,
        proof: proof_bytes,
        metadata: Some(ProofMetadata {
            generation_time_ms: u64::try_from(generation_time.as_millis()).unwrap_or(u64::MAX),
            platform: get_platform_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
        debug_info,
    })
}

/// Generate proof with automatic hash computations (convenience function).
pub fn prove_age_snark_auto(
    params: &Parameters<Bls12>,
    // Cutoff days supplied by the server challenge; do not recompute locally.
    cutoff_days: i32,
    rp_challenge: [u8; 32],
    witness: AgeWitness,
    vk_id: u32,
    direction: AgeDirection,
) -> Result<AgeSnarkProofV2Extended> {
    debug_log!(DebugLevel::Basic, "=== PROVE_AGE_SNARK_AUTO STARTED ===");

    // Log that we are using the server-provided cutoff days verbatim.
    debug_log!(
        DebugLevel::Basic,
        "⚠️ Using cutoff_days={} FROM SERVER CHALLENGE (not computed locally!)",
        cutoff_days
    );

    // Publish the raw issuer verification key bytes (no hashing).
    debug_log!(
        DebugLevel::Verbose,
        "Using raw issuer VK bytes: {}",
        hex::encode(witness.issuer_vk_bytes)
    );

    // Compute the credential nullifier using the Pedersen commitment.
    let nullifier = pedersen_nullifier(&witness.c_bytes);
    debug_log!(
        DebugLevel::Verbose,
        "Computed Pedersen nullifier: {}",
        hex::encode(nullifier)
    );

    // Compute the RP hash from the provided challenge (off-circuit step).
    let rp_hash = {
        let mut hasher = Blake2s256::new();
        hasher.update(rp_challenge);
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    };
    debug_log!(
        DebugLevel::Verbose,
        "Computed RP hash: {}",
        hex::encode(rp_hash)
    );
    debug_log!(DebugLevel::Verbose, "=== RP HASH TRACKING ===");
    debug_log!(
        DebugLevel::Verbose,
        "rp_challenge(hex) = {}",
        hex::encode(rp_challenge)
    );
    debug_log!(
        DebugLevel::Verbose,
        "rp_hash(hex) = {}",
        hex::encode(rp_hash)
    );

    // Build public inputs using raw verification key bytes (no hashing).
    let public = AgePublic {
        cutoff_days,
        rp_hash,
        // Carry the raw verification key bytes emitted by the witness.
        issuer_vk_bytes: witness.issuer_vk_bytes,
        cred_nullifier: nullifier,
        direction,
    };

    // Use the diagnostic assembly path and compare with manual packing.
    debug_log!(
        DebugLevel::Verbose,
        "=== ASSEMBLING PUBLIC INPUTS FOR VERIFICATION ==="
    );

    // Assemble with the diagnostic path to ensure bit 254 is preserved.
    let direction_bool = public.direction == AgeDirection::Over;
    let publics = assemble_public_inputs_diagnostic(
        direction_bool,
        public.cutoff_days,
        public.rp_hash,
        public.issuer_vk_bytes,
        public.cred_nullifier,
    )
    .map_err(|_| Error::InvalidInput)?;

    // Assemble using the manual path for comparison.
    let publics_manual = assemble_public_inputs_manual(
        direction_bool,
        public.cutoff_days,
        public.rp_hash,
        public.issuer_vk_bytes,
        public.cred_nullifier,
    )
    .map_err(|_| Error::InvalidInput)?;

    // Compare both assembly outputs.
    debug_log!(DebugLevel::Verbose, "=== COMPARING PACKING METHODS ===");
    let mut use_manual = false;
    for (i, (mp, man)) in publics.iter().zip(publics_manual.iter()).enumerate() {
        if mp != man {
            debug_log!(DebugLevel::Basic, "MISMATCH at index {}", i);
            debug_log!(
                DebugLevel::Basic,
                "  multipack: {}",
                hex::encode(mp.to_repr())
            );
            debug_log!(
                DebugLevel::Basic,
                "  manual: {}",
                hex::encode(man.to_repr())
            );
            use_manual = true;
        }
    }

    if use_manual {
        debug_log!(
            DebugLevel::Basic,
            "⚠️ Using MANUAL packing due to multipack bug"
        );
    } else {
        debug_log!(DebugLevel::Verbose, "✅ Multipack and manual methods agree");
    }

    debug_log!(
        DebugLevel::Verbose,
        "Public inputs (multipacked) count: {} (expected 8)",
        publics.len()
    );

    // Capture hexadecimal representations for debugging.
    let mut public_inputs_hex = Vec::new();
    for (i, s) in publics.iter().enumerate() {
        let hex_repr = hex::encode(s.to_repr());
        debug_log!(DebugLevel::Verbose, "pi[{}]={}", i, &hex_repr);
        public_inputs_hex.push(hex_repr.clone());
    }

    // Log the complete hexadecimal view for quick comparison.
    debug_log!(DebugLevel::Verbose, "Full PI vector for comparison:");
    for (i, hex) in public_inputs_hex.iter().enumerate() {
        debug_log!(DebugLevel::Verbose, "  [{}] = 0x{}", i, hex);
    }

    // Compute a fingerprint for the assembled public inputs.
    {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        for pi in &publics {
            hasher.update(pi.to_repr());
        }
        let fp = hasher.finalize();
        // SAFETY(slicing): Blake2s256 digest is always 32 bytes; [..8] is in bounds.
        #[allow(clippy::indexing_slicing)]
        let fp_short = hex::encode(&fp[..8]);
        debug_log!(
            DebugLevel::Verbose,
            "Public inputs fingerprint (Blake2s): {}",
            fp_short
        );
        debug_log!(
            DebugLevel::Extreme,
            "PI fingerprint (full): {}",
            hex::encode(fp)
        );
    }

    // The witness already carries the RP hash, so forward it directly.
    prove_age_snark(params, public, witness, vk_id)
}

/// Test circuit synthesis without generating a proof.
fn test_circuit_synthesis(public: &AgePublic, witness: &AgeWitness) -> Result<CircuitStats> {
    debug_log!(DebugLevel::Verbose, "Testing circuit synthesis...");

    let circuit = AgeCircuit {
        public: public.clone(),
        witness: Some(witness.clone()),
    };

    use bellman::gadgets::test::TestConstraintSystem;

    // Use `bls12_381::Scalar` consistently for the constraint system.
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let start = Instant::now();

    match circuit.synthesize(&mut cs) {
        Ok(_) => {
            let synthesis_time = start.elapsed();
            let num_constraints = cs.num_constraints();
            let num_inputs = cs.num_inputs();

            debug_log!(DebugLevel::Verbose, "Circuit synthesis successful:");
            debug_log!(DebugLevel::Verbose, "  - Constraints: {}", num_constraints);
            debug_log!(DebugLevel::Verbose, "  - Public inputs: {}", num_inputs);

            // Log the in-circuit public input order for traceability.
            debug_log!(
                DebugLevel::Extreme,
                "Circuit public input order (as synthesized):"
            );
            if cs.num_inputs() > 0 {
                // Skip index 0 (the implicit ONE provided by the system).
                for i in 1..cs.num_inputs() {
                    debug_log!(DebugLevel::Extreme, "  - Circuit input[{}] allocated", i);
                }
            }

            // Verify that the expected multipacked values match the diagnostic path.
            let direction_bool = public.direction == AgeDirection::Over;
            let publics = assemble_public_inputs_diagnostic(
                direction_bool,
                public.cutoff_days,
                public.rp_hash,
                public.issuer_vk_bytes,
                public.cred_nullifier,
            )
            .map_err(|_| Error::InvalidInput)?;

            let publics_manual = assemble_public_inputs_manual(
                direction_bool,
                public.cutoff_days,
                public.rp_hash,
                public.issuer_vk_bytes,
                public.cred_nullifier,
            )
            .map_err(|_| Error::InvalidInput)?;

            let use_manual = publics
                .iter()
                .zip(publics_manual.iter())
                .any(|(mp, man)| mp != man);

            let expected_publics = if use_manual { publics_manual } else { publics };

            debug_log!(
                DebugLevel::Extreme,
                "Expected multipacked public inputs: {}",
                expected_publics.len()
            );
            for (i, val) in expected_publics.iter().enumerate() {
                debug_log!(
                    DebugLevel::Extreme,
                    "  - Expected pi[{}] = {}",
                    i,
                    hex::encode(val.to_repr())
                );
            }
            debug_log!(
                DebugLevel::Verbose,
                "  - Synthesis time: {:?}",
                synthesis_time
            );

            // Check whether the circuit constraints are satisfied.
            let satisfied = cs.is_satisfied();
            debug_log!(
                DebugLevel::Verbose,
                "  - Constraint satisfaction: {}",
                satisfied
            );

            if !satisfied {
                debug_log!(
                    DebugLevel::Basic,
                    "ERROR: Circuit constraints not satisfied!"
                );

                // Identify which constraint failed.
                let unsatisfied = cs.which_is_unsatisfied();
                if let Some(constraint_name) = unsatisfied {
                    debug_log!(
                        DebugLevel::Basic,
                        "  - Unsatisfied constraint: {}",
                        constraint_name
                    );
                }

                // Provide additional context about the failure.
                debug_log!(DebugLevel::Verbose, "Constraint system analysis:");
                debug_log!(
                    DebugLevel::Verbose,
                    "  - Total constraints: {}",
                    num_constraints
                );
                debug_log!(DebugLevel::Verbose, "  - Public inputs: {}", num_inputs);
                debug_log!(DebugLevel::Verbose, "  - Circuit failed satisfaction check");
                debug_log!(
                    DebugLevel::Verbose,
                    "  - This means the witness values don't satisfy the circuit logic"
                );

                return Err(Error::ProverFailed);
            }

            debug_log!(DebugLevel::Verbose, "  - All constraints satisfied ✓");

            Ok(CircuitStats {
                num_constraints: Some(num_constraints),
                num_variables: Some(num_inputs),
                synthesis_time_ms: Some(
                    u64::try_from(synthesis_time.as_millis()).unwrap_or(u64::MAX),
                ),
            })
        }
        Err(e) => {
            debug_log!(
                DebugLevel::Basic,
                "ERROR: Circuit synthesis failed: {:?}",
                e
            );
            match e {
                SynthesisError::AssignmentMissing => {
                    debug_log!(
                        DebugLevel::Basic,
                        "  - Assignment missing - witness incomplete"
                    );
                    debug_log!(
                        DebugLevel::Verbose,
                        "  - Some witness field is not properly set"
                    );
                }
                SynthesisError::DivisionByZero => {
                    debug_log!(DebugLevel::Basic, "  - Division by zero in circuit");
                    debug_log!(
                        DebugLevel::Verbose,
                        "  - Check for zero values in denominators"
                    );
                }
                SynthesisError::Unsatisfiable => {
                    debug_log!(DebugLevel::Basic, "  - Circuit is unsatisfiable");
                    debug_log!(
                        DebugLevel::Verbose,
                        "  - The circuit logic itself may have issues"
                    );
                }
                SynthesisError::PolynomialDegreeTooLarge => {
                    debug_log!(DebugLevel::Basic, "  - Polynomial degree too large");
                }
                SynthesisError::UnexpectedIdentity => {
                    debug_log!(DebugLevel::Basic, "  - Unexpected identity");
                }
                SynthesisError::IoError(io_err) => {
                    debug_log!(DebugLevel::Basic, "  - IO error: {}", io_err);
                }
                _ => {
                    debug_log!(DebugLevel::Basic, "  - Other synthesis error");
                }
            }
            Err(Error::ProverFailed)
        }
    }
}

/// Generate proof with retry logic and panic protection.
fn generate_proof_with_retry(
    params: &Parameters<Bls12>,
    public: &AgePublic,
    witness: &AgeWitness,
    config: &RuntimeConfig,
) -> Result<Proof<Bls12>> {
    debug_log!(
        DebugLevel::Verbose,
        "Starting proof generation (mobile={}, threads={})",
        config.is_mobile,
        config.max_threads
    );

    // First attempt with panic protection.
    let circuit = AgeCircuit {
        public: public.clone(),
        witness: Some(witness.clone()),
    };

    // Use `OsRng` for cryptographically secure randomness in proof generation.
    let mut rng = OsRng;

    debug_log!(DebugLevel::Verbose, "Attempt 1: Creating proof...");
    let attempt_start = Instant::now();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_random_proof(circuit, params, &mut rng)
    }));

    match result {
        Ok(Ok(proof)) => {
            let elapsed = attempt_start.elapsed();
            debug_log!(
                DebugLevel::Basic,
                "SUCCESS: Proof generated on first attempt in {:?}",
                elapsed
            );
            Ok(proof)
        }
        Ok(Err(e)) => {
            let elapsed = attempt_start.elapsed();
            debug_log!(
                DebugLevel::Basic,
                "FAILED: Proof generation failed after {:?}",
                elapsed
            );
            debug_log!(DebugLevel::Basic, "Error type: {:?}", e);

            // Provide additional context about the error.
            match e {
                SynthesisError::AssignmentMissing => {
                    debug_log!(
                        DebugLevel::Basic,
                        "ERROR: Assignment missing - checking witness completeness"
                    );
                    log_witness_details(witness);
                }
                SynthesisError::DivisionByZero => {
                    debug_log!(
                        DebugLevel::Basic,
                        "ERROR: Division by zero - checking for zero values"
                    );
                }
                SynthesisError::Unsatisfiable => {
                    debug_log!(
                        DebugLevel::Basic,
                        "ERROR: Circuit unsatisfiable - constraints cannot be met"
                    );
                }
                _ => {
                    debug_log!(DebugLevel::Basic, "ERROR: Other synthesis error");
                }
            }

            // Retry with a fresh circuit instance.
            debug_log!(
                DebugLevel::Verbose,
                "Attempt 2: Retrying proof generation..."
            );
            let retry_start = Instant::now();

            let retry_circuit = AgeCircuit {
                public: public.clone(),
                witness: Some(witness.clone()),
            };

            match create_random_proof(retry_circuit, params, &mut OsRng) {
                Ok(proof) => {
                    let elapsed = retry_start.elapsed();
                    debug_log!(
                        DebugLevel::Basic,
                        "SUCCESS: Retry succeeded in {:?}",
                        elapsed
                    );
                    Ok(proof)
                }
                Err(retry_err) => {
                    let elapsed = retry_start.elapsed();
                    debug_log!(
                        DebugLevel::Basic,
                        "FAILED: Retry failed after {:?}",
                        elapsed
                    );
                    debug_log!(DebugLevel::Basic, "Retry error: {:?}", retry_err);
                    Err(Error::ProverFailed)
                }
            }
        }
        Err(panic_payload) => {
            let elapsed = attempt_start.elapsed();
            debug_log!(
                DebugLevel::Basic,
                "PANIC: Proof generation panicked after {:?}",
                elapsed
            );

            // Attempt to extract the panic message.
            if let Some(s) = panic_payload.downcast_ref::<String>() {
                debug_log!(DebugLevel::Basic, "Panic message: {}", s);
            } else if let Some(s) = panic_payload.downcast_ref::<&str>() {
                debug_log!(DebugLevel::Basic, "Panic message: {}", s);
            }

            // Delay briefly to allow threads to unwind.
            std::thread::sleep(Duration::from_millis(100));

            // Attempt to recover after the panic.
            debug_log!(DebugLevel::Verbose, "Attempt 3: Recovery after panic...");
            let recovery_start = Instant::now();

            let retry_circuit = AgeCircuit {
                public: public.clone(),
                witness: Some(witness.clone()),
            };

            let recovery_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                create_random_proof(retry_circuit, params, &mut OsRng)
            }));

            match recovery_result {
                Ok(Ok(proof)) => {
                    let elapsed = recovery_start.elapsed();
                    debug_log!(
                        DebugLevel::Basic,
                        "SUCCESS: Recovery succeeded in {:?}",
                        elapsed
                    );
                    Ok(proof)
                }
                Ok(Err(e)) => {
                    let elapsed = recovery_start.elapsed();
                    debug_log!(
                        DebugLevel::Basic,
                        "FAILED: Recovery failed after {:?}",
                        elapsed
                    );
                    debug_log!(DebugLevel::Basic, "Recovery error: {:?}", e);
                    Err(Error::ProverFailed)
                }
                Err(_) => {
                    debug_log!(DebugLevel::Basic, "PANIC: Recovery also panicked");
                    Err(Error::ProverFailed)
                }
            }
        }
    }
}

/// Log detailed input information.
fn log_detailed_inputs(public: &AgePublic, witness: &AgeWitness) {
    // Load the current configuration to determine the debug level.
    let config = RUNTIME_CONFIG
        .lock()
        .map(|c| c.clone())
        .unwrap_or_else(|_| RuntimeConfig::new());

    if config.debug_level == DebugLevel::None {
        return;
    }

    // Compute the current epoch day for context.
    // SAFETY(cast): current epoch days ~20500 in 2026, well within i32 range.
    #[allow(clippy::cast_possible_truncation)]
    let today_epoch_days = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400) as i32;

    debug_log!(DebugLevel::Verbose, "=== PUBLIC INPUTS ===");
    debug_log!(
        DebugLevel::Verbose,
        "Cutoff days: {} (today epoch: {})",
        public.cutoff_days,
        today_epoch_days
    );

    // Diagnose the cutoff_days value for common mistakes.
    if public.cutoff_days < 10_000 {
        debug_log!(
            DebugLevel::Basic,
            "⚠️  WARNING: cutoff_days={} looks like a DURATION not an EPOCH!",
            public.cutoff_days
        );
        // SAFETY(arithmetic): today_epoch_days ~20500, subtraction cannot underflow.
        let approx_cutoff = today_epoch_days.saturating_sub(6570);
        debug_log!(
            DebugLevel::Basic,
            "   Should be approximately {} for 18+ today",
            approx_cutoff
        );
    }

    debug_log!(
        DebugLevel::Verbose,
        "RP hash: {}",
        hex::encode(public.rp_hash)
    );
    debug_log!(
        DebugLevel::Verbose,
        "Issuer VK bytes: {}",
        hex::encode(public.issuer_vk_bytes)
    );
    debug_log!(
        DebugLevel::Verbose,
        "Cred nullifier: {}",
        hex::encode(public.cred_nullifier)
    );

    // SECURITY: Witness fields dob_days, r_bits, and sig_rj_bytes are secret.
    // Only log non-secret metadata (lengths, public fields). Never log values.
    debug_log!(DebugLevel::Verbose, "=== WITNESS (redacted) ===");
    debug_log!(DebugLevel::Verbose, "DOB days: [REDACTED]");

    // Preview the age comparison outcome without revealing the actual DOB.
    debug_log!(DebugLevel::Verbose, "=== AGE CHECK PREVIEW ===");
    let age_check_passes = public.cutoff_days >= witness.dob_days;
    if age_check_passes {
        debug_log!(DebugLevel::Verbose, "Age check: PASS (user is old enough)");
    } else {
        debug_log!(
            DebugLevel::Basic,
            "Age check: FAIL (user does not meet threshold)"
        );
        debug_log!(
            DebugLevel::Basic,
            "   This causes 'age_threshold_check/no_final_borrow' error"
        );
    }

    debug_log!(DebugLevel::Verbose, "Version: {}", witness.v);
    // SECURITY: iat and exp are private witness fields. Logging their values
    // could correlate to a specific credential issuance window.
    debug_log!(DebugLevel::Verbose, "IAT: [REDACTED]");
    debug_log!(DebugLevel::Verbose, "EXP: [REDACTED]");
    debug_log!(DebugLevel::Verbose, "Kid length: {}", witness.kid.len());
    debug_log!(
        DebugLevel::Verbose,
        "Schema length: {}",
        witness.schema.len()
    );
    debug_log!(
        DebugLevel::Verbose,
        "R bits length: {}",
        witness.r_bits.len()
    );

    // SECURITY: r_bits is the blinding factor. Never log its value.
    debug_log!(
        DebugLevel::Verbose,
        "R bits: [REDACTED; {} bits]",
        witness.r_bits.len()
    );

    debug_log!(
        DebugLevel::Verbose,
        "Sig RJ bytes length: {}",
        witness.sig_rj_bytes.len()
    );
    // Issuer VK is a public key, safe to log.
    debug_log!(
        DebugLevel::Verbose,
        "Issuer VK bytes: {}",
        hex::encode(witness.issuer_vk_bytes)
    );
    // Commitment is a public value, safe to log.
    debug_log!(
        DebugLevel::Verbose,
        "C bytes: {}",
        hex::encode(witness.c_bytes)
    );

    // SECURITY: Never log r_bits values or sig_rj_bytes, even at Extreme level.
    if config.debug_level == DebugLevel::Extreme {
        debug_log!(
            DebugLevel::Extreme,
            "R bits: [REDACTED; {} bits]",
            witness.r_bits.len()
        );
        debug_log!(
            DebugLevel::Extreme,
            "Sig bytes: [REDACTED; {} bytes]",
            witness.sig_rj_bytes.len()
        );
    }
}

/// Log witness details for debugging (redacted to protect secret values).
///
/// SECURITY: Only logs structural metadata (lengths, zero-counts, timestamps).
/// Never logs actual values of dob_days, r_bits, or sig_rj_bytes.
fn log_witness_details(witness: &AgeWitness) {
    let config = RUNTIME_CONFIG
        .lock()
        .map(|c| c.clone())
        .unwrap_or_else(|_| RuntimeConfig::new());

    if config.debug_level == DebugLevel::None {
        return;
    }

    debug_log!(DebugLevel::Verbose, "=== WITNESS DETAILS (redacted) ===");

    // Check for degenerate randomness without revealing actual values.
    let zero_count = witness.r_bits.iter().filter(|&&b| !b).count();
    // SAFETY(arithmetic): zero_count <= r_bits.len() by definition (it counts elements within).
    #[allow(clippy::arithmetic_side_effects)]
    let one_count = witness.r_bits.len() - zero_count;

    if zero_count == witness.r_bits.len() {
        debug_log!(DebugLevel::Basic, "WARNING: All R bits are zero!");
    }
    if one_count == witness.r_bits.len() {
        debug_log!(DebugLevel::Basic, "WARNING: All R bits are one!");
    }

    debug_log!(
        DebugLevel::Verbose,
        "R bits: [REDACTED; {} bits]",
        witness.r_bits.len()
    );

    // Check for degenerate signature without revealing actual bytes.
    let sig_zero_count = witness.sig_rj_bytes.iter().filter(|&&b| b == 0).count();
    if sig_zero_count == witness.sig_rj_bytes.len() {
        debug_log!(DebugLevel::Basic, "WARNING: Signature is all zeros!");
    }

    debug_log!(
        DebugLevel::Verbose,
        "Sig RJ bytes: [REDACTED; {} bytes]",
        witness.sig_rj_bytes.len()
    );

    // Commitment bytes are public (the output of the Pedersen hash).
    if witness.c_bytes == [0u8; 32] {
        debug_log!(DebugLevel::Basic, "WARNING: Commitment is all zeros!");
    }

    // Review issuance and expiration timestamps for inconsistencies.
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if witness.iat > current_time {
        debug_log!(DebugLevel::Basic, "WARNING: IAT is in the future!");
    }
    if witness.exp < current_time {
        debug_log!(DebugLevel::Basic, "WARNING: Credential may be expired!");
    }
}

/// Validate inputs with detailed results.
fn validate_inputs_detailed(public: &AgePublic, witness: &AgeWitness) -> ValidationResults {
    let mut results = ValidationResults {
        input_validation: true,
        witness_validation: true,
        constraint_satisfaction: None,
        details: Vec::new(),
    };

    // Validate public input bounds.
    if public.cutoff_days == 0 {
        results.input_validation = false;
        results.details.push("Cutoff days is 0".to_string());
    }
    if public.cutoff_days > 36500 {
        results.input_validation = false;
        results
            .details
            .push(format!("Cutoff days too large: {}", public.cutoff_days));
    }

    // Validate witness field bounds.
    // SECURITY: Never include actual dob_days values in detail strings,
    // as these end up in the serialised proof debug output.
    if witness.dob_days == 0 {
        results.witness_validation = false;
        results.details.push("DOB days is 0".to_string());
    }
    if witness.dob_days > 36500 {
        results.witness_validation = false;
        results
            .details
            .push("DOB days exceeds maximum bound".to_string());
    }

    if witness.r_bits.len() != 128 {
        results.witness_validation = false;
        results.details.push(format!(
            "R bits length is {} (expected 128)",
            witness.r_bits.len()
        ));
    }

    if witness.sig_rj_bytes.len() != 64 {
        results.witness_validation = false;
        results.details.push(format!(
            "Signature length is {} (expected 64)",
            witness.sig_rj_bytes.len()
        ));
    }

    // Validate issuance and expiration timestamps.
    if witness.iat >= witness.exp {
        results.witness_validation = false;
        // SECURITY: Do not include actual iat/exp values in detail strings,
        // as these end up in debug log output and could identify the credential.
        results
            .details
            .push("Invalid timestamps: iat >= exp".to_string());
    }

    // Validate commitment bytes.
    if witness.c_bytes == [0u8; 32] {
        results.witness_validation = false;
        results.details.push("Commitment is all zeros".to_string());
    }

    // Check age logic against the public cutoff.
    // SECURITY: Do not include witness.dob_days in message.
    if witness.dob_days > public.cutoff_days {
        results
            .details
            .push("WARNING: Age check may fail (dob exceeds cutoff)".to_string());
    }

    results.input_validation = results.input_validation && results.witness_validation;

    if results.details.is_empty() {
        results.details.push("All validations passed".to_string());
    }

    results
}

/// Validate inputs before proof generation.
#[allow(dead_code)]
fn validate_inputs(public: &AgePublic, witness: &AgeWitness) -> Result<()> {
    let results = validate_inputs_detailed(public, witness);
    if results.input_validation {
        Ok(())
    } else {
        debug_log!(
            DebugLevel::Basic,
            "Validation failed: {:?}",
            results.details
        );
        Err(Error::InvalidInput)
    }
}

/// Helper function to dump debug logs (useful for error reporting).
pub fn dump_debug_log() {
    if let Ok(logger) = DEBUG_LOGGER.lock() {
        for line in &logger.logs {
            #[cfg(target_os = "android")]
            log::error!("[prover-debug] {}", line);

            #[cfg(not(target_os = "android"))]
            eprintln!("[prover-debug] {line}"); // nosemgrep: provii.crypto.debug-output-in-lib
        }
    }
}

fn get_platform_string() -> String {
    if cfg!(target_os = "ios") {
        "ios".to_string()
    } else if cfg!(target_os = "android") {
        "android".to_string()
    } else if cfg!(target_arch = "wasm32") {
        "wasm".to_string()
    } else if cfg!(target_os = "macos") {
        "macos".to_string()
    } else if cfg!(target_os = "windows") {
        "windows".to_string()
    } else {
        "linux".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    RUNTIME CONFIGURATION TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_runtime_initialization() -> std::result::Result<(), Box<dyn std::error::Error>> {
        init_prover_runtime();
        let config = RUNTIME_CONFIG.lock()?.clone();

        // The runtime should be single-threaded during tests.
        assert_eq!(config.max_threads, 1);
        Ok(())
    }

    #[test]
    fn test_runtime_config_new() {
        let config = RuntimeConfig::new();
        assert_eq!(config.max_threads, 1);
        assert!(!config.is_mobile);
    }

    #[test]
    fn test_debug_level_ordering() {
        assert!((DebugLevel::None as u8) < (DebugLevel::Basic as u8));
        assert!((DebugLevel::Basic as u8) < (DebugLevel::Verbose as u8));
        assert!((DebugLevel::Verbose as u8) < (DebugLevel::Extreme as u8));
    }

    /* ========================================================================== */
    /*                    PLATFORM DETECTION TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_platform_detection() {
        let platform = get_platform_string();
        assert!(!platform.is_empty());

        // Should be one of the known platforms
        let known_platforms = ["ios", "android", "wasm", "macos", "windows", "linux"];
        assert!(known_platforms.contains(&platform.as_str()));
    }

    /* ========================================================================== */
    /*                    INPUT VALIDATION TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_input_validation_valid() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 6570,
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 7300,
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        assert!(results.input_validation);
    }

    #[test]
    fn test_input_validation_invalid_r_bits_length() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 6570,
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let bad_witness = AgeWitness {
            dob_days: 7300,
            r_bits: vec![false; 100], // Wrong length!
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        let bad_results = validate_inputs_detailed(&public, &bad_witness);
        assert!(!bad_results.witness_validation);
        assert!(bad_results
            .details
            .iter()
            .any(|d| d.contains("R bits length")));
    }

    #[test]
    fn test_input_validation_invalid_sig_length() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 6570,
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 7300,
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 32], // Wrong length!
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        assert!(!results.witness_validation);
        assert!(results
            .details
            .iter()
            .any(|d| d.contains("Signature length")));
    }

    #[test]
    fn test_input_validation_zero_cutoff() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 0, // Invalid!
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 7300,
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        assert!(!results.input_validation);
        assert!(results
            .details
            .iter()
            .any(|d| d.contains("Cutoff days is 0")));
    }

    #[test]
    fn test_input_validation_zero_dob() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 6570,
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 0, // Invalid!
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        assert!(!results.witness_validation);
        assert!(results.details.iter().any(|d| d.contains("DOB days is 0")));
    }

    #[test]
    fn test_input_validation_invalid_timestamps() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 6570,
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 7300,
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 2000,
            exp: 1000, // Exp before iat!
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        assert!(!results.witness_validation);
        assert!(results
            .details
            .iter()
            .any(|d| d.contains("Invalid timestamps")));
    }

    #[test]
    fn test_input_validation_zero_commitment() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 6570,
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 7300,
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [0; 32], // All zeros!
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        assert!(!results.witness_validation);
        assert!(results
            .details
            .iter()
            .any(|d| d.contains("Commitment is all zeros")));
    }

    #[test]
    fn test_input_validation_cutoff_too_large() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 50000, // Too large!
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 7300,
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        assert!(!results.input_validation);
        assert!(results.details.iter().any(|d| d.contains("too large")));
    }

    #[test]
    fn test_input_validation_dob_too_large() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 6570,
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 50000, // Too large!
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        assert!(!results.witness_validation);
        assert!(results
            .details
            .iter()
            .any(|d| d.contains("exceeds maximum bound")));
    }

    #[test]
    fn test_validate_inputs_wrapper() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 6570,
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 7300,
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        assert!(validate_inputs(&public, &witness).is_ok());
    }

    /* ========================================================================== */
    /*                    LOAD_PROVING_KEY TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_load_proving_key_empty_bytes() {
        let result = load_proving_key(&[]);
        assert!(result.is_err());
        // Check error type without unwrapping (Parameters<Bls12> doesn't implement Debug)
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidFormat));
        }
    }

    #[test]
    fn test_load_proving_key_invalid_bytes() {
        let invalid = vec![0xFF; 100];
        let result = load_proving_key(&invalid);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    STRUCT SERIALIZATION TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_proof_metadata_serialization() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let metadata = ProofMetadata {
            generation_time_ms: 1234,
            platform: "test".to_string(),
            version: "1.0.0".to_string(),
        };

        let json = serde_json::to_string(&metadata)?;
        let deserialized: ProofMetadata = serde_json::from_str(&json)?;

        assert_eq!(deserialized.generation_time_ms, 1234);
        assert_eq!(deserialized.platform, "test");
        assert_eq!(deserialized.version, "1.0.0");
        Ok(())
    }

    #[test]
    fn test_validation_results_structure() {
        let results = ValidationResults {
            input_validation: true,
            witness_validation: true,
            constraint_satisfaction: Some(true),
            details: vec!["test".to_string()],
        };

        assert!(results.input_validation);
        assert!(results.witness_validation);
        assert_eq!(results.constraint_satisfaction, Some(true));
        assert_eq!(results.details.len(), 1);
    }

    #[test]
    fn test_circuit_stats_structure() {
        let stats = CircuitStats {
            num_constraints: Some(1000),
            num_variables: Some(500),
            synthesis_time_ms: Some(100),
        };

        assert_eq!(stats.num_constraints, Some(1000));
        assert_eq!(stats.num_variables, Some(500));
        assert_eq!(stats.synthesis_time_ms, Some(100));
    }

    #[test]
    fn test_age_snark_proof_v2_extended_serialization(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let proof = AgeSnarkProofV2Extended {
            v: 2,
            vk: 1,
            rp_hash: [0; 32],
            cutoff: 6570,
            issuer_vk_bytes: [1; 32],
            cred_nullifier: [2; 32],
            direction: AgeDirection::Over,
            proof: vec![0xFF; 192],
            metadata: None,
            debug_info: None,
        };

        let json = serde_json::to_string(&proof)?;
        let deserialized: AgeSnarkProofV2Extended = serde_json::from_str(&json)?;

        assert_eq!(deserialized.v, 2);
        assert_eq!(deserialized.vk, 1);
        assert_eq!(deserialized.cutoff, 6570);
        assert_eq!(deserialized.proof.len(), 192);
        Ok(())
    }

    #[test]
    fn test_age_snark_proof_with_metadata() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let metadata = Some(ProofMetadata {
            generation_time_ms: 5000,
            platform: "test-platform".to_string(),
            version: "0.1.0".to_string(),
        });

        let proof = AgeSnarkProofV2Extended {
            v: 2,
            vk: 1,
            rp_hash: [0; 32],
            cutoff: 6570,
            issuer_vk_bytes: [1; 32],
            cred_nullifier: [2; 32],
            direction: AgeDirection::Over,
            proof: vec![0; 192],
            metadata,
            debug_info: None,
        };

        assert!(proof.metadata.is_some());
        assert_eq!(
            proof.metadata.ok_or("missing metadata")?.generation_time_ms,
            5000
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    DEBUG LOGGER TESTS                                     */
    /* ========================================================================== */

    #[test]
    fn test_debug_logger_new() {
        let logger = DebugLogger::new();
        assert_eq!(logger.logs.len(), 0);
        assert!(logger.start_time.is_none());
    }

    #[test]
    fn test_debug_logger_start_session() {
        let mut logger = DebugLogger::new();
        logger.logs.push("old log".to_string());

        logger.start_session();

        assert_eq!(logger.logs.len(), 0);
        assert!(logger.start_time.is_some());
    }

    #[test]
    fn test_debug_logger_dump_all() {
        let mut logger = DebugLogger::new();
        logger.logs.push("line1".to_string());
        logger.logs.push("line2".to_string());

        let dump = logger.dump_all();
        assert!(dump.contains("line1"));
        assert!(dump.contains("line2"));
    }

    /* ========================================================================== */
    /*                    INTEGRATION TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_validation_results_failure_accumulation() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 0, // Invalid
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 0,              // Invalid
            r_bits: vec![false; 100], // Invalid length
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 32], // Invalid length
            v: 2,
            kid: vec![],
            c_bytes: [0; 32], // Invalid (all zeros)
            iat: 2000,
            exp: 1000, // Invalid (exp < iat)
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);

        assert!(!results.input_validation);
        assert!(!results.witness_validation);
        // Should have multiple validation failures
        assert!(results.details.len() > 3);
    }

    #[test]
    fn test_dump_debug_log_doesnt_panic() {
        dump_debug_log();
        // Just ensure it doesn't panic
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    use proptest::prelude::*;

    proptest! {
        /// Property: valid inputs pass validation
        #[test]
        fn prop_valid_inputs_pass_validation(
            cutoff_days in 1i32..36500,
            dob_days in 1i32..36500
        ) {
            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days,
                rp_hash: [1; 32],
                issuer_vk_bytes: [2; 32],
                cred_nullifier: [3; 32],
            };

            let witness = AgeWitness {
                dob_days,
                r_bits: vec![false; 128],
                issuer_vk_bytes: [2; 32],
                sig_rj_bytes: vec![1; 64],
                v: 2,
                kid: vec![],
                c_bytes: [1; 32],
                iat: 1000,
                exp: 2000,
                schema: vec![],
            };

            let result = validate_inputs(&public, &witness);
            prop_assert!(result.is_ok(), "Valid inputs should pass validation");
        }

        /// Property: invalid r_bits length fails validation
        #[test]
        fn prop_invalid_r_bits_fails_validation(
            r_bits_len in 0usize..256
        ) {
            prop_assume!(r_bits_len != 128);

            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days: 6570,
                rp_hash: [1; 32],
                issuer_vk_bytes: [2; 32],
                cred_nullifier: [3; 32],
            };

            let witness = AgeWitness {
                dob_days: 7300,
                r_bits: vec![false; r_bits_len],
                issuer_vk_bytes: [2; 32],
                sig_rj_bytes: vec![1; 64],
                v: 2,
                kid: vec![],
                c_bytes: [1; 32],
                iat: 1000,
                exp: 2000,
                schema: vec![],
            };

            let result = validate_inputs(&public, &witness);
            prop_assert!(result.is_err(), "Invalid r_bits length should fail validation");
        }

        /// Property: invalid sig_bytes length fails validation
        #[test]
        fn prop_invalid_sig_bytes_fails_validation(
            sig_len in 0usize..256
        ) {
            prop_assume!(sig_len != 64);

            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days: 6570,
                rp_hash: [1; 32],
                issuer_vk_bytes: [2; 32],
                cred_nullifier: [3; 32],
            };

            let witness = AgeWitness {
                dob_days: 7300,
                r_bits: vec![false; 128],
                issuer_vk_bytes: [2; 32],
                sig_rj_bytes: vec![1; sig_len],
                v: 2,
                kid: vec![],
                c_bytes: [1; 32],
                iat: 1000,
                exp: 2000,
                schema: vec![],
            };

            let result = validate_inputs(&public, &witness);
            prop_assert!(result.is_err(), "Invalid sig length should fail validation");
        }

        /// Property: validation is deterministic
        #[test]
        fn prop_validation_deterministic(
            cutoff_days in 1i32..36500,
            dob_days in 1i32..36500
        ) {
            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days,
                rp_hash: [1; 32],
                issuer_vk_bytes: [2; 32],
                cred_nullifier: [3; 32],
            };

            let witness = AgeWitness {
                dob_days,
                r_bits: vec![false; 128],
                issuer_vk_bytes: [2; 32],
                sig_rj_bytes: vec![1; 64],
                v: 2,
                kid: vec![],
                c_bytes: [1; 32],
                iat: 1000,
                exp: 2000,
                schema: vec![],
            };

            let result1 = validate_inputs(&public, &witness);
            let result2 = validate_inputs(&public, &witness);
            prop_assert_eq!(result1.is_ok(), result2.is_ok());
        }

        /// Property: zero commitment fails validation
        #[test]
        fn prop_zero_commitment_fails(_i in 0..20) {
            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days: 6570,
                rp_hash: [1; 32],
                issuer_vk_bytes: [2; 32],
                cred_nullifier: [3; 32],
            };

            let witness = AgeWitness {
                dob_days: 7300,
                r_bits: vec![false; 128],
                issuer_vk_bytes: [2; 32],
                sig_rj_bytes: vec![1; 64],
                v: 2,
                kid: vec![],
                c_bytes: [0; 32], // Zero commitment
                iat: 1000,
                exp: 2000,
                schema: vec![],
            };

            let results = validate_inputs_detailed(&public, &witness);
            prop_assert!(!results.witness_validation);
        }

        /// Property: cutoff boundary at 36500
        #[test]
        fn prop_cutoff_boundary_36500(_i in 0..20) {
            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days: 36500,
                rp_hash: [1; 32],
                issuer_vk_bytes: [2; 32],
                cred_nullifier: [3; 32],
            };

            let witness = AgeWitness {
                dob_days: 7300,
                r_bits: vec![false; 128],
                issuer_vk_bytes: [2; 32],
                sig_rj_bytes: vec![1; 64],
                v: 2,
                kid: vec![],
                c_bytes: [1; 32],
                iat: 1000,
                exp: 2000,
                schema: vec![],
            };

            let result = validate_inputs(&public, &witness);
            prop_assert!(result.is_ok(), "36500 should be valid");
        }

        /// Property: cutoff 36501 fails
        #[test]
        fn prop_cutoff_boundary_36501(_i in 0..20) {
            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days: 36501,
                rp_hash: [1; 32],
                issuer_vk_bytes: [2; 32],
                cred_nullifier: [3; 32],
            };

            let witness = AgeWitness {
                dob_days: 7300,
                r_bits: vec![false; 128],
                issuer_vk_bytes: [2; 32],
                sig_rj_bytes: vec![1; 64],
                v: 2,
                kid: vec![],
                c_bytes: [1; 32],
                iat: 1000,
                exp: 2000,
                schema: vec![],
            };

            let results = validate_inputs_detailed(&public, &witness);
            prop_assert!(!results.input_validation);
        }

        /// Property: invalid timestamps (iat >= exp) fails
        #[test]
        fn prop_invalid_timestamps_fails(
            iat in 1000u64..10000,
            exp in 1000u64..10000
        ) {
            prop_assume!(iat >= exp);

            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days: 6570,
                rp_hash: [1; 32],
                issuer_vk_bytes: [2; 32],
                cred_nullifier: [3; 32],
            };

            let witness = AgeWitness {
                dob_days: 7300,
                r_bits: vec![false; 128],
                issuer_vk_bytes: [2; 32],
                sig_rj_bytes: vec![1; 64],
                v: 2,
                kid: vec![],
                c_bytes: [1; 32],
                iat,
                exp,
                schema: vec![],
            };

            let results = validate_inputs_detailed(&public, &witness);
            prop_assert!(!results.witness_validation);
        }

        /// Property: validation results are serializable
        #[test]
        fn prop_validation_results_serializable(
            cutoff_days in 1i32..36500
        ) {
            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days,
                rp_hash: [1; 32],
                issuer_vk_bytes: [2; 32],
                cred_nullifier: [3; 32],
            };

            let witness = AgeWitness {
                dob_days: 7300,
                r_bits: vec![false; 128],
                issuer_vk_bytes: [2; 32],
                sig_rj_bytes: vec![1; 64],
                v: 2,
                kid: vec![],
                c_bytes: [1; 32],
                iat: 1000,
                exp: 2000,
                schema: vec![],
            };

            let results = validate_inputs_detailed(&public, &witness);
            let json = serde_json::to_string(&results);
            prop_assert!(json.is_ok());
        }

        /// Property: platform string is non-empty
        #[test]
        fn prop_platform_string_non_empty(_i in 0..20) {
            let platform = get_platform_string();
            prop_assert!(!platform.is_empty());
        }

        /// Property: debug level ordering
        #[test]
        fn prop_debug_level_ordering(_i in 0..20) {
            prop_assert!((DebugLevel::None as u8) < (DebugLevel::Basic as u8));
            prop_assert!((DebugLevel::Basic as u8) < (DebugLevel::Verbose as u8));
            prop_assert!((DebugLevel::Verbose as u8) < (DebugLevel::Extreme as u8));
        }

        /// Property: AgeSnarkProofV2Extended serialization round-trip
        #[test]
        fn prop_proof_serialization_round_trip(
            cutoff in 1i32..36500,
            vk_id in 0u32..100
        ) {
            let proof = AgeSnarkProofV2Extended {
                v: 2,
                vk: vk_id,
                rp_hash: [42; 32],
                cutoff,
                issuer_vk_bytes: [99; 32],
                cred_nullifier: [77; 32],
                direction: AgeDirection::Over,
                proof: vec![0xFF; 192],
                metadata: None,
                debug_info: None,
            };

            let json = serde_json::to_string(&proof);
            prop_assert!(json.is_ok());

            let _json_val = json?;
            let deserialized = serde_json::from_str::<AgeSnarkProofV2Extended>(&_json_val);
            prop_assert!(deserialized.is_ok());

            let proof2 = deserialized?;
            prop_assert_eq!(proof.v, proof2.v);
            prop_assert_eq!(proof.cutoff, proof2.cutoff);
        }

        /// Property: load_proving_key rejects empty bytes
        #[test]
        fn prop_load_proving_key_rejects_empty(_i in 0..20) {
            let result = load_proving_key(&[]);
            prop_assert!(result.is_err());
        }

        /// Property: validation detailed produces non-empty details
        #[test]
        fn prop_validation_produces_details(
            cutoff_days in 1i32..36500,
            dob_days in 1i32..36500
        ) {
            let public = AgePublic {
                direction: AgeDirection::Over,
                cutoff_days,
                rp_hash: [1; 32],
                issuer_vk_bytes: [2; 32],
                cred_nullifier: [3; 32],
            };

            let witness = AgeWitness {
                dob_days,
                r_bits: vec![false; 128],
                issuer_vk_bytes: [2; 32],
                sig_rj_bytes: vec![1; 64],
                v: 2,
                kid: vec![],
                c_bytes: [1; 32],
                iat: 1000,
                exp: 2000,
                schema: vec![],
            };

            let results = validate_inputs_detailed(&public, &witness);
            prop_assert!(!results.details.is_empty());
        }
    }

    /* ========================================================================== */
    /*                    DEBUG_INFO STRUCT TESTS                                */
    /* ========================================================================== */

    #[test]
    fn test_debug_info_structure() {
        let debug_info = DebugInfo {
            validation_results: ValidationResults {
                input_validation: true,
                witness_validation: true,
                constraint_satisfaction: Some(true),
                details: vec!["test".to_string()],
            },
            circuit_stats: CircuitStats {
                num_constraints: Some(1000),
                num_variables: Some(500),
                synthesis_time_ms: Some(100),
            },
            error_trace: vec!["error1".to_string(), "error2".to_string()],
            full_debug_log: "log content".to_string(),
            public_inputs_hex: vec!["abc".to_string(), "def".to_string()],
        };

        assert!(debug_info.validation_results.input_validation);
        assert_eq!(debug_info.circuit_stats.num_constraints, Some(1000));
        assert_eq!(debug_info.error_trace.len(), 2);
        assert_eq!(debug_info.full_debug_log, "log content");
        assert_eq!(debug_info.public_inputs_hex.len(), 2);
    }

    #[test]
    fn test_debug_info_serialization() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let debug_info = DebugInfo {
            validation_results: ValidationResults {
                input_validation: true,
                witness_validation: true,
                constraint_satisfaction: None,
                details: vec![],
            },
            circuit_stats: CircuitStats {
                num_constraints: None,
                num_variables: None,
                synthesis_time_ms: None,
            },
            error_trace: vec![],
            full_debug_log: String::new(),
            public_inputs_hex: vec![],
        };

        let json = serde_json::to_string(&debug_info)?;
        let deserialized: DebugInfo = serde_json::from_str(&json)?;

        assert!(deserialized.validation_results.input_validation);
        assert_eq!(deserialized.error_trace.len(), 0);
        Ok(())
    }

    #[test]
    fn test_age_snark_proof_with_debug_info() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let debug_info = Some(DebugInfo {
            validation_results: ValidationResults {
                input_validation: true,
                witness_validation: true,
                constraint_satisfaction: Some(true),
                details: vec!["All validations passed".to_string()],
            },
            circuit_stats: CircuitStats {
                num_constraints: Some(5000),
                num_variables: Some(2500),
                synthesis_time_ms: Some(250),
            },
            error_trace: vec![],
            full_debug_log: "[100ms] Starting proof generation".to_string(),
            public_inputs_hex: vec!["0a".to_string(), "1b".to_string()],
        });

        let proof = AgeSnarkProofV2Extended {
            v: 2,
            vk: 1,
            rp_hash: [0; 32],
            cutoff: 6570,
            issuer_vk_bytes: [1; 32],
            cred_nullifier: [2; 32],
            direction: AgeDirection::Over,
            proof: vec![0; 192],
            metadata: None,
            debug_info,
        };

        assert!(proof.debug_info.is_some());
        let debug = proof.debug_info.ok_or("missing debug_info")?;
        assert_eq!(debug.circuit_stats.num_constraints, Some(5000));
        assert_eq!(debug.public_inputs_hex.len(), 2);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ADDITIONAL EDGE CASE TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_debug_level_equality() {
        assert_eq!(DebugLevel::None, DebugLevel::None);
        assert_eq!(DebugLevel::Basic, DebugLevel::Basic);
        assert_ne!(DebugLevel::None, DebugLevel::Basic);
    }

    #[test]
    fn test_runtime_config_clone() {
        let config1 = RuntimeConfig::new();
        let config2 = config1.clone();

        assert_eq!(config1.max_threads, config2.max_threads);
        assert_eq!(config1.is_mobile, config2.is_mobile);
        assert_eq!(config1.debug_level, config2.debug_level);
    }

    #[test]
    fn test_validation_results_clone() {
        let results1 = ValidationResults {
            input_validation: true,
            witness_validation: false,
            constraint_satisfaction: Some(true),
            details: vec!["test".to_string()],
        };

        let results2 = results1.clone();
        assert_eq!(results1.input_validation, results2.input_validation);
        assert_eq!(results1.witness_validation, results2.witness_validation);
    }

    #[test]
    fn test_circuit_stats_none_values() {
        let stats = CircuitStats {
            num_constraints: None,
            num_variables: None,
            synthesis_time_ms: None,
        };

        assert!(stats.num_constraints.is_none());
        assert!(stats.num_variables.is_none());
        assert!(stats.synthesis_time_ms.is_none());
    }

    #[test]
    fn test_proof_metadata_clone() {
        let metadata1 = ProofMetadata {
            generation_time_ms: 1000,
            platform: "test".to_string(),
            version: "1.0".to_string(),
        };

        let metadata2 = metadata1.clone();
        assert_eq!(metadata1.generation_time_ms, metadata2.generation_time_ms);
        assert_eq!(metadata1.platform, metadata2.platform);
    }

    #[test]
    fn test_age_snark_proof_clone() {
        let proof1 = AgeSnarkProofV2Extended {
            v: 2,
            vk: 1,
            rp_hash: [0; 32],
            cutoff: 6570,
            issuer_vk_bytes: [1; 32],
            cred_nullifier: [2; 32],
            direction: AgeDirection::Over,
            proof: vec![0xFF; 192],
            metadata: None,
            debug_info: None,
        };

        let proof2 = proof1.clone();
        assert_eq!(proof1.v, proof2.v);
        assert_eq!(proof1.cutoff, proof2.cutoff);
        assert_eq!(proof1.proof.len(), proof2.proof.len());
    }

    #[test]
    fn test_validation_boundary_36500() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 36500, // Exactly at boundary
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 36500, // Exactly at boundary
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        assert!(
            results.input_validation,
            "36500 should be valid (100 years)"
        );
    }

    #[test]
    fn test_validation_boundary_36501() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 36501, // Just over boundary
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 7300,
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        assert!(!results.input_validation, "36501 should be invalid");
    }

    #[test]
    fn test_validation_equal_timestamps() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 6570,
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 7300,
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 1000, // Equal timestamps
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        assert!(!results.witness_validation, "Equal timestamps should fail");
        assert!(results
            .details
            .iter()
            .any(|d| d.contains("Invalid timestamps")));
    }

    #[test]
    fn test_validation_results_debug() {
        let results = ValidationResults {
            input_validation: true,
            witness_validation: false,
            constraint_satisfaction: Some(false),
            details: vec!["error".to_string()],
        };

        let debug_str = format!("{results:?}");
        assert!(debug_str.contains("ValidationResults"));
        assert!(debug_str.contains("false"));
    }

    #[test]
    fn test_circuit_stats_debug() {
        let stats = CircuitStats {
            num_constraints: Some(1000),
            num_variables: Some(500),
            synthesis_time_ms: Some(100),
        };

        let debug_str = format!("{stats:?}");
        assert!(debug_str.contains("CircuitStats"));
        assert!(debug_str.contains("1000"));
    }

    #[test]
    fn test_proof_metadata_debug() {
        let metadata = ProofMetadata {
            generation_time_ms: 5000,
            platform: "linux".to_string(),
            version: "1.0.0".to_string(),
        };

        let debug_str = format!("{metadata:?}");
        assert!(debug_str.contains("ProofMetadata"));
        assert!(debug_str.contains("5000"));
        assert!(debug_str.contains("linux"));
    }

    #[test]
    fn test_age_snark_proof_debug() {
        let proof = AgeSnarkProofV2Extended {
            v: 2,
            vk: 1,
            rp_hash: [0; 32],
            cutoff: 6570,
            issuer_vk_bytes: [1; 32],
            cred_nullifier: [2; 32],
            direction: AgeDirection::Over,
            proof: vec![0; 10],
            metadata: None,
            debug_info: None,
        };

        let debug_str = format!("{proof:?}");
        assert!(debug_str.contains("AgeSnarkProofV2Extended"));
        assert!(debug_str.contains("6570"));
    }

    #[test]
    fn test_load_proving_key_very_small() {
        let small = vec![0x01, 0x02, 0x03];
        let result = load_proving_key(&small);
        assert!(result.is_err(), "Very small inputs should fail");
    }

    #[test]
    fn test_validation_age_check_warning() {
        let public = AgePublic {
            direction: AgeDirection::Over,
            cutoff_days: 6570,
            rp_hash: [0; 32],
            issuer_vk_bytes: [0; 32],
            cred_nullifier: [0; 32],
        };

        let witness = AgeWitness {
            dob_days: 7000, // dob > cutoff (will fail age check)
            r_bits: vec![false; 128],
            issuer_vk_bytes: [0; 32],
            sig_rj_bytes: vec![0; 64],
            v: 2,
            kid: vec![],
            c_bytes: [1; 32],
            iat: 1000,
            exp: 2000,
            schema: vec![],
        };

        let results = validate_inputs_detailed(&public, &witness);
        // Should pass validation but have warning in details
        assert!(results.details.iter().any(|d| d.contains("WARNING")));
    }

    #[test]
    fn test_age_snark_proof_full_serialization(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let proof = AgeSnarkProofV2Extended {
            v: 2,
            vk: 1,
            rp_hash: [42; 32],
            cutoff: 6570,
            issuer_vk_bytes: [99; 32],
            cred_nullifier: [77; 32],
            direction: AgeDirection::Over,
            proof: vec![0xFF; 192],
            metadata: Some(ProofMetadata {
                generation_time_ms: 5000,
                platform: "test".to_string(),
                version: "1.0.0".to_string(),
            }),
            debug_info: Some(DebugInfo {
                validation_results: ValidationResults {
                    input_validation: true,
                    witness_validation: true,
                    constraint_satisfaction: Some(true),
                    details: vec!["pass".to_string()],
                },
                circuit_stats: CircuitStats {
                    num_constraints: Some(1000),
                    num_variables: Some(500),
                    synthesis_time_ms: Some(100),
                },
                error_trace: vec![],
                full_debug_log: "logs".to_string(),
                public_inputs_hex: vec!["0a".to_string()],
            }),
        };

        let json = serde_json::to_string(&proof)?;
        let deserialized: AgeSnarkProofV2Extended = serde_json::from_str(&json)?;

        assert_eq!(deserialized.v, 2);
        assert_eq!(deserialized.vk, 1);
        assert_eq!(deserialized.cutoff, 6570);
        assert_eq!(deserialized.rp_hash, [42; 32]);
        assert_eq!(deserialized.issuer_vk_bytes, [99; 32]);
        assert_eq!(deserialized.cred_nullifier, [77; 32]);
        assert!(deserialized.metadata.is_some());
        assert!(deserialized.debug_info.is_some());
        Ok(())
    }
}
