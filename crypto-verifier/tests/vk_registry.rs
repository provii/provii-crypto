//! Integration test proving `init_with_vk_registry` actually loads VK bytes into
//! the global registry. Lives in its own file because `VK_REGISTRY` is a
//! `OnceCell` that cannot be reset after initialisation.
//!
//! The surviving mutant replaces the entire function body with `Ok(())`, meaning
//! the VK is never stored. This test kills that mutant by calling
//! `verify_age_snark` after init and asserting the error is about an invalid
//! proof format (VK present, proof bytes garbage) rather than a missing VK.

#![allow(clippy::expect_used)]

use provii_crypto_commons::Error;
use provii_crypto_verifier::{init_with_vk_registry, verify_age_snark};

const VK_ID: u32 = 914_153_247;

/// The real age verifying key binary, compiled into the test at build time.
static VK_BYTES: &[u8] = include_bytes!("../../age_vk.914153247.bin");

#[test]
fn init_with_vk_registry_actually_loads_vk() {
    // Initialise the registry with the real VK binary.
    init_with_vk_registry(vec![(VK_ID, VK_BYTES.to_vec())])
        .expect("init_with_vk_registry should succeed with valid VK bytes");

    // Attempt verification with garbage proof bytes. The VK must be present
    // for the verifier to get past the registry lookup and reach the proof
    // deserialisation step.
    let garbage_proof = vec![0xDE; 192];
    let result = verify_age_snark(
        &garbage_proof,
        true,
        6570,
        [0xAA; 32],
        [0xBB; 32],
        [0xCC; 32],
        VK_ID,
    );

    // With the real function: VK is loaded, proof parsing fails -> InvalidFormat.
    // With the mutant (body replaced by Ok(())): VK_REGISTRY is never set ->
    // VerifierNotInitialized.
    let err = result.expect_err("garbage proof bytes must not verify successfully");
    assert_eq!(
        err,
        Error::InvalidFormat,
        "expected InvalidFormat (VK present, bad proof), got {err:?} \
         which suggests the VK was never loaded into the registry"
    );
}
