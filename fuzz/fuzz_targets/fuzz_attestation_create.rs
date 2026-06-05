#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use ed25519_dalek::SigningKey;
use provii_crypto_commons::attestation::DobAttestation;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    dob_days: i32,
    issuer_id_bytes: Vec<u8>,
    timestamp: u64,
    nonce: [u8; 32],
    signing_key_bytes: [u8; 32],
}

fuzz_target!(|input: FuzzInput| {
    let issuer_id = match core::str::from_utf8(&input.issuer_id_bytes) {
        Ok(s) if !s.is_empty() => s,
        _ => return,
    };

    let signing_key = SigningKey::from_bytes(&input.signing_key_bytes);
    let verifying_key = signing_key.verifying_key();

    // Test create + verify round-trip
    let attestation = match DobAttestation::create(
        input.dob_days,
        issuer_id,
        input.timestamp,
        input.nonce,
        &signing_key,
    ) {
        Ok(att) => att,
        Err(_) => return,
    };

    // Signature must verify against the correct key
    assert!(
        attestation.verify(&verifying_key).is_ok(),
        "Fresh attestation must verify against its own key"
    );

    // Determinism: create again with same inputs
    let attestation2 = match DobAttestation::create(
        input.dob_days,
        issuer_id,
        input.timestamp,
        input.nonce,
        &signing_key,
    ) {
        Ok(att) => att,
        Err(_) => return,
    };
    assert_eq!(attestation.signature, attestation2.signature);

    // Wrong key must not verify
    let wrong_key_bytes = {
        let mut b = input.signing_key_bytes;
        b[0] = b[0].wrapping_add(1);
        b
    };
    let wrong_signing_key = SigningKey::from_bytes(&wrong_key_bytes);
    let wrong_verifying_key = wrong_signing_key.verifying_key();
    assert!(
        attestation.verify(&wrong_verifying_key).is_err(),
        "Attestation must not verify against wrong key"
    );

    // JSON round-trip must preserve fields
    if let Ok(json) = serde_json::to_string(&attestation) {
        if let Ok(deserialized) = serde_json::from_str::<DobAttestation>(&json) {
            assert_eq!(deserialized.dob_days, input.dob_days);
            assert_eq!(deserialized.issuer_id, issuer_id);
            assert_eq!(deserialized.timestamp, input.timestamp);
            assert_eq!(deserialized.nonce, input.nonce);
            assert_eq!(deserialized.signature, attestation.signature);

            // Deserialized attestation must still verify
            assert!(deserialized.verify(&verifying_key).is_ok());
        }
    }
});
