#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz target for DobAttestation JSON deserialization.
///
/// Exercises the serde path including the custom hex_bytes_32 and hex_bytes_64
/// deserializers with arbitrary byte sequences. The attestation's verify() path
/// is also exercised when deserialization succeeds to confirm it never panics
/// on malformed but parseable inputs.
fuzz_target!(|data: &[u8]| {
    // Attempt JSON deserialization from arbitrary bytes.
    let Ok(json_str) = std::str::from_utf8(data) else {
        return;
    };

    let attestation: Result<
        provii_crypto_commons::attestation::DobAttestation,
        _,
    > = serde_json::from_str(json_str);

    if let Ok(att) = attestation {
        // Verify fields are populated (must not panic).
        let _ = att.dob_days;
        let _ = att.issuer_id.len();
        let _ = att.timestamp;
        let _ = att.nonce;
        let _ = att.signature;
        let _ = att.nonce_hex();

        // Verify with a dummy key (will fail, but must not panic).
        let dummy_vk = ed25519_dalek::VerifyingKey::from_bytes(&[
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
            0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3,
            0x23, 0x91, 0x87, 0x14, 0xe4, 0x0d, 0x8f, 0x7b, 0x05, 0x16,
        ]);
        if let Ok(vk) = dummy_vk {
            let _ = att.verify(&vk);
            let _ = att.verify_with_timestamp(&vk, att.timestamp);
        }

        // Compute message bytes (must not panic).
        let _ = provii_crypto_commons::attestation::DobAttestation::compute_message_bytes(
            att.dob_days,
            &att.issuer_id,
            att.timestamp,
            &att.nonce,
            att.session_id.as_deref(),
            att.client_id.as_deref(),
        );
    }
});
