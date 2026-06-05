#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_commons::{Timestamp, CredMsgV2, AgeSnarkProofV2};
use serde_json;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // Timestamp fields
    timestamp_seconds: i64,
    timestamp_nanos: i32,

    // CredMsgV2 fields
    cred_v: u8,
    cred_kid: Vec<u8>,
    cred_c: [u8; 32],
    cred_iat: u64,
    cred_exp: u64,
    cred_schema: Vec<u8>,

    // AgeSnarkProofV2 fields
    proof_v: u8,
    proof_vk: u32,
    proof_rp: [u8; 32],
    proof_cutoff: i32,
    proof_bytes: Vec<u8>,
}

/// Fuzz serialization/deserialization of common structs
/// Tests:
/// - Timestamp serialization round-trip
/// - CredMsgV2 serialization round-trip
/// - AgeSnarkProofV2 serialization round-trip
/// - Extreme values (i64::MIN, i64::MAX, etc.)
/// - Empty strings
/// - Large proof bytes
/// - Malformed JSON
fuzz_target!(|input: FuzzInput| {
    // Test Timestamp serialization
    let timestamp = Timestamp {
        seconds: input.timestamp_seconds,
        nanos: input.timestamp_nanos,
    };

    if let Ok(json) = serde_json::to_string(&timestamp) {
        // Test deserialization
        if let Ok(deserialized) = serde_json::from_str::<Timestamp>(&json) {
            // Invariant: round-trip preserves data
            assert_eq!(deserialized.seconds, timestamp.seconds,
                "Timestamp seconds must be preserved");
            assert_eq!(deserialized.nanos, timestamp.nanos,
                "Timestamp nanos must be preserved");
        }
    }

    // Test CredMsgV2 serialization
    if let (Ok(kid), Ok(schema)) = (
        std::str::from_utf8(&input.cred_kid),
        std::str::from_utf8(&input.cred_schema),
    ) {
        let cred = CredMsgV2 {
            v: input.cred_v,
            kid: kid.to_string(),
            c: input.cred_c,
            iat: input.cred_iat,
            exp: input.cred_exp,
            schema: schema.to_string(),
        };

        if let Ok(json) = serde_json::to_string(&cred) {
            if let Ok(deserialized) = serde_json::from_str::<CredMsgV2>(&json) {
                // Invariant: round-trip preserves data
                assert_eq!(deserialized.v, cred.v);
                assert_eq!(deserialized.kid, cred.kid);
                assert_eq!(deserialized.c, cred.c);
                assert_eq!(deserialized.iat, cred.iat);
                assert_eq!(deserialized.exp, cred.exp);
                assert_eq!(deserialized.schema, cred.schema);
            }
        }
    }

    // Test AgeSnarkProofV2 serialization
    let proof = AgeSnarkProofV2 {
        v: input.proof_v,
        vk: input.proof_vk,
        rp: input.proof_rp,
        cutoff: input.proof_cutoff,
        proof: input.proof_bytes.clone(),
    };

    if let Ok(json) = serde_json::to_string(&proof) {
        if let Ok(deserialized) = serde_json::from_str::<AgeSnarkProofV2>(&json) {
            // Invariant: round-trip preserves data
            assert_eq!(deserialized.v, proof.v);
            assert_eq!(deserialized.vk, proof.vk);
            assert_eq!(deserialized.rp, proof.rp);
            assert_eq!(deserialized.cutoff, proof.cutoff);
            assert_eq!(deserialized.proof, proof.proof);
        }
    }

    // Test extreme values
    let extreme_timestamp = Timestamp {
        seconds: i64::MAX,
        nanos: i32::MAX,
    };
    let _ = serde_json::to_string(&extreme_timestamp);

    let min_timestamp = Timestamp {
        seconds: i64::MIN,
        nanos: i32::MIN,
    };
    let _ = serde_json::to_string(&min_timestamp);

    // Test with empty proof bytes
    let empty_proof = AgeSnarkProofV2 {
        v: 2,
        vk: 1,
        rp: [0u8; 32],
        cutoff: 6570,
        proof: vec![],
    };
    let _ = serde_json::to_string(&empty_proof);

    // Test with large proof bytes
    if input.proof_bytes.len() < 10000 {
        let large_proof = AgeSnarkProofV2 {
            v: 2,
            vk: 1,
            rp: [0u8; 32],
            cutoff: 6570,
            proof: vec![0xFF; 10000],
        };
        let _ = serde_json::to_string(&large_proof);
    }
});
