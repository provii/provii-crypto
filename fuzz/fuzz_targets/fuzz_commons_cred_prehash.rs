#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_commons::cred_v2_prehash_bytes;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    v: u8,
    kid: Vec<u8>,
    c: [u8; 32],
    iat: u64,
    exp: u64,
    schema: Vec<u8>,
}

/// Fuzz cred_v2_prehash_bytes function
/// Tests:
/// - Various version bytes
/// - Empty/long kid strings
/// - Empty/long schema strings
/// - Various commitment values
/// - Extreme timestamp values
/// - Determinism
/// - Domain separation tag presence
fuzz_target!(|input: FuzzInput| {
    if let (Ok(kid), Ok(schema)) = (
        std::str::from_utf8(&input.kid),
        std::str::from_utf8(&input.schema),
    ) {
        let result = match cred_v2_prehash_bytes(
            input.v,
            kid,
            &input.c,
            input.iat,
            input.exp,
            schema,
        ) {
            Ok(r) => r,
            Err(provii_crypto_commons::Error::FieldTooLong) => {
                // Expected: kid or schema exceeds 255 bytes
                assert!(kid.len() > 255 || schema.len() > 255);
                return;
            }
            Err(e) => panic!("unexpected error: {:?}", e),
        };

        // Invariant: result is never empty
        assert!(!result.is_empty(), "Result must not be empty");

        // Invariant: result starts with domain separation tag
        assert!(result.starts_with(provii_crypto_commons::CRED_DST),
            "Result must start with CRED_DST");

        // Invariant: determinism
        let result2 = cred_v2_prehash_bytes(
            input.v,
            kid,
            &input.c,
            input.iat,
            input.exp,
            schema,
        ).unwrap();
        assert_eq!(result, result2, "Function must be deterministic");

        // Invariant: different versions produce different outputs
        let v2 = input.v.wrapping_add(1);
        let result_diff_v = cred_v2_prehash_bytes(
            v2,
            kid,
            &input.c,
            input.iat,
            input.exp,
            schema,
        ).unwrap();
        assert_ne!(result, result_diff_v, "Different versions must produce different outputs");

        // Invariant: different commitments produce different outputs
        let mut c2 = input.c;
        c2[0] = c2[0].wrapping_add(1);
        let result_diff_c = cred_v2_prehash_bytes(
            input.v,
            kid,
            &c2,
            input.iat,
            input.exp,
            schema,
        ).unwrap();
        assert_ne!(result, result_diff_c, "Different commitments must produce different outputs");

        // Test with empty strings
        let result_empty = cred_v2_prehash_bytes(input.v, "", &input.c, input.iat, input.exp, "").unwrap();
        assert!(!result_empty.is_empty());
        assert!(result_empty.starts_with(provii_crypto_commons::CRED_DST));

        // Test with extreme timestamp values
        let _ = cred_v2_prehash_bytes(input.v, kid, &input.c, 0, 0, schema);
        let _ = cred_v2_prehash_bytes(input.v, kid, &input.c, u64::MAX, u64::MAX, schema);

        // Test length prefixing is correct
        // kid length should be at position DST.len() + 1
        let dst_len = provii_crypto_commons::CRED_DST.len();
        assert_eq!(result[dst_len + 1], kid.len() as u8, "kid length prefix incorrect");
    }
});
