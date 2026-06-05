#![no_main]

use libfuzzer_sys::fuzz_target;
use provii_crypto_commons::cred_v2_prehash_bytes;
use provii_crypto_commit::pedersen_nullifier;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 (commitment) + 8 (iat) + 8 (exp) + 1 (v) + 1 (kid_len) + 1 (schema_len) = 51 bytes
    if data.len() < 51 {
        return;
    }

    let v = data[0];
    let c = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data[1..33]);
        arr
    };
    let iat = u64::from_le_bytes([
        data[33], data[34], data[35], data[36], data[37], data[38], data[39], data[40],
    ]);
    let exp = u64::from_le_bytes([
        data[41], data[42], data[43], data[44], data[45], data[46], data[47], data[48],
    ]);

    let kid_len = (data[49] as usize) % 64;
    let schema_len = (data[50] as usize) % 64;

    let remaining = &data[51..];
    if remaining.len() < kid_len.saturating_add(schema_len) {
        return;
    }

    let kid = core::str::from_utf8(&remaining[..kid_len]).unwrap_or("fallback_kid__");
    let schema_start = kid_len;
    let schema =
        core::str::from_utf8(&remaining[schema_start..schema_start + schema_len]).unwrap_or("schema______");

    // Test 1: cred_v2_prehash_bytes with fuzzed inputs
    let result = cred_v2_prehash_bytes(v, kid, &c, iat, exp, schema);
    if let Ok(ref prehash) = result {
        // Determinism
        let result2 = cred_v2_prehash_bytes(v, kid, &c, iat, exp, schema);
        assert_eq!(prehash, result2.as_ref().unwrap());

        // Different version byte produces different prehash
        let result_diff_v = cred_v2_prehash_bytes(v.wrapping_add(1), kid, &c, iat, exp, schema);
        if let Ok(ref diff) = result_diff_v {
            assert_ne!(prehash, diff);
        }
    }

    // Test 2: pedersen_nullifier determinism and sensitivity
    let nullifier = pedersen_nullifier(&c);
    assert_eq!(nullifier.len(), 32);

    let nullifier2 = pedersen_nullifier(&c);
    assert_eq!(nullifier, nullifier2);

    // Single byte change in commitment should change nullifier
    let mut c_modified = c;
    c_modified[0] = c_modified[0].wrapping_add(1);
    let nullifier_modified = pedersen_nullifier(&c_modified);
    assert_ne!(nullifier, nullifier_modified);
});
