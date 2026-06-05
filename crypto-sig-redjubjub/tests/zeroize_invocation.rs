//! Integration tests verifying that Zeroize/Drop impls on secret scalar material
//! are actually invoked. These kill surviving mutants where the zeroize body or
//! Drop impl is replaced with a no-op.
//!
//! The approach uses a `cfg(test)` atomic counter (`ZEROIZE_CALL_COUNT`) that the
//! production zeroize paths increment. Miri separately verifies that the volatile
//! writes actually zero memory; this file only checks invocation.

#![allow(clippy::expect_used)]

use provii_crypto_sig_redjubjub::ZEROIZE_CALL_COUNT;
use std::sync::atomic::Ordering;

/// Construct a valid 32-byte scalar (little-endian 7) that is non-zero and
/// within the Jubjub scalar field order.
fn valid_sk_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 7;
    b
}

#[test]
fn signing_key_drop_invokes_zeroize() {
    let before = ZEROIZE_CALL_COUNT.load(Ordering::Relaxed);
    {
        let sk = provii_crypto_sig_redjubjub::SigningKey::from_bytes(&valid_sk_bytes())
            .expect("valid scalar");
        // Prevent the compiler from optimising away the key entirely.
        let _ = sk.verification_key();
        // sk drops here, triggering Drop -> zeroize
    }
    let after = ZEROIZE_CALL_COUNT.load(Ordering::Relaxed);
    assert!(
        after > before,
        "SigningKey::drop must invoke zeroize (counter did not increment: before={before}, after={after})"
    );
}

#[test]
fn sign_cred_v2_zeroizes_nonce_scalar() {
    use provii_crypto_commons::CredMsgV2;

    let sk_bytes = valid_sk_bytes();
    let cred = CredMsgV2 {
        v: 2,
        kid: "test-key".to_string(),
        c: [1; 32],
        iat: 1_704_067_200,
        exp: 1_735_689_600,
        schema: "age18+".to_string(),
    };

    let before = ZEROIZE_CALL_COUNT.load(Ordering::Relaxed);
    let result = provii_crypto_sig_redjubjub::sign_cred_v2(&cred, &sk_bytes);
    let after = ZEROIZE_CALL_COUNT.load(Ordering::Relaxed);

    // sign_cred_v2 internally calls zeroize_jubjub_scalar (nonce) AND drops the
    // SigningKey (which calls SigningKey::zeroize). Expect at least 2 increments.
    assert!(result.is_ok(), "sign_cred_v2 should succeed");
    assert!(
        after >= before + 2,
        "sign_cred_v2 must zeroize both nonce and signing key (expected >=2 increments, got {})",
        after - before
    );
}

#[test]
fn explicit_zeroize_trait_increments_counter() {
    use zeroize::Zeroize;

    let before = ZEROIZE_CALL_COUNT.load(Ordering::Relaxed);
    {
        let mut sk = provii_crypto_sig_redjubjub::SigningKey::from_bytes(&valid_sk_bytes())
            .expect("valid scalar");
        sk.zeroize();
        // Explicit zeroize call: +1
        // Then drop calls zeroize again: +1
    }
    let after = ZEROIZE_CALL_COUNT.load(Ordering::Relaxed);
    assert!(
        after >= before + 2,
        "explicit zeroize + drop should yield >=2 increments (got {})",
        after - before
    );
}
