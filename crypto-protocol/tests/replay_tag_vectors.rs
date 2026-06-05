//! Golden-vector test for `compute_replay_tag`.
//!
//! Pins the concatenation and encoding logic against a known input/output pair.
//! Any mutation to the separator byte or slice ordering will fail.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

#[test]
fn replay_tag_known_vector() {
    let origin_hash = [0x01u8; 4];
    let nonce = [0x02u8; 4];

    let tag = provii_crypto_protocol::compute_replay_tag(&origin_hash, &nonce);

    // Expected concatenation: [0x01,0x01,0x01,0x01, 0x3A, 0x02,0x02,0x02,0x02]
    // 0x3A is b':'
    let expected = URL_SAFE_NO_PAD.encode([0x01, 0x01, 0x01, 0x01, 0x3A, 0x02, 0x02, 0x02, 0x02]);
    assert_eq!(tag, expected);
}

#[test]
fn replay_tag_empty_inputs() {
    let tag = provii_crypto_protocol::compute_replay_tag(&[], &[]);

    // Empty origin + ':' + empty nonce = just the separator byte.
    let expected = URL_SAFE_NO_PAD.encode([0x3A]);
    assert_eq!(tag, expected);
}

#[test]
fn replay_tag_separator_present() {
    // Verifies the ':' separator is always injected between origin_hash and nonce.
    let origin_hash = [0xAAu8; 2];
    let nonce = [0xBBu8; 2];

    let tag = provii_crypto_protocol::compute_replay_tag(&origin_hash, &nonce);
    let expected = URL_SAFE_NO_PAD.encode([0xAA, 0xAA, 0x3A, 0xBB, 0xBB]);
    assert_eq!(tag, expected);
}

#[test]
fn replay_tag_32_byte_inputs() {
    let origin_hash = [0x42u8; 32];
    let nonce = [0x7Fu8; 32];

    let tag = provii_crypto_protocol::compute_replay_tag(&origin_hash, &nonce);

    let mut concat = Vec::with_capacity(65);
    concat.extend_from_slice(&[0x42u8; 32]);
    concat.push(b':');
    concat.extend_from_slice(&[0x7Fu8; 32]);

    let expected = URL_SAFE_NO_PAD.encode(&concat);
    assert_eq!(tag, expected);
}
