#![allow(clippy::expect_used)]

use provii_crypto_commons::constants::{bias_for_circuit, unbias_from_circuit};

#[test]
fn known_vectors_bias() {
    assert_eq!(bias_for_circuit(0), 0x8000_0000);
    assert_eq!(bias_for_circuit(-1), 0x7FFF_FFFF);
    assert_eq!(bias_for_circuit(1), 0x8000_0001);
    assert_eq!(bias_for_circuit(i32::MIN), 0);
    assert_eq!(bias_for_circuit(i32::MAX), u32::MAX);
}

#[test]
fn known_vectors_unbias() {
    assert_eq!(unbias_from_circuit(0x8000_0000), 0);
    assert_eq!(unbias_from_circuit(0), i32::MIN);
    assert_eq!(unbias_from_circuit(0x7FFF_FFFF), -1);
    assert_eq!(unbias_from_circuit(u32::MAX), i32::MAX);
}

#[test]
fn roundtrip() {
    let cases: &[i32] = &[0, 1, -1, 100, -100, i32::MIN, i32::MAX, 7300];
    for &x in cases {
        assert_eq!(
            unbias_from_circuit(bias_for_circuit(x)),
            x,
            "round-trip failed for {x}"
        );
    }
}

#[test]
fn order_preservation() {
    let low = bias_for_circuit(-3652);
    let mid = bias_for_circuit(0);
    let high = bias_for_circuit(13880);
    assert!(
        low < mid,
        "expected bias(-3652) < bias(0), got {low} vs {mid}"
    );
    assert!(
        mid < high,
        "expected bias(0) < bias(13880), got {mid} vs {high}"
    );
}
