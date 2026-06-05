//! Golden-vector tests for `pedersen_nullifier`.
//!
//! These vectors are pinned to the sapling-crypto 0.5 Pedersen generators.
//! Any mutation to the bit-decomposition logic (shift direction, mask operator,
//! comparison inversion) produces a completely different hash output, so a
//! single exact-match assertion kills all surviving mutants from cargo-mutants.

#[test]
fn golden_vector_0x42_repeated() {
    let input = [0x42u8; 32];
    let result = provii_crypto_commit::pedersen_nullifier(&input);

    // Computed with sapling-crypto 0.5, provii.nullifier.pedersen.v0 DST.
    let expected: [u8; 32] = [
        0xd9, 0x41, 0x1a, 0x79, 0x5b, 0xd0, 0x30, 0xd7, 0xdc, 0xb5, 0x8e, 0x08, 0xf1, 0xd8, 0x16,
        0xd7, 0x0a, 0xbf, 0x33, 0x78, 0xec, 0xb6, 0xce, 0x40, 0xac, 0xfb, 0x58, 0xf3, 0xd7, 0xf5,
        0x15, 0xbe,
    ];

    assert_eq!(
        result, expected,
        "pedersen_nullifier([0x42; 32]) output changed"
    );
}

#[test]
fn golden_vector_all_zeros() {
    let input = [0x00u8; 32];
    let result = provii_crypto_commit::pedersen_nullifier(&input);

    // Computed with sapling-crypto 0.5, provii.nullifier.pedersen.v0 DST.
    let expected: [u8; 32] = [
        0xbf, 0x91, 0x7a, 0xf8, 0xa9, 0x68, 0xea, 0xef, 0x1e, 0xb6, 0x07, 0x64, 0x9b, 0xb6, 0x01,
        0x10, 0x54, 0xe7, 0x7f, 0xec, 0x83, 0xe6, 0xbe, 0xc2, 0x61, 0x60, 0x60, 0xb0, 0x93, 0xa9,
        0xdf, 0xca,
    ];

    assert_eq!(
        result, expected,
        "pedersen_nullifier([0x00; 32]) output changed"
    );
}
