# Provii Cryptographic Protocol Specification

**Version**: 1.0.0
**Date**: 2026-02-03
**Status**: Draft
**Implementation**: `provii-crypto` workspace (Rust)

This document specifies the cryptographic constructions used in the Provii privacy-preserving age verification protocol. It is derived directly from the source code in the `provii-crypto` workspace and serves as the formal reference for auditing and validation.

---

## Table of Contents

1. [Notation and Conventions](#1-notation-and-conventions)
2. [Curve Parameters](#2-curve-parameters)
3. [Domain Separation Tags](#3-domain-separation-tags)
4. [System Constants](#4-system-constants)
5. [Hash Function Specifications](#5-hash-function-specifications)
6. [RedJubjub Signature Scheme](#6-redjubjub-signature-scheme)
7. [Pedersen Commitment Scheme](#7-pedersen-commitment-scheme)
8. [Ed25519 Attestation Scheme](#8-ed25519-attestation-scheme)
9. [Age Verification Circuit (R1CS)](#9-age-verification-circuit-r1cs)
10. [Prover and Verifier Protocols](#10-prover-and-verifier-protocols)
11. [Protocol Layer](#11-protocol-layer)
12. [Security Properties](#12-security-properties)
13. [Deviations from Zcash](#13-deviations-from-zcash)

---

## 1. Notation and Conventions

| Symbol | Meaning |
|--------|---------|
| `\|\|` | Byte concatenation |
| `LE(x, n)` | Little-endian encoding of integer `x` in `n` bytes |
| `BE(x, n)` | Big-endian encoding of integer `x` in `n` bytes |
| `bits_le(x, n)` | Little-endian bit decomposition of `x` into `n` bits |
| `Fr_J` | Scalar field of the Jubjub curve (~251 bits) |
| `Fr_B` | Scalar field of BLS12-381 (~255 bits) |
| `G` | Spending key generator on the Jubjub curve |
| `[s]P` | Scalar multiplication of point `P` by scalar `s` |
| `H_b2s(pers, data)` | Blake2s-256 with personalization parameter `pers` and input `data` |
| `H_b2s(data)` | Blake2s-256 (no personalization) over `data` |
| `H_ped(pers, bits)` | Zcash Sapling Pedersen hash with personalization `pers` over bit vector `bits` |
| `H_sha256(data)` | SHA-256 over `data` |
| `wide_reduce_J(x)` | Reduce 64-byte value `x` into `Fr_J` via `from_bytes_wide` |
| `compress(P)` | Compressed encoding of Jubjub point `P` (32 bytes) |

### Byte Ordering

Byte ordering varies by construction and is specified explicitly for each operation:
- **Credential prehash** (Section 6.2): `iat` and `exp` use **big-endian**
- **Ed25519 attestation** (Section 8.2): `dob_days` and `timestamp` use **little-endian**
- **Circuit public inputs** (Section 9.3): All values use **little-endian** bit decomposition
- **Issuance consent** (Section 11.7): `consent_time` and `terms_version` use **little-endian**
- **Jubjub scalars and points**: Canonical **little-endian** representations as defined by the `jubjub` crate

---

## 2. Curve Parameters

### 2.1 BLS12-381 (Pairing Curve)

Used as the SNARK backend for Groth16 proofs.

| Parameter | Value |
|-----------|-------|
| Security level | 128-bit |
| Scalar field order `r` | `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` |
| Scalar field bits | ~255 bits |
| Library | `bls12_381 = "0.8"` |

### 2.2 Jubjub (Twisted Edwards Curve)

Used for commitments and signatures. Embedded in BLS12-381's scalar field.

| Parameter | Value |
|-----------|-------|
| Security level | 128-bit |
| Curve equation | `-u^2 + v^2 = 1 + d * u^2 * v^2` (twisted Edwards) |
| Scalar field order `r_J` | `0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7` |
| Scalar field bits | ~251 bits |
| Library | `jubjub = "0.10"` |

### 2.3 Spending Key Generator

All RedJubjub operations use a fixed generator point `G` on the Jubjub curve. This is the same generator used in the circuit for signature verification.

```
G = SubgroupPoint::from_bytes([
    0x30, 0xb5, 0xf2, 0xaa, 0xad, 0x32, 0x56, 0x30,
    0xbc, 0xdd, 0xdb, 0xce, 0x4d, 0x67, 0x65, 0x6d,
    0x05, 0xfd, 0x1c, 0xc2, 0xd0, 0x37, 0xbb, 0x53,
    0x75, 0xb6, 0xe9, 0x6d, 0x9e, 0x01, 0xa1, 0x57,
])

Hex: 30b5f2aaad325630bcdddbce4d67656d05fd1cc2d037bb5375b6e96d9e01a157
```

This is the compressed Edwards-form encoding (v-coordinate with sign bit). The point MUST decode into the prime-order subgroup of Jubjub.

### 2.4 Ed25519 (Attestation Curve)

Used for issuer attestation signatures (separate from the ZK system).

| Parameter | Value |
|-----------|-------|
| Security level | 128-bit |
| Library | `ed25519-dalek = "2.1"` |
| Key size | 32-byte signing key, 32-byte verifying key |
| Signature size | 64 bytes |

---

## 3. Domain Separation Tags

All cryptographic operations use distinct domain separation tags to prevent cross-protocol attacks. No two operations share a tag.

### 3.1 Credential and Proof Tags

| Constant | Value (UTF-8 bytes) | Length | Usage |
|----------|---------------------|--------|-------|
| `CRED_DST` | `provii.cred.v0` | 14 | Credential v2 prehash prefix |
| `CHALLENGE_DST` | `provii.challenge.v0` | 19 | Challenge binding |
| `NULLIFIER_DST` | `provii.nullifier.pedersen.v0` | 28 | Nullifier domain (Pedersen-based nullifier computation) |

### 3.2 Commitment Tags

| Constant | Value (UTF-8 bytes) | Length | Usage |
|----------|---------------------|--------|-------|
| Nullifier DST | `provii.nullifier.pedersen.v0` | 28 | Nullifier computation (local to `crypto-commit`) |

### 3.3 Signature Tags

| Constant | Value (UTF-8 bytes) | Length | Usage |
|----------|---------------------|--------|-------|
| `PROVII_RJ_PERSONALIZATION` | `ProviiRJ` | 8 | Blake2s personalization for RedJubjub challenge |
| `PROVII_RJ_NONCE_TAG` | `ProviiRJ/nonce` | 14 | Prefix for RedJubjub nonce derivation |

> **Code constant names**: In `crypto-commons/src/constants.rs` these are exported as `REDJUBJUB_PERSONALIZATION` and `REDJUBJUB_NONCE_TAG`. The `crypto-sig-redjubjub` crate re-binds them to the local aliases `PROVII_RJ_PERSONALIZATION` and `PROVII_RJ_NONCE_TAG`.

### 3.4 Attestation Tags

| Constant | Value (UTF-8 bytes) | Length | Usage |
|----------|---------------------|--------|-------|
| `DOB_ATTESTATION_DST` | `provii.attestation.dob.v0` | 25 | Ed25519 DOB attestation message prefix |

### 3.5 Pedersen Personalizations (from Zcash Sapling)

| Personalization | Zcash Constant | Usage in Provii |
|-----------------|----------------|-----------------|
| `NoteCommitment` | `Zcash_PH` | DOB Pedersen commitment |
| `MerkleTree(0)` | `Zcash_PH` (depth 0) | Nullifier computation |

### 3.6 Protocol Tags

| Constant | Value (UTF-8 bytes) | Length | Usage |
|----------|---------------------|--------|-------|
| `ISSUANCE_CONSENT_DST` | `provii:issuance-consent:v0` | 26 | Domain prefix for issuance consent hash (see section 11.7) |

---

## 4. System Constants

### 4.1 Time Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `CHALLENGE_EXPIRY_SECONDS` | 300 | Challenge validity window (5 minutes) |
| `CLOCK_SKEW_TOLERANCE_SECONDS` | 30 | Clock drift allowance |
| `REPLAY_WINDOW_SECONDS` | 600 | Replay protection window (10 minutes) |
| `SESSION_TIMEOUT_MS` | 120,000 | Session timeout (2 minutes) |
| `ATTESTATION_MAX_AGE_SECONDS` | 3,600 | Ed25519 attestation validity (1 hour) |

**Invariants**:
- `CHALLENGE_EXPIRY_SECONDS > CLOCK_SKEW_TOLERANCE_SECONDS`
- `REPLAY_WINDOW_SECONDS >= CHALLENGE_EXPIRY_SECONDS`

### 4.2 Size Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `CREDENTIAL_ID_SIZE` | 32 bytes | Credential identifier length |
| `MAX_CREDENTIAL_SIZE` | 8,192 bytes | Maximum serialized credential |
| `MAX_RANGE_PROOF_SIZE` | 1,024 bytes | Maximum range proof |
| `MAX_CREDENTIAL_SIGNATURE_SIZE` | 512 bytes | Maximum credential signature |
| `MAX_WALLET_SIGNATURE_SIZE` | 128 bytes | Maximum wallet signature |
| `NONCE_SIZE` | 32 bytes | Nonce length |

---

## 5. Hash Function Specifications

### 5.1 Blake2s-256 with Personalization Parameter

Used for the RedJubjub challenge hash. This uses the Blake2s **personalization** field (8 bytes), NOT a prefix.

**Library**: `blake2s_simd::Params`

```
H_b2s(pers, data):
    Params::new()
        .hash_length(32)
        .personal(pers)          // 8-byte personalization
        .to_state()
        .update(data)
        .finalize()
    → 32 bytes
```

**Distinction**: The personalization parameter is part of the Blake2s parameter block and is processed differently from prepending a tag to the data. This is the construction specified in RFC 7693.

### 5.2 Blake2s-256 with Prefix Domain Separation

Used for nonce derivation, credential prehashing, and attestation messages. This prepends the domain tag directly to the hash input.

**Library**: `blake2::Blake2s256` (Digest trait)

```
H_b2s_prefix(tag, data):
    Blake2s256::new()
        .update(tag)
        .update(data)
        .finalize()
    → 32 bytes
```

### 5.3 SHA-256

Used for challenge hashing and PKCE (RFC 7636).

**Library**: `sha2::Sha256`

### 5.4 Zcash Sapling Pedersen Hash

Used for commitments and nullifiers. This is the windowed Pedersen hash from Zcash Sapling with fixed generator tables.

**Library**: `sapling_crypto::pedersen_hash::pedersen_hash`

```
H_ped(personalization, bits):
    pedersen_hash(personalization, bits.into_iter())
    → SubgroupPoint (compressed to 32 bytes)
```

The generator points are deterministically derived from the personalization tag per the Zcash Sapling specification (section 5.4.1.7).

---

## 6. RedJubjub Signature Scheme

**WARNING**: This is a **custom scheme** inspired by RedJubjub. It is **NOT** Zcash-compatible. See [Section 13](#13-deviations-from-zcash) for explicit differences.

### 6.1 Key Generation

```
KeyGen():
    sk ← random element of Fr_J (via CSPRNG, reject zero)
    VK = [sk]G
    return (sk, VK)

Encoding:
    sk_bytes = sk.to_bytes()        → 32 bytes (canonical LE)
    vk_bytes = compress(VK)         → 32 bytes (compressed Edwards)
```

**Validation on deserialization**:
- `sk`: Must be canonical representation in `Fr_J`, must not be zero
- `VK`: Must decode to a point in the prime-order subgroup of Jubjub

### 6.2 Credential Prehash

Before signing, a credential is serialized into a canonical byte string:

```
CredPrehash(v, kid, c, iat, exp, schema):
    kid_b = kid.as_bytes()
    sch_b = schema.as_bytes()
    return CRED_DST              // "provii.cred.v0" (14 bytes)
        || byte(v)                   // version (1 byte)
        || byte(len(kid_b))         // kid length prefix (1 byte)
        || kid_b                     // kid bytes (variable)
        || c                         // commitment (32 bytes)
        || BE(iat, 8)               // issued-at (8 bytes, big-endian)
        || BE(exp, 8)               // expires-at (8 bytes, big-endian)
        || byte(len(sch_b))         // schema length prefix (1 byte)
        || sch_b                     // schema bytes (variable)
```

**Note**: The serialization format supports variable-length `kid` and `schema` via length prefixes. However, the circuit (Section 9) constrains `kid` to exactly 14 bytes and `schema` to exactly 12 bytes. Off-circuit signing accepts any length, but only credentials with these exact sizes can be proven in-circuit.

### 6.3 Nonce Derivation

Deterministic nonce generation prevents nonce reuse attacks:

```
NonceDerive(sk_bytes, msg_hash):
    digest = H_b2s_prefix("ProviiRJ/nonce", sk_bytes || msg_hash)
    wide = digest || 0x00^32         // pad to 64 bytes
    return wide_reduce_J(wide)       // reduce into Fr_J
```

The nonce is derived deterministically from the signing key and message, similar to RFC 6979 but using Blake2s-256.

### 6.4 Challenge Hash

```
ChallengeHash(R_bytes, VK_bytes, msg_hash):
    hash = H_b2s("ProviiRJ", R_bytes || VK_bytes || msg_hash)
    wide = hash || 0x00^32           // pad to 64 bytes
    return wide_reduce_J(wide)       // reduce into Fr_J
```

**CRITICAL**: This uses Blake2s **personalization** (Section 5.1), NOT prefix domain separation. The 8-byte string `"ProviiRJ"` is set as the Blake2s personalization parameter.

### 6.5 Sign (No RP Binding)

```
Sign(sk, cred):
    prehash = CredPrehash(cred.v, cred.kid, cred.c, cred.iat, cred.exp, cred.schema)
    msg_hash = H_b2s(prehash)              // Blake2s256 of full prehash (DST already in prehash)
    nonce = NonceDerive(sk_bytes, msg_hash)
    R = [nonce]G
    VK = [sk]G
    c = ChallengeHash(compress(R), compress(VK), msg_hash)
    s = nonce + c * sk                     // in Fr_J
    return (R, s)

Encoding:
    signature = compress(R) || s.to_bytes()  → 64 bytes
```

### 6.6 Verify (No RP Binding)

```
Verify(VK, cred, (R, s)):
    prehash = CredPrehash(cred.v, cred.kid, cred.c, cred.iat, cred.exp, cred.schema)
    msg_hash = H_b2s(prehash)
    c = ChallengeHash(compress(R), compress(VK), msg_hash)
    return [s]G == R + [c]VK
```

### 6.7 Sign with RP Binding

**Note**: This RP-bound signature variant is used for off-circuit verification scenarios. The in-circuit proof path (Section 9.5 Step 8) uses the non-RP-bound signature (Section 6.5) and binds to the RP via a separate public input instead.

When binding the signature to a relying party challenge:

```
SignWithRP(sk, cred, rp):
    prehash = CredPrehash(cred.v, cred.kid, cred.c, cred.iat, cred.exp, cred.schema)
    cred_hash = H_b2s(prehash)
    final_hash = H_b2s(cred_hash || rp)           // bind to RP
    nonce = NonceDerive(sk_bytes, final_hash)
    R = [nonce]G
    VK = [sk]G
    c = ChallengeHash(compress(R), compress(VK), final_hash)
    s = nonce + c * sk
    return (R, s)
```

### 6.8 Verify with RP Binding

```
VerifyWithRP(VK, cred, rp, (R, s)):
    prehash = CredPrehash(cred.v, cred.kid, cred.c, cred.iat, cred.exp, cred.schema)
    cred_hash = H_b2s(prehash)
    final_hash = H_b2s(cred_hash || rp)
    c = ChallengeHash(compress(R), compress(VK), final_hash)
    return [s]G == R + [c]VK
```

### 6.9 Key Zeroization

The `SigningKey` struct implements `Zeroize` and `Drop`. On drop, the secret scalar memory is overwritten with zeros using volatile writes (via the `zeroize` crate) to prevent compiler optimization from removing the zeroing.

---

## 7. Pedersen Commitment Scheme

### 7.1 Commitment

Hides the date of birth using Zcash Sapling's Pedersen hash with the `NoteCommitment` personalization.

```
PedersenCommit(dob_days, r_bits):
    biased = (dob_days as u32) ^ 0x8000_0000   // XOR sign bit for unsigned comparison
    dob_bits = bits_le(biased, 32)              // 32 bits, little-endian
    input = dob_bits || r_bits                  // concatenate
    point = H_ped(NoteCommitment, input)
    return compress(point)                      // 32 bytes
```

**Parameters**:
- `dob_days`: `i32` representing days since Unix epoch (signed to support dates before 1970-01-01)
- `r_bits`: Random bit vector, exactly **128 bits** (enforced by the circuit)
- Output: 32-byte compressed Jubjub point

**Capacity limit**: The Sapling Pedersen hash provides 6 generators × 63 chunks × 3 bits = 1,134 total input bits. After 6 bits consumed by the `NoteCommitment` personalization and 32 bits for `dob_days`, at most **1,096 bits** of randomness can be accepted (`MAX_PEDERSEN_RANDOMNESS_BITS`). Inputs exceeding this limit return the identity point encoding. In practice, the circuit enforces exactly 128 bits.

**Properties**:
- **Perfectly hiding**: For any commitment C and message m, there exists r such that Commit(m,r) = C. The commitment reveals no information about `dob_days`
- **Computationally binding**: Under the discrete log assumption on Jubjub, cannot find two distinct openings for the same commitment
- **Circuit compatibility**: This construction matches the in-circuit Pedersen commitment exactly (bit-for-bit)

### 7.2 Commitment Randomness Generation

```
GenerateRandomness(rng, num_bits):
    bits = []
    for i in 0..num_bits:
        if i % 8 == 0:
            byte = rng.next_u32() as u8
        bits.push((byte >> (i % 8)) & 1 == 1)
    return bits
```

### 7.3 Entropy Validation

Before computing a commitment, randomness is validated:

```
ValidateRandomness(r_bits):
    require len(r_bits) >= 32
    bytes = pack_bits_to_bytes(r_bits)
    unique_byte_values = count_unique(bytes)
    require unique_byte_values >= 8
```

This prevents weak randomness (e.g., all zeros, all ones) that would compromise the hiding property.

### 7.4 Nullifier

Derives a deterministic nullifier from a commitment, used for replay prevention. Uses a different Pedersen personalization (`MerkleTree(0)`) than the commitment itself.

```
PedersenNullifier(c_bytes):
    DST = "provii.nullifier.pedersen.v0"     // 28 bytes

    // Encode DST as little-endian bits
    bits = []
    for byte in DST:
        for i in 0..8:
            bits.push((byte >> i) & 1 != 0)

    // Append commitment bytes as little-endian bits
    for byte in c_bytes:
        for i in 0..8:
            bits.push((byte >> i) & 1 != 0)

    point = H_ped(MerkleTree(0), bits)
    return compress(point)                   // 32 bytes
```

**Note**: The domain separator is included as **bit-level input** to the Pedersen hash, NOT as a personalization parameter. The Pedersen hash personalization is `MerkleTree(0)` (from Zcash Sapling).

---

## 8. Ed25519 Attestation Scheme

Used for blind credential issuance. A trusted issuer creates an Ed25519-signed attestation of a user's date of birth.

### 8.1 Protocol Flow

1. Issuer verifies user identity and creates Ed25519-signed attestation
2. User generates commitment randomness locally
3. User sends attestation + randomness bits to the Provii issuance API
4. Provii verifies the attestation signature and computes the Pedersen commitment server-side

This ensures the issuer never sees the commitment (privacy) while preventing the user from lying about their DOB (integrity).

### 8.2 Attestation Message Construction

```
AttestationMessage(dob_days, issuer_id, timestamp, nonce, session_id?, client_id?):
    issuer_bytes = issuer_id.as_bytes()
    hasher = Blake2s256()
    hasher.update(DOB_ATTESTATION_DST)    // "provii.attestation.dob.v0" (25 bytes)
    hasher.update(LE(dob_days, 4))        // 4 bytes, little-endian
    hasher.update(byte(len(issuer_bytes)))// 1 byte length prefix
    hasher.update(issuer_bytes)           // variable
    hasher.update(LE(timestamp, 8))       // 8 bytes, little-endian
    hasher.update(nonce)                  // 32 bytes
    if session_id is Some or client_id is Some:
        sid = session_id.unwrap_or("").as_bytes()
        hasher.update(byte(len(sid)))     // 1 byte length prefix
        hasher.update(sid)                // variable
        cid = client_id.unwrap_or("").as_bytes()
        hasher.update(byte(len(cid)))     // 1 byte length prefix
        hasher.update(cid)                // variable
    return hasher.finalize()              // 32 bytes (Blake2s-256 digest)
```

**Note**: Unlike the credential prehash (Section 6.2), the attestation uses **little-endian** encoding for `dob_days` and `timestamp`.

**v1.1 binding fields** (`session_id`, `client_id`): added for the
docs-sandbox gateway flow. When both are absent, the canonical bytes
byte-match the pre-v1.1 layout so legacy attestations verify unchanged.
When either is present, both length-prefixed sections are emitted in
session-then-client order.

### 8.3 Create Attestation

```
CreateAttestation(dob_days, issuer_id, timestamp, nonce, ed25519_sk):
    message = AttestationMessage(dob_days, issuer_id, timestamp, nonce)
    signature = Ed25519_Sign(ed25519_sk, message)
    return DobAttestation {
        dob_days,
        issuer_id,
        timestamp,
        nonce,
        signature,    // 64 bytes
    }
```

### 8.4 Verify Attestation

```
VerifyAttestation(attestation, ed25519_vk):
    message = AttestationMessage(
        attestation.dob_days,
        attestation.issuer_id,
        attestation.timestamp,
        attestation.nonce,
    )
    return Ed25519_Verify(ed25519_vk, message, attestation.signature)
```

### 8.5 Verify with Freshness

```
VerifyAttestationFresh(attestation, ed25519_vk, current_time):
    require attestation.timestamp <= current_time           // not in future
    require current_time - attestation.timestamp <= 3600    // max 1 hour old
    require VerifyAttestation(attestation, ed25519_vk)
```

### 8.6 Serialization

The `DobAttestation` struct is serialized as JSON with hex-encoded byte arrays:

```json
{
    "dob_days": 7300,
    "issuer_id": "dmv.ca.gov",
    "timestamp": 1704067200,
    "nonce": "4242424242...42",
    "signature": "abcdef0123...ef"
}
```

---

## 9. Age Verification Circuit (R1CS)

The circuit proves, in zero knowledge, that the prover holds a validly-signed credential for a date of birth that satisfies an age threshold, without revealing the DOB, the signature, or the commitment randomness.

### 9.1 Circuit Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PUBLIC_INPUTS_LEN` | 8 | Number of Groth16 public input field elements (excluding implicit `1`) |
| `KID_SIZE_BYTES` | 14 | Fixed key identifier size in bytes |
| `SCHEMA_SIZE_BYTES` | 12 | Fixed credential schema size in bytes |
| `r_bits` length | 128 | Commitment randomness length in bits |
| Circuit version | `v7` | Unified direction circuit (used in constants hash) |

**Circuit Constants Hash**: A fingerprint of all constants that affect R1CS structure is computed via `compute_circuit_constants_hash()`. This hashes:

```
Blake2s256(
    "provii.age.circuit.constants.v0"
    || SPENDING_KEY_GENERATOR bytes
    || "ProviiRJ"
    || "provii.nullifier.pedersen.v0"
    || "provii.cred.v0"
    || NoteCommitment personalization bytes
    || LE(14, 4)        // kid length
    || LE(12, 4)        // schema length
    || LE(128, 4)       // r_bits length
)
```

If any of these constants change, the R1CS structure changes and all trusted setup parameters must be regenerated.

### 9.2 Age Direction

The circuit supports two modes of age comparison via the `AgeDirection` enum:

| Direction | Value | Semantics | Constraint |
|-----------|-------|-----------|------------|
| `Over` | `1` (true) | User is AT LEAST `min_age` years old | `cutoff_days >= dob_days` |
| `Under` | `0` (false) | User is AT MOST `max_age` years old | `dob_days >= cutoff_days` |

Both directions share a single R1CS layout. The direction is a public input, and a conditional swap (mux) selects operand order at proving time.

### 9.3 Public Inputs

The circuit exposes **8** `Fr_B` (BLS12-381 scalar) field elements, packed via Zcash's multipack algorithm:

| Index | Name | Packing | Description |
|-------|------|---------|-------------|
| 0 | `direction` | 32 LE bits → 1 element | Age direction bit (1 = Over, 0 = Under) |
| 1 | `cutoff_days` | 32 LE bits → 1 element | Age cutoff in days since epoch |
| 2-3 | `rp_hash` | 256 LE bits → 2 elements | RP challenge hash (computed off-circuit) |
| 4-5 | `issuer_vk_bytes` | 256 LE bits → 2 elements | Raw issuer verification key |
| 6-7 | `cred_nullifier` | 256 LE bits → 2 elements | Pedersen-based nullifier |

**Total**: 1 + 1 + 2 + 2 + 2 = **8 field elements**

Bellman adds an implicit `1` input at index 0, so the verifying key has `ic.len() == 9`.

**Multipack**: 256-bit values are split into chunks of at most `Scalar::CAPACITY` bits (254 bits for BLS12-381) and each chunk is packed into one field element. This means each 256-bit value requires exactly 2 field elements.

### 9.4 Private Witness

| Field | Type | Fixed Size | Description |
|-------|------|------------|-------------|
| `dob_days` | `i32` | 32 bits (biased to u32 via XOR 0x8000_0000) | Date of birth as days since epoch |
| `r_bits` | `[bool; 128]` | 128 bits | Commitment randomness |
| `issuer_vk_bytes` | `[u8; 32]` | 256 bits | Issuer verification key (must match public input) |
| `sig_rj_bytes` | `[u8; 64]` | 512 bits | RedJubjub signature (R ‖ s) |
| `v` | `u8` | 8 bits | Credential format version |
| `kid` | `[u8; 14]` | 112 bits | Key identifier (exactly `KID_SIZE_BYTES`) |
| `c_bytes` | `[u8; 32]` | 256 bits | Pedersen commitment |
| `iat` | `u64` | 64 bits | Credential issued-at (Unix seconds) |
| `exp` | `u64` | 64 bits | Credential expires-at (Unix seconds) |
| `schema` | `[u8; 12]` | 96 bits | Credential schema (exactly `SCHEMA_SIZE_BYTES`) |

**Validation**: The circuit rejects (returns `SynthesisError::Unsatisfiable`) if:
- `kid.len() != 14`
- `schema.len() != 12`
- `sig_rj_bytes.len() != 64`
- `r_bits.len() != 128`

### 9.5 Circuit Steps (~99,084 constraints)

The `synthesize` function proceeds in 8 steps:

**Step 0, Allocate public inputs**:
- Allocate `direction_bit` as a single boolean public input
- Allocate `cutoff_bits` as 32 LE bits (public input)
- Allocate `rp_hash_bits` as 256 bits (public input)
- Allocate `issuer_vk_bits_public` as 256 bits (public input)
- Allocate `cred_nullifier_bits` as 256 bits (public input)
- Pack all 5 conceptual values into 8 field elements via `multipack::pack_into_inputs`
- Packing order: direction → cutoff → rp_hash → issuer_vk → nullifier

**Step 1, Allocate witness inputs**:
- Allocate all private witness values (dob_bits, r_bits, issuer_vk, signature, v, kid, c_bytes, iat, exp, schema)
- Validate witness sizes match circuit constants

**Step 2, Verify issuer VK equality**:
- Extract the witness issuer VK as bytes bits
- Enforce bitwise equality: `issuer_vk_bytes_bits(witness) == issuer_vk_bits_public`
- This ensures the key used for signature verification matches the declared public input

**Step 3, Verify credential nullifier**:
- Compute `nullifier' = PedersenHash(MerkleTree(0), DST_bits || c_bytes_bits)` in-circuit
- Enforce bitwise equality: `nullifier' == cred_nullifier_bits`
- This binds the proof to a specific commitment for replay prevention

**Step 4, Verify Pedersen commitment**:
- Compute `C' = PedersenCommit(dob_bits, r_bits)` in-circuit using Sapling's Pedersen gadget
- Enforce bitwise equality: `C' == c_bytes_bits`
- This proves the prover knows a `dob_days` and `r_bits` that open the commitment

**Step 5, Age check (direction-dependent)**:
```
conditional_swap(direction_bit, cutoff_bits, dob_bits) → (left, right)
    if direction_bit = 1 (Over):  left = cutoff, right = dob
    if direction_bit = 0 (Under): left = dob, right = cutoff
enforce_ge(left, right)
```
- `enforce_ge` proves `left >= right` using unsigned integer comparison on 32-bit values
- Both `cutoff_days` and `dob_days` are biased from signed `i32` to unsigned `u32` via `bias_for_circuit(days) = (days as u32) ^ 0x8000_0000`. This XOR flips the sign bit, mapping signed ordering to unsigned ordering so that `bias(-3652) < bias(0) < bias(13880)` holds when compared as unsigned integers. The bias constant `SIGN_BIAS = 0x8000_0000` is defined in `crypto-commons/src/constants.rs`.

**Step 6, Build credential prehash message**:
- Construct the credential message bits in-circuit matching Section 6.2:
  `CRED_DST || v || len(kid) || kid || c_bytes || BE(iat) || BE(exp) || len(schema) || schema`
- All field sizes are fixed (kid=14, schema=12), ensuring deterministic circuit structure

**Step 7, Blake2s hash**:
- Compute `msg_hash = Blake2s256(message_bits)` in-circuit → 256 output bits
- Uses the Bellman Blake2s gadget (no personalization, matching the off-circuit `Blake2s256::new()` Digest construction)

**Step 8, Verify RedJubjub signature (no RP binding)**:
- Verify the RedJubjub signature `(R, s)` over `msg_hash` under `issuer_vk` in-circuit
- This uses the **non-RP-bound** signature (Section 6.5), NOT the RP-bound variant (Section 6.7)
- The issuer signs the credential without RP binding; the RP hash is bound to the proof separately via public inputs
- This proves the credential was signed by the declared issuer without revealing the signature

### 9.6 Gadget Modules

| Module | Purpose |
|--------|---------|
| `gadgets/bits.rs` | Bit allocation, `enforce_ge`, `enforce_bits_equal`, `conditional_swap`, u32/u64/u8 witness allocation |
| `gadgets/pedersen.rs` | In-circuit Pedersen commitment (`commit`) and nullifier (`pedersen_nullifier`), byte equality enforcement |
| `gadgets/blake2s.rs` | In-circuit Blake2s-256 hashing |
| `gadgets/redjubjub.rs` | In-circuit RedJubjub signature verification, VK/signature allocation |
| `gadgets/prehash.rs` | In-circuit credential message transcript construction (`build_prehash_bits`) |
| `gadgets/jubjub.rs` | In-circuit Jubjub curve arithmetic |

---

## 10. Prover and Verifier Protocols

### 10.1 Groth16 Parameters

| Parameter | Value |
|-----------|-------|
| Proving system | Groth16 |
| Pairing curve | BLS12-381 |
| Constraint count | 99,084 |
| Public inputs | 8 field elements (+ 1 implicit) |

### 10.2 Public Input Assembly

The `assemble_public_inputs_canonical` function packs public values into 8 BLS12-381 scalar field elements using Zcash's multipack algorithm. 32-bit values fit in a single field element. 256-bit values are split at `Scalar::CAPACITY` (254 bits) into 2 field elements each.

```
AssemblePublicInputs(direction, cutoff_days, rp_hash, issuer_vk_bytes, cred_nullifier):
    inputs = []

    // 0. Direction (1 bit packed as u32 LE bits → 1 element)
    dir_u32 = 1 if direction == Over else 0
    inputs.extend(multipack(bits_le(LE(dir_u32, 4), 32)))       // 1 element

    // 1. Cutoff days (32 bits → 1 element)
    inputs.extend(multipack(bits_le(LE(cutoff_days, 4), 32)))   // 1 element

    // 2-3. RP hash (256 bits → 2 elements)
    inputs.extend(multipack(bits_le(rp_hash, 256)))              // 2 elements

    // 4-5. Issuer VK (256 bits → 2 elements)
    inputs.extend(multipack(bits_le(issuer_vk_bytes, 256)))      // 2 elements

    // 6-7. Nullifier (256 bits → 2 elements)
    inputs.extend(multipack(bits_le(cred_nullifier, 256)))       // 2 elements

    assert len(inputs) == 8
    return inputs
```

**Order is critical**: The packing order must match exactly between the prover circuit (`pack_into_inputs` calls in `synthesize`) and the verifier (`assemble_public_inputs_canonical`). A mismatch causes proof verification to fail silently.

**Bit 254 preservation**: The implementation uses a manual packing routine rather than relying solely on `multipack::compute_multipacking` to ensure bit 254 of 256-bit values is not dropped during chunking.

### 10.3 Proof Generation

```
Prove(params, direction, cutoff_days, rp_hash, witness):
    public = AgePublic { direction, cutoff_days, rp_hash, issuer_vk_bytes, cred_nullifier }
    circuit = AgeCircuit { public, witness }
    proof = Groth16.prove(params, circuit)
    public_inputs = AssemblePublicInputs(
        direction, cutoff_days, rp_hash, witness.issuer_vk_bytes, nullifier
    )
    return (proof, public_inputs)
```

### 10.4 Proof Verification

```
Verify(vk, proof_bytes, direction, cutoff_days, rp_hash, issuer_vk_bytes, cred_nullifier):
    public_inputs = AssemblePublicInputs(
        direction, cutoff_days, rp_hash, issuer_vk_bytes, cred_nullifier
    )
    proof = deserialize_groth16_proof(proof_bytes)
    return Groth16.verify(vk, public_inputs, proof)
```

---

## 11. Protocol Layer

The protocol layer provides challenge generation, PKCE support, RP binding, replay protection, and issuance consent. All functions are in `crypto-protocol`.

### 11.1 Nonce Generation

```
new_nonce():
    nonce = [0u8; 32]
    // Native: OsRng.fill_bytes(nonce)
    // WASM:   getrandom::getrandom(nonce)   (Web Crypto API)
    return nonce    // 32 bytes, cryptographically random
```

### 11.2 PKCE (RFC 7636, S256)

Used to bind verification sessions. The `code_challenge` is computed from a `code_verifier` using the S256 method:

```
code_challenge_s256(code_verifier):
    digest = SHA-256(code_verifier.as_bytes())
    return base64url_no_pad(digest)     // 43 characters
```

**Properties**: Always 43 characters, URL-safe (no `+`, `/`, or `=` padding).

### 11.3 RP Challenge Binding

Binds a proof to a specific relying party origin and nonce. The RP challenge hash is a public input to the circuit.

```
rp_challenge(origin, nonce):
    return SHA-256(
        origin.as_bytes()
        || nonce
        || "provii.challenge.v0"
    )
    → [u8; 32]
```

**Note**: The domain tag `"provii.challenge.v0"` is appended **after** the origin and nonce, not prepended. This is the hash that becomes the `rp_hash` public input to the circuit.

### 11.4 Origin Hash

A simple SHA-256 hash of the origin string, used for replay tag computation:

```
compute_origin_hash(origin):
    return SHA-256(origin.as_bytes())
    → [u8; 32]
```

**Properties**: Case-sensitive (e.g., `"Example.com"` ≠ `"example.com"`).

### 11.5 Replay Tag

Combines the origin hash and nonce into a compact, URL-safe tag for replay detection:

```
compute_replay_tag(origin_hash, nonce):
    data = origin_hash || byte(':') || nonce
    return base64url_no_pad(data)
    → String
```

The separator byte `':'` (`0x3A`) ensures the tag encodes a structured value.

### 11.6 Issuance Consent Message

Used for wallet signatures during credential issuance. Binds the consent to a specific session, issuer, wallet, and terms.

**Version history**: v1 concatenated `session_id`, `issuer_id`, and `issuer_kid` without length prefixes, enabling trivial second-preimage collisions by shifting bytes across field boundaries. v2 introduces length prefixes for all three variable-length string fields and updates the domain separator.

```
build_issuance_consent_message(
    session_id, issuer_id, issuer_kid, wallet_pubkey,
    consent_time, terms_version, nonce
):
    DOMAIN = "provii:issuance-consent:v0"

    h = SHA-256()
    h.update(DOMAIN)
    write_length_prefixed(h, session_id.as_bytes())  // LE(len, 4) || bytes
    write_length_prefixed(h, issuer_id.as_bytes())   // LE(len, 4) || bytes
    write_length_prefixed(h, issuer_kid.as_bytes())  // LE(len, 4) || bytes
    h.update(wallet_pubkey)              // 32 bytes (fixed length, no prefix needed)
    h.update(LE(consent_time, 8))        // i64, little-endian
    h.update(LE(terms_version, 4))       // u32, little-endian
    if nonce is Some:
        h.update([0x01])
        h.update(nonce)                  // 16 bytes
    else:
        h.update([0x00])
    return h.finalize()
    → [u8; 32]
```

**Parameters**:
- `consent_time`: `i64` (signed), can be negative for testing
- `terms_version`: `u32`
- `nonce`: `Option<[u8; 16]>`, optional 16-byte nonce for additional entropy

**Note**: The nonce field is 16 bytes (not 32 like the challenge nonce). `write_length_prefixed` encodes the 4-byte LE length before each variable-length field, preventing second-preimage collisions across field boundaries. `wallet_pubkey` is fixed at 32 bytes and requires no length prefix.

### 11.7 Length-Prefixed Data Helper

Used internally for signature message construction:

```
write_length_prefixed(h, data):
    h.update(LE(len(data) as u32, 4))   // 4-byte LE length prefix
    h.update(data)
```

**Limitation**: Casts `usize` to `u32`, so data length must be ≤ 4,294,967,295 bytes.

### 11.8 Replay Protection

Replay is prevented through multiple layers:

1. **Nonce uniqueness**: Each challenge contains a 32-byte CSPRNG nonce (`new_nonce`)
2. **Time bounds**: Challenges expire after `CHALLENGE_EXPIRY_SECONDS` (300s)
3. **Clock skew tolerance**: `CLOCK_SKEW_TOLERANCE_SECONDS` (30s) prevents drift issues
4. **Replay window**: Tags tracked for `REPLAY_WINDOW_SECONDS` (600s) after challenge expiry
5. **Nullifier uniqueness**: The Pedersen nullifier (Section 7.4) derived from the commitment is a public input; the verifier can reject duplicate nullifiers within a time window
6. **RP binding**: The `rp_challenge` hash binds the proof to a specific origin + nonce pair

---

## 12. Security Properties

### 12.1 Guaranteed Properties

| Property | Mechanism |
|----------|-----------|
| **Memory safety** | `#![forbid(unsafe_code)]` in 5/9 crates. Exceptions documented with safety proofs. |
| **Key zeroization** | `SigningKey` implements `Zeroize + Drop` with volatile writes |
| **Domain separation** | Unique tags for every cryptographic operation (Section 3) |
| **Scalar field alignment** | Off-circuit and in-circuit computations use identical scalar field reduction |
| **Replay prevention** | Nonce entropy validation, time bounds, nullifier tracking |
| **Deterministic signing** | Nonce derived from (sk, message) - no random nonce |
| **Subgroup enforcement** | All Jubjub points validated as prime-order subgroup elements |
| **Zero rejection** | Zero scalar rejected as signing key |
| **Non-canonical rejection** | Non-canonical scalar/point encodings rejected on deserialization |

### 12.2 Direction Safety

The `AgeDirection` public input prevents direction confusion attacks:
- The direction bit is a **public input** to the circuit, so the verifier knows which comparison was proven
- A proof generated for `Over` (cutoff >= dob) cannot be used to satisfy an `Under` query, and vice versa
- Both directions use the same R1CS layout (unified circuit), eliminating the need for separate trusted setups

### 12.3 Not Guaranteed

| Property | Reason |
|----------|--------|
| Constant-time operations | Blake2s personalization uses `blake2s_simd`, nonce uses `blake2` crate - timing characteristics not formally verified |
| Side-channel resistance | Requires formal verification and hardware-specific analysis |
| Protocol-level correctness | Requires formal proofs (e.g., in a proof assistant) |

### 12.4 Commitment Security

The Pedersen commitment provides:
- **Perfectly hiding**: Information-theoretic. Given a commitment C, the message is statistically independent of C
- **Computationally binding**: Under the discrete log assumption on Jubjub. Finding (m1,r1) != (m2,r2) with Commit(m1,r1) = Commit(m2,r2) requires solving DLP
- Entropy validation requires >= 8 unique byte values in randomness

### 12.5 Signature Security

The RedJubjub variant provides EUF-CMA (existential unforgeability under chosen message attack) security under the discrete log assumption on Jubjub, assuming:
- The hash function (Blake2s-256) behaves as a random oracle
- Domain separation prevents cross-protocol attacks
- The generator `G` is a valid prime-order subgroup element

---

## 13. Deviations from Zcash

This section documents all intentional differences from the Zcash protocol specifications.

### 13.1 RedJubjub Modifications

| Aspect | Zcash RedJubjub | Provii RedJubjub |
|--------|-----------------|------------------|
| Challenge hash | `BLAKE2b-512` with Zcash-specific DST | `Blake2s-256` with `"ProviiRJ"` personalization, wide-reduced to `Fr_J` |
| Nonce derivation | Per Zcash spec (randomized or derived) | `Blake2s-256("ProviiRJ/nonce" \|\| sk \|\| msg_hash)`, wide-reduced |
| Message format | Zcash transaction sighash | Credential prehash (Section 6.2) |
| Generator | Zcash spending key generator | Same bytes but loaded via `SubgroupPoint::from_bytes` directly |
| RP binding | N/A | Optional double-hash: `Blake2s(H(cred) \|\| rp)` |

### 13.2 Pedersen Hash Usage

| Aspect | Zcash Sapling | Provii |
|--------|---------------|--------|
| Personalization | `NoteCommitment` for note commitments | `NoteCommitment` for DOB commitments (same) |
| Input format | Note fields per Zcash spec | `bits_le(dob_days, 32) \|\| r_bits` |
| Nullifier | Derived from note commitment + nk | `PedersenHash(MerkleTree(0), DST_bits \|\| commitment_bits)` |
| Nullifier DST | N/A (uses nullifier key) | `"provii.nullifier.pedersen.v0"` encoded as LE bits |

### 13.3 Circuit Differences

| Aspect | Zcash Sapling | Provii |
|--------|---------------|--------|
| Purpose | Shielded transactions | Age threshold verification |
| Public inputs | Value commitment, nullifier, etc. | 8 elements: direction, cutoff_days, rp_hash, issuer_vk, nullifier |
| Constraints | ~100K (Sapling spend) | 99,084 |
| Signature in circuit | N/A (signatures outside circuit) | RedJubjub verification inside circuit |
| Age comparison | N/A | Direction-dependent via conditional swap mux |
| Fixed field sizes | N/A | kid=14 bytes, schema=12 bytes, r_bits=128 bits |
| Proving system | Groth16 on BLS12-381 | Same |

### 13.4 No Zcash Compatibility

This implementation shares **primitives** with Zcash (curves, Pedersen generators, Groth16) but is **not compatible** with Zcash at the protocol level. Zcash proofs, signatures, and commitments cannot be used interchangeably with Provii.

---

## Appendix A: Data Structures

### A.1 CredMsgV2

```rust
struct CredMsgV2 {
    v: u8,              // Format version
    kid: String,        // Key identifier
    c: [u8; 32],        // Pedersen commitment
    iat: u64,           // Issued-at (Unix seconds)
    exp: u64,           // Expires-at (Unix seconds)
    schema: String,     // Credential schema identifier
}
```

### A.2 AgeSnarkProofV2

```rust
struct AgeSnarkProofV2 {
    v: u8,              // Format version
    vk: u16,            // Verifying key identifier
    rp: [u8; 32],       // Relying party hash
    cutoff: u32,        // Age cutoff in days
    proof: Vec<u8>,     // Serialized Groth16 proof
}
```

### A.3 DobAttestation

```rust
struct DobAttestation {
    dob_days: i32,                  // Days since Unix epoch (signed to support dates before 1970-01-01)
    issuer_id: String,              // Issuing authority identifier
    timestamp: u64,                 // Creation time (Unix seconds)
    nonce: [u8; 32],                // Replay prevention nonce
    session_id: Option<String>,     // v1.1: docs-sandbox gateway session id
    client_id: Option<String>,      // v1.1: docs-sbx-*/mwallet-sbx-* client id
    signature: [u8; 64],            // Ed25519 signature
}
```

### A.4 AgePublic (Circuit Public Inputs)

```rust
struct AgePublic {
    direction: AgeDirection,    // Over or Under
    cutoff_days: u32,           // Age cutoff in days since epoch
    rp_hash: [u8; 32],         // RP challenge hash
    issuer_vk_bytes: [u8; 32], // Raw issuer verification key
    cred_nullifier: [u8; 32],  // Pedersen-based nullifier
}
```

### A.5 AgeWitness (Circuit Private Witness)

```rust
struct AgeWitness {
    dob_days: i32,              // Date of birth (days since epoch, biased via XOR 0x8000_0000)
    r_bits: Vec<bool>,          // 128 bits commitment randomness
    issuer_vk_bytes: [u8; 32],  // Issuer verification key
    sig_rj_bytes: Vec<u8>,      // 64-byte RedJubjub signature
    v: u8,                      // Format version
    kid: Vec<u8>,               // MUST be exactly 14 bytes
    c_bytes: [u8; 32],          // Pedersen commitment
    iat: u64,                   // Issued-at (Unix seconds)
    exp: u64,                   // Expires-at (Unix seconds)
    schema: Vec<u8>,            // MUST be exactly 12 bytes
}
```

### A.6 AgeDirection

```rust
enum AgeDirection {
    Over,   // cutoff >= dob (user is at least min_age)
    Under,  // dob >= cutoff (user is at most max_age)
}
```

---

## Appendix B: Dependency Versions

| Crate | Version | Purpose |
|-------|---------|---------|
| `bellman` | 0.14 | Groth16 proving system |
| `bls12_381` | 0.8 | BLS12-381 curve |
| `jubjub` | 0.10 | Jubjub curve |
| `ed25519-dalek` | 2.1 | Ed25519 signatures |
| `blake2` | 0.10 | Blake2s-256 (Digest trait) |
| `blake2s_simd` | 1.0 | Blake2s-256 (with personalization) |
| `sha2` | 0.10 | SHA-256 |
| `sapling-crypto` | 0.5 | Pedersen hash gadgets |
| `zcash_primitives` | 0.24 | Zcash Sapling primitives |
| `zcash_proofs` | 0.24 | Proof utilities |
| `ff` | 0.13 | Field arithmetic traits |
| `group` | 0.13 | Group arithmetic traits |
| `zeroize` | 1.8 | Secret key zeroing |
| `subtle` | 2.6 | Constant-time operations |
