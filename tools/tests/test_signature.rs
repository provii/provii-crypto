//! Diagnostic test program to identify mismatches between off-circuit and in-circuit computations.
//! Run this test to see exactly where the computations diverge.

use provii_crypto_sig_redjubjub::{sign_cred_v2, verify_cred_v2, generate_keypair};
use provii_crypto_commons::CredMsgV2;
use blake2::{Blake2s256, Digest};
use blake2s_simd::Params;
use jubjub::{Fr as JubjubScalar, SubgroupPoint};
use ff::{Field, PrimeField};
use group::GroupEncoding;

fn main() {
    println!("\n========================================");
    println!("=== DIAGNOSTIC TEST FOR SIGNATURE MISMATCH ===");
    println!("========================================\n");
    
    // Step 1: Generate a test keypair.
    println!("Step 1: Generating test keypair...");
    let (sk_bytes, vk_bytes) = generate_keypair();
    println!("  VK: {}", hex::encode(&vk_bytes));
    
    // Step 2: Create a test credential message.
    println!("\nStep 2: Creating test credential message...");
    let cred = CredMsgV2 {
        v: 2,
        kid: "provii:2026-05".to_string(),
        c: hex::decode("1625f1c7760c9612049ebf4e0d7b77026b4de152942b198bd0d5adca903ef5d1")
            .unwrap()
            .try_into()
            .unwrap(),
        iat: 1757747313,
        exp: 1789283313,
        schema: "provii.age/0".to_string(),
    };
    
    println!("  v: {}", cred.v);
    println!("  kid: {}", cred.kid);
    println!("  c: {}", hex::encode(&cred.c));
    println!("  iat: {}", cred.iat);
    println!("  exp: {}", cred.exp);
    println!("  schema: {}", cred.schema);
    
    // Step 3: Sign the credential.
    println!("\nStep 3: Signing credential...");
    let signature = sign_cred_v2(&cred, &sk_bytes).unwrap();
    println!("  Signature: {}", hex::encode(&signature));
    println!("  R (first 32): {}", hex::encode(&signature[..32]));
    println!("  s (last 32): {}", hex::encode(&signature[32..]));
    
    // Step 4: Verify off-circuit.
    println!("\nStep 4: Verifying signature off-circuit...");
    match verify_cred_v2(&cred, &signature, &vk_bytes) {
        Ok(_) => println!("  ✅ Off-circuit verification PASSED"),
        Err(e) => println!("  ❌ Off-circuit verification FAILED: {:?}", e),
    }
    
    // Step 5: Manually compute the challenge to compare values.
    println!("\nStep 5: Manual challenge computation for debugging...");
    
    // Compute the message hash that was signed.
    let prehash = provii_crypto_commons::cred_v2_prehash_bytes(
        cred.v,
        &cred.kid,
        &cred.c,
        cred.iat,
        cred.exp,
        &cred.schema,
    )
    .expect("credential fields are within 255-byte limit");
    println!("  Prehash: {}", hex::encode(&prehash));
    
    let mut h = Blake2s256::new();
    h.update(&prehash);
    let msg_hash = h.finalize();
    println!("  Message hash: {}", hex::encode(&msg_hash));
    
    // Extract R and compute the challenge input.
    let r_bytes = &signature[..32];
    println!("  R for challenge: {}", hex::encode(r_bytes));
    println!("  VK for challenge: {}", hex::encode(&vk_bytes));
    
    // Compute the challenge hash.
    let challenge_hash = Params::new()
        .hash_length(32)
        .personal(b"ProviiRJ")
        .to_state()
        .update(r_bytes)
        .update(&vk_bytes)
        .update(&msg_hash)
        .finalize();
    
    println!("  Challenge hash: {}", hex::encode(challenge_hash.as_bytes()));
    
    // Reduce the challenge to a Jubjub scalar.
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(challenge_hash.as_bytes());
    let c_jubjub = JubjubScalar::from_bytes_wide(&wide);
    println!("  Challenge scalar (Jubjub): {}", hex::encode(c_jubjub.to_bytes()));
    
    // Also derive the corresponding BLS scalar for comparison.
    use bls12_381::Scalar as BlsScalar;
    let c_bls = BlsScalar::from_bytes_wide(&wide);
    println!("  Challenge scalar (BLS): {}", hex::encode(c_bls.to_repr()));
    
    // Step 6: Verify the signature equation manually.
    println!("\nStep 6: Manual verification of signature equation...");
    
    // Parse signature components.
    let mut r_bytes_array = [0u8; 32];
    let mut s_bytes_array = [0u8; 32];
    r_bytes_array.copy_from_slice(&signature[..32]);
    s_bytes_array.copy_from_slice(&signature[32..]);
    
    let r_point = SubgroupPoint::from_bytes(&r_bytes_array).unwrap();
    let s_scalar = JubjubScalar::from_bytes(&s_bytes_array).unwrap();
    let vk_point = SubgroupPoint::from_bytes(&vk_bytes).unwrap();
    
    println!("  R point loaded");
    println!("  s scalar: {}", hex::encode(s_scalar.to_bytes()));
    println!("  VK point loaded");
    
    // Load the generator point used for RedJubJub signatures.
    const SPENDING_KEY_GEN_BYTES: [u8; 32] = [
        0x30, 0xb5, 0xf2, 0xaa, 0xad, 0x32, 0x56, 0x30,
        0xbc, 0xdd, 0xdb, 0xce, 0x4d, 0x67, 0x65, 0x6d,
        0x05, 0xfd, 0x1c, 0xc2, 0xd0, 0x37, 0xbb, 0x53,
        0x75, 0xb6, 0xe9, 0x6d, 0x9e, 0x01, 0xa1, 0x57
    ];
    let g = SubgroupPoint::from_bytes(&SPENDING_KEY_GEN_BYTES).unwrap();
    
    // Compute both sides of the signature equation.
    let lhs = g * s_scalar;
    let rhs = r_point + (vk_point * c_jubjub);
    
    // Convert the points to affine coordinates for comparison.
    use jubjub::ExtendedPoint;
    let lhs_ext = ExtendedPoint::from(lhs);
    let lhs_affine = lhs_ext.to_affine();
    let rhs_ext = ExtendedPoint::from(rhs);
    let rhs_affine = rhs_ext.to_affine();
    
    println!("  s*G - u: {}, v: {}", 
             hex::encode(lhs_affine.get_u().to_repr()),
             hex::encode(lhs_affine.get_v().to_repr()));
    println!("  R+c*VK - u: {}, v: {}", 
             hex::encode(rhs_affine.get_u().to_repr()),
             hex::encode(rhs_affine.get_v().to_repr()));
    
    if lhs == rhs {
        println!("  ✅ Equation s*G = R + c*VK holds");
    } else {
        println!("  ❌ Equation s*G ≠ R + c*VK FAILED");
        
        // Compute coordinate differences for debugging output.
        use ff::Field;
        let mut u_diff = lhs_affine.get_u();
        u_diff.sub_assign(&rhs_affine.get_u());
        let mut v_diff = lhs_affine.get_v();
        v_diff.sub_assign(&rhs_affine.get_v());
        
        println!("  u difference: {}", hex::encode(u_diff.to_repr()));
        println!("  v difference: {}", hex::encode(v_diff.to_repr()));
    }
    
    // Step 7: Test with the circuit's scalar conversion approach.
    println!("\nStep 7: Testing circuit's scalar conversion approach...");
    
    // Simulate the circuit's scalar conversion by mapping the Jubjub scalar into the BLS field.
    let s_jubjub_bytes = s_scalar.to_repr();
    let s_bls = BlsScalar::from_repr(s_jubjub_bytes).unwrap();
    println!("  s as BLS scalar: {}", hex::encode(s_bls.to_repr()));
    
    // Challenge scalar as computed by the circuit (uses Jubjub reduction).
    let c_circuit = c_jubjub; // Circuit should use this
    println!("  Challenge for circuit: {}", hex::encode(c_circuit.to_bytes()));
    
    // Step 8: Summary.
    println!("\n========================================");
    println!("=== SUMMARY ===");
    println!("========================================");
    println!("This test helps identify where the off-circuit and in-circuit");
    println!("computations diverge. Key things to check:");
    println!("1. Challenge hash computation matches");
    println!("2. Scalar field reduction matches (Jubjub vs BLS)");
    println!("3. Generator point is consistent");
    println!("4. Point arithmetic operations match");
    println!("\nIf the off-circuit verification passes but circuit fails,");
    println!("the issue is in the scalar field handling or point operations.");
}
