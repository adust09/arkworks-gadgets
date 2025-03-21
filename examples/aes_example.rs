use ark_bn254::Fr;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::ConstraintSystem;
use arkworks_gadgets::aes::aes::aes_encrypt;
use std::time::Instant;

fn main() {
    // Create a constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Create a key (128 bits = 16 bytes)
    let key_bytes: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    // Create plaintext (128 bits = 16 bytes)
    let plaintext: [u8; 16] = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
        0x34,
    ];

    println!("Key: {:02x?}", key_bytes);
    println!("Plaintext: {:02x?}", plaintext);

    // Convert key and plaintext to UInt8 for the circuit
    let start = Instant::now();

    // Convert key to UInt8 variables
    let key_vars: Vec<UInt8<Fr>> = key_bytes
        .iter()
        .map(|b| UInt8::new_variable(cs.clone(), || Ok(*b), AllocationMode::Witness).unwrap())
        .collect();

    // Convert plaintext to UInt8 variables
    let plaintext_vars: Vec<UInt8<Fr>> = plaintext
        .iter()
        .map(|b| UInt8::new_variable(cs.clone(), || Ok(*b), AllocationMode::Witness).unwrap())
        .collect();

    // Encrypt the plaintext (aes_encrypt will handle key expansion internally)
    let ciphertext_vars = aes_encrypt(cs.clone(), &plaintext_vars, &key_vars).unwrap();

    // Get the values out of the circuit
    let ciphertext: Vec<u8> = ciphertext_vars.iter().map(|v| v.value().unwrap()).collect();

    let duration = start.elapsed();

    println!("Ciphertext: {:02x?}", ciphertext);
    println!("Constraints satisfied: {}", cs.is_satisfied().unwrap());
    println!("Number of constraints: {}", cs.num_constraints());
    println!("Time taken: {:?}", duration);
}
