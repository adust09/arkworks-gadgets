# Arkworks Gadgets

Cryptographic gadgets for use with the Arkworks zero-knowledge proof library.

## Features

- **AES Encryption/Decryption**: Implementations of AES for use in zero-knowledge circuits
- **Blake3 Hash Function**: Blake3 hash function implementation for zero-knowledge proofs

## Usage

### Blake3 Hash Function

```rust
use ark_bn254::Fr;
use ark_relations::r1cs::ConstraintSystem;
use arkworks_gadgets::hash::blake3::{Blake3CRH, Blake3CRHGadget, DigestVar};
use ark_r1cs_std::alloc::AllocationMode;

// Create a constraint system
let cs = ConstraintSystem::<Fr>::new_ref();

// Test inputs
let left_input = [1u8; 32];
let right_input = [2u8; 32];

// Native computation 
let result = Blake3CRH::evaluate(&(), &left_input, &right_input).unwrap();

// Gadget computation in zero-knowledge circuit
let left_var = DigestVar::<Fr>::new_variable(cs.clone(), || Ok(left_input), AllocationMode::Witness).unwrap();
let right_var = DigestVar::<Fr>::new_variable(cs.clone(), || Ok(right_input), AllocationMode::Witness).unwrap();
let result_var = Blake3CRHGadget::evaluate(&(), &left_var, &right_var).unwrap();

// Verify that the gadget produces the same result as the native implementation
let gadget_result = result_var.value().unwrap();
assert_eq!(gadget_result, result);

// Check that the constraints are satisfied
assert!(cs.is_satisfied().unwrap());
```

### AES Encryption

```rust
use ark_bn254::Fr;
use ark_relations::r1cs::ConstraintSystem;
use arkworks_gadgets::aes::aes::{aes_encrypt, key_expansion};
use ark_r1cs_std::{uint8::UInt8, prelude::*};

// Create a constraint system
let cs = ConstraintSystem::<Fr>::new_ref();

// Create a key (128 bits = 16 bytes)
let key_bytes: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                          0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
                          
// Create plaintext (128 bits = 16 bytes)
let plaintext: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 
                          0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];

// Convert key and plaintext to UInt8 for the circuit
let key_vars: Vec<UInt8<Fr>> = key_bytes.iter()
    .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)).unwrap())
    .collect();

let plaintext_vars: Vec<UInt8<Fr>> = plaintext.iter()
    .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)).unwrap())
    .collect();

// Expand the key
let expanded_key = key_expansion(cs.clone(), &key_vars).unwrap();

// Encrypt the plaintext
let ciphertext = aes_encrypt(cs.clone(), &plaintext_vars, &expanded_key).unwrap();

// The resulting ciphertext is now available for use in the zero-knowledge circuit
```

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
arkworks-gadgets = { git = "https://github.com/yourusername/arkworks-gadets" }
```

## License

This project is licensed under either of

- MIT license
- Apache License, Version 2.0

at your option.
