# Arkworks Gadgets

Cryptographic gadgets for use with the Arkworks zero-knowledge proof library. This library provides efficient implementations of cryptographic primitives that can be used within zero-knowledge circuits.

## Features

- **AES Encryption/Decryption**: Implementations of AES for use in zero-knowledge circuits
- **Pseudo-Random Generator (PRG)**: Based on AES for generating random values in circuits
- **Blake3 Hash Function**: Blake3 hash function implementation for zero-knowledge proofs

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
arkworks-gadgets = { git = "https://github.com/yourusername/arkworks-gadets" }
```

You'll also need to add the appropriate Arkworks dependencies to your project:

```toml
ark-bn254 = "^0.5.0"
ark-ff = "^0.5.0"
ark-r1cs-std = "^0.5.0"
ark-relations = "^0.5.0"
```

## Usage

### Blake3 Hash Function

The Blake3 implementation provides a cryptographic hash function that can be used in zero-knowledge circuits.

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

The AES implementation allows you to perform AES encryption within zero-knowledge circuits.

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

### Pseudo-Random Generator (PRG)

The PRG implementation uses AES in counter mode to generate pseudo-random values.

```rust
use ark_bn254::Fr;
use ark_relations::r1cs::ConstraintSystem;
use arkworks_gadgets::aes::prg::{PRGGadget, expand_key_for_prg};
use ark_r1cs_std::{uint8::UInt8, prelude::*};

// Create a constraint system
let cs = ConstraintSystem::<Fr>::new_ref();

// Create a seed (128 bits = 16 bytes)
let seed: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];

// Convert seed to UInt8 variables
let seed_vars: Vec<UInt8<Fr>> = seed.iter()
    .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)).unwrap())
    .collect();

// Expand the key for PRG
let expanded_key = expand_key_for_prg(cs.clone(), &seed_vars).unwrap();

// Generate 32 bytes of random data
let random_data = PRGGadget::generate_random_bytes(
    cs.clone(),
    &expanded_key,
    32 // Number of bytes to generate
).unwrap();

// The random_data can now be used in your circuit
```

## Running the Examples

The repository includes example code for both AES and Blake3. You can run them with:

```bash
# Run the AES example
cargo run --example aes_example

# Run the Blake3 example
cargo run --example blake3_example
```

## Building the Project

To build the library:

```bash
cargo build
```

For optimized release builds:

```bash
cargo build --release
```

## License

This project is licensed under either of

- MIT license
- Apache License, Version 2.0

at your option.
