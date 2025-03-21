//! Arkworks Gadgets Library
//!
//! This library provides cryptographic gadgets for use with the Arkworks zero-knowledge proof library,
//! including AES and hash function implementations that can be used in zk-SNARKs.

// Re-export commonly used traits and types
pub use ark_crypto_primitives::crh::constraints::TwoToOneCRHSchemeGadget;
pub use ark_crypto_primitives::crh::TwoToOneCRHScheme;
pub use ark_r1cs_std::alloc::AllocVar;
pub use ark_r1cs_std::R1CSVar;

pub mod aes;
pub mod hash;
