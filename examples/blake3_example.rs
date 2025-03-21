use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::R1CSVar; // Direct import of R1CSVar trait
use ark_relations::r1cs::ConstraintSystem;
// Use the re-exported traits from our library
use arkworks_gadgets::hash::blake3::{Blake3CRH, Blake3CRHGadget, DigestVar};
use arkworks_gadgets::{AllocVar, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};

fn main() {
    // Create a constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Test inputs
    let left_input = [1u8; 32];
    let right_input = [2u8; 32];

    // Native computation
    let result = Blake3CRH::evaluate(&(), &left_input, &right_input).unwrap();
    println!("Native hash result: {:?}", result);

    // Gadget computation in zero-knowledge circuit
    let left_var =
        DigestVar::<Fr>::new_variable(cs.clone(), || Ok(left_input), AllocationMode::Witness)
            .unwrap();

    let right_var =
        DigestVar::<Fr>::new_variable(cs.clone(), || Ok(right_input), AllocationMode::Witness)
            .unwrap();

    let result_var = Blake3CRHGadget::evaluate(&(), &left_var, &right_var).unwrap();

    // Verify that the gadget produces the same result as the native implementation
    let gadget_result = result_var.value().unwrap();
    println!("Gadget hash result: {:?}", gadget_result);
    assert_eq!(gadget_result, result);

    // Check that the constraints are satisfied
    let satisfied = cs.is_satisfied().unwrap();
    println!("Constraints satisfied: {}", satisfied);

    // Number of constraints generated
    println!("Number of constraints: {}", cs.num_constraints());
}
