use alloy_primitives::keccak256;
use alloy_sol_types::SolValue;
use semaphore::{hash_to_field, Field};

use crate::bindings::IEntryPoint::PackedUserOperation;

pub fn hash_user_op(user_op: &PackedUserOperation) -> Field {
    let keccak_hash = keccak256(SolValue::abi_encode_packed(&(
        &user_op.sender,
        &user_op.nonce,
        &user_op.initCode,
        &user_op.callData,
        &user_op.accountGasLimits,
        &user_op.preVerificationGas,
        &user_op.gasFees,
        &user_op.paymasterAndData,
    )));

    hash_to_field(keccak_hash.as_slice())
}
