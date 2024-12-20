// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IAggregator} from "@account-abstraction/contracts/interfaces/IAggregator.sol";
import "@forge-std/console.sol";

contract TestUtils {
    function encodeSignature(bytes memory proofData) public pure returns (bytes memory) {
        bytes memory sigBuffer = new bytes(65);
        bytes memory signature = new bytes(417);
        assembly {
            mstore(signature, sigBuffer)
            mstore(add(signature, 32), mload(add(sigBuffer, 32)))
            mstore(add(signature, 64), mload(add(sigBuffer, 64)))
            mstore(add(signature, 65), mload(proofData))
            mstore(add(add(signature, 65), 32), mload(add(proofData, 32)))
            mstore(add(add(signature, 65), 64), mload(add(proofData, 64)))
            mstore(add(add(signature, 65), 96), mload(add(proofData, 96)))
            mstore(add(add(signature, 65), 128), mload(add(proofData, 128)))
            mstore(add(add(signature, 65), 160), mload(add(proofData, 160)))
            mstore(add(add(signature, 65), 192), mload(add(proofData, 192)))
            mstore(add(add(signature, 65), 224), mload(add(proofData, 224)))
            mstore(add(add(signature, 65), 256), mload(add(proofData, 256)))
        }
        return signature;
    }

    /// @notice Create a test data for UserOperations.
    function createUOTestData(address sender, bytes[] memory proofs)
        public
        pure
        returns (PackedUserOperation[] memory)
    {
        PackedUserOperation[] memory uOps = new PackedUserOperation[](proofs.length);
        for (uint256 i = 0; i < proofs.length; ++i) {
            bytes memory signature = encodeSignature(proofs[i]);
            // uint256 preVerificationGas = uint256(100000) << 64 | 100000;
            PackedUserOperation memory uo = PackedUserOperation({
                sender: sender,
                nonce: i,
                initCode: new bytes(0),
                callData: new bytes(0),
                accountGasLimits: 0x00000000000000000000000000009fd300000000000000000000000000000000,
                preVerificationGas: 21000,
                gasFees: 0x0000000000000000000000000000000100000000000000000000000000000001,
                paymasterAndData: new bytes(0),
                signature: signature
            });
            uOps[i] = uo;
        }

        return uOps;
    }
}
