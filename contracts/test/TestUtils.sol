// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IAggregator} from "@account-abstraction/contracts/interfaces/IAggregator.sol";

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

    function createUOTestData(address sender, bytes memory proofData)
        public
        pure
        returns (PackedUserOperation[] memory)
    {
        bytes memory signature = encodeSignature(proofData);
        PackedUserOperation[] memory uOps = new PackedUserOperation[](2);
        PackedUserOperation memory baseUO = PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: abi.encodePacked("0x"),
            callData: abi.encodePacked("0x"),
            accountGasLimits: bytes32("10000"),
            preVerificationGas: 10000,
            gasFees: bytes32(0),
            paymasterAndData: abi.encodePacked("0x"),
            signature: signature
        });

        uOps[0] = baseUO;
        uOps[1] = baseUO;
        return uOps;
    }
}
