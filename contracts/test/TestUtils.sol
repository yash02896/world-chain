// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@solady/LibBytes.sol";
import "@forge-std/console.sol";
import "@forge-std/Vm.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IAggregator} from "@account-abstraction/contracts/interfaces/IAggregator.sol";
import {Mock4337Module} from "./mocks/Mock4337Module.sol";

library TestUtils {
    /// @notice Encodes the ECDSA signature and proof data into a single bytes array.
    function encodeSignature(bytes memory proofData, bytes memory ecdsaSignature)
        public
        pure
        returns (bytes memory res)
    {
        res = LibBytes.concat(ecdsaSignature, proofData);
    }

    /// @notice Create a test data for UserOperations.
    function createUOTestData(
        Vm vm,
        uint256 nonceKey,
        address module,
        address sender,
        bytes[] memory proofs,
        uint256 signingKey
    ) public view returns (PackedUserOperation[] memory) {
        PackedUserOperation[] memory uOps = new PackedUserOperation[](proofs.length);
        for (uint256 i = 0; i < proofs.length; i++) {
            PackedUserOperation memory uo = createMockUserOperation(sender, nonceKey, i);
            bytes32 operationHash = Mock4337Module(module).getOperationHash(uo);
            bytes memory ecdsaSignature = createSignature(vm, operationHash, signingKey);
            bytes memory signature = encodeSignature(proofs[i], ecdsaSignature);
            uo.signature = signature;
            uOps[i] = uo;
        }

        return uOps;
    }

    /// @notice Creates a Mock UserOperation w/ an unsigned signature.
    function createMockUserOperation(address sender, uint256 nonceKey, uint256 nonce) public pure returns (PackedUserOperation memory uo) {
        uo = PackedUserOperation({
            sender: sender,
            nonce: nonceKey << 64 + nonce,
            initCode: new bytes(0),
            callData: new bytes(0),
            accountGasLimits: 0x00000000000000000000000000009fd300000000000000000000000000000000,
            preVerificationGas: 21000,
            gasFees: 0x0000000000000000000000000000000100000000000000000000000000000001,
            paymasterAndData: new bytes(0),
            signature: abi.encodePacked(uint48(0), uint48(0))
        });
    }

    /// @notice Creates an ECDSA signature from the UserOperation Hash, and signer.
    function createSignature(Vm vm, bytes32 operationHash, uint256 signingKey) public pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, operationHash);
        bytes memory signature = abi.encodePacked(uint48(0), uint48(0), r, s, v);
        return signature;
    }
}
