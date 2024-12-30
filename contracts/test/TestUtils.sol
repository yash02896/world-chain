// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@solady/LibBytes.sol";
import "@forge-std/console.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IAggregator} from "@account-abstraction/contracts/interfaces/IAggregator.sol";

contract TestUtils {
    function encodeSignature(bytes memory proofData, uint256 signatureThreshold)
        public
        pure
        returns (bytes memory res)
    {
        bytes memory sigBuffer = new bytes(65 * signatureThreshold + 12);
        res = LibBytes.concat(sigBuffer, proofData);
    }

    /// @notice Create a test data for UserOperations.
    function createUOTestData(address sender, bytes[] memory proofs, uint256 signatureThreshold)
        public
        pure
        returns (PackedUserOperation[] memory)
    {
        PackedUserOperation[] memory uOps = new PackedUserOperation[](proofs.length);
        for (uint256 i = 0; i < proofs.length; i++) {
            bytes memory signature = encodeSignature(proofs[i], signatureThreshold);
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
