// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@solady/LibBytes.sol";
import "@forge-std/console.sol";
import "@forge-std/Vm.sol";
import "@BokkyPooBahsDateTimeLibrary/BokkyPooBahsDateTimeLibrary.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@helpers/PBHExternalNullifier.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IAggregator} from "@account-abstraction/contracts/interfaces/IAggregator.sol";
import {Mock4337Module} from "./mocks/Mock4337Module.sol";
import {Safe4337Module} from "@4337/Safe4337Module.sol";
import {IPBHEntryPoint} from "../src/interfaces/IPBHEntryPoint.sol";
import {Safe} from "@safe-global/safe-contracts/contracts/Safe.sol";

library TestUtils {
    /// @notice Encodes the ECDSA signature and proof data into a single bytes array.
    function encodeSignature(bytes memory userOpSignature, bytes memory proofData)
        public
        pure
        returns (bytes memory res)
    {
        res = LibBytes.concat(userOpSignature, proofData);
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
            address owner = vm.addr(signingKey);
            bool isOwner = Safe(payable(sender)).isOwner(owner);
            console.logBool(isOwner);
            PackedUserOperation memory uo = createMockUserOperation(sender, nonceKey, i);
            bytes32 operationHash = Mock4337Module(module).getOperationHash(uo);
            bytes memory ecdsaSignature = createUserOpSignature(vm, operationHash, signingKey);
            bytes memory signature = encodeSignature(ecdsaSignature, proofs[i]);
            uo.signature = signature;
            uOps[i] = uo;
        }

        return uOps;
    }

    /// @notice Creates a Mock UserOperation w/ an unsigned signature.
    function createMockUserOperation(address sender, uint256 nonceKey, uint256 nonce)
        public
        pure
        returns (PackedUserOperation memory uo)
    {
        bytes memory data = abi.encodeCall(Safe4337Module.executeUserOp, (address(0), 0, new bytes(0), 0));
        uo = PackedUserOperation({
            sender: sender,
            nonce: nonceKey << 64 + nonce,
            initCode: new bytes(0),
            callData: data,
            accountGasLimits: 0x0000000000000000000000000000ffd300000000000000000000000000000000,
            preVerificationGas: 21000,
            gasFees: 0x0000000000000000000000000000000100000000000000000000000000000001,
            paymasterAndData: new bytes(0),
            signature: abi.encodePacked(uint48(0), uint48(0))
        });
    }

    /// @notice Creates an ECDSA signature from the UserOperation Hash, and signer.
    function createUserOpSignature(Vm vm, bytes32 operationHash, uint256 signingKey) public pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, operationHash);
        bytes memory signature = abi.encodePacked(uint48(0), uint48(0), r, s, v);
        return signature;
    }

    function mockPBHPayload(uint256 root, uint8 pbhNonce, uint256 nullifierHash)
        public
        view
        returns (IPBHEntryPoint.PBHPayload memory)
    {
        return IPBHEntryPoint.PBHPayload({
            root: root,
            pbhExternalNullifier: getPBHExternalNullifier(pbhNonce),
            nullifierHash: nullifierHash,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });
    }

    function getPBHExternalNullifier(uint8 pbhNonce) public view returns (uint256) {
        uint8 month = uint8(BokkyPooBahsDateTimeLibrary.getMonth(block.timestamp));
        uint16 year = uint16(BokkyPooBahsDateTimeLibrary.getYear(block.timestamp));
        return PBHExternalNullifier.encode(PBHExternalNullifier.V1, pbhNonce, month, year);
    }
}
