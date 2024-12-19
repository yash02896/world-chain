// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Setup} from "./Setup.sol";
import {IPBHVerifier} from "../src/interfaces/IPBHVerifier.sol";
import {console} from "@forge-std/console.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract PBHSignatureAggregatorTest is Setup {
    function setUp() public override {
        super.setUp();
    }

    function testAggregateSignatures(uint256 root, uint256 pbhExternalNullifier, uint256 nullifierHash) public {
        IPBHVerifier.PBHPayload memory proof = IPBHVerifier.PBHPayload({
            root: root,
            pbhExternalNullifier: pbhExternalNullifier,
            nullifierHash: nullifierHash,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        PackedUserOperation[] memory uoTestFixture = createUOTestData(proof);
        bytes memory aggregatedSignature = pbhAggregator.aggregateSignatures(uoTestFixture);
        IPBHVerifier.PBHPayload[] memory decodedProofs = abi.decode(aggregatedSignature, (IPBHVerifier.PBHPayload[]));
        assertEq(decodedProofs.length, 2, "Decoded proof length should be 1");
        assertEq(decodedProofs[0].root, proof.root, "Root should match");
        assertEq(
            decodedProofs[0].pbhExternalNullifier, proof.pbhExternalNullifier, "PBH External Nullifier should match"
        );
        assertEq(decodedProofs[0].nullifierHash, proof.nullifierHash, "Nullifier Hash should match");

        assertEq(decodedProofs[1].root, proof.root, "Root should match");
        assertEq(
            decodedProofs[1].pbhExternalNullifier, proof.pbhExternalNullifier, "PBH External Nullifier should match"
        );
        assertEq(decodedProofs[1].nullifierHash, proof.nullifierHash, "Nullifier Hash should match");

    }

    function createUOTestData(IPBHVerifier.PBHPayload memory proof) public view returns (PackedUserOperation[] memory) {
        PackedUserOperation[] memory uOps = new PackedUserOperation[](2);
        bytes memory proofData = abi.encode(proof);
        bytes memory sigBuffer = new bytes(65);
        bytes memory signature = new bytes(417);
        assembly ("memory-safe") {
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
            mstore(add(add(signature, 65), 288), mload(add(proofData, 288)))
            mstore(add(add(signature, 65), 320), mload(add(proofData, 320)))
        }

        PackedUserOperation memory baseUO = PackedUserOperation({
            sender: address(safe),
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
