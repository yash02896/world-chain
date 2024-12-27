// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Setup} from "./Setup.sol";
import {console} from "@forge-std/console.sol";
import {TestUtils} from "./TestUtils.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IPBHEntryPoint} from "../src/interfaces/IPBHEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@BokkyPooBahsDateTimeLibrary/BokkyPooBahsDateTimeLibrary.sol";
import "../src/helpers/PBHExternalNullifier.sol";
import {PBHSignatureAggregator} from "../src/PBHSignatureAggregator.sol";

contract PBHSignatureAggregatorTest is TestUtils, Setup {
    function setUp() public override {
        super.setUp();
    }

    function testFullFlow() public {
        uint256 timestamp = block.timestamp;
        uint8 month = uint8(BokkyPooBahsDateTimeLibrary.getMonth(timestamp));
        uint16 year = uint16(BokkyPooBahsDateTimeLibrary.getYear(timestamp));
        uint256 encoded = PBHExternalNullifier.encode(PBHExternalNullifier.V1, 0, month, year);

        worldIDGroups.setVerifyProofSuccess(true);
        IPBHEntryPoint.PBHPayload memory proof0 = IPBHEntryPoint.PBHPayload({
            root: 1,
            pbhExternalNullifier: encoded,
            nullifierHash: 0,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        IPBHEntryPoint.PBHPayload memory proof1 = IPBHEntryPoint.PBHPayload({
            root: 2,
            pbhExternalNullifier: encoded,
            nullifierHash: 1,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = abi.encode(proof0);
        proofs[1] = abi.encode(proof1);

        PackedUserOperation[] memory uoTestFixture = createUOTestData(address(safe), proofs, 1);
        bytes memory aggregatedSignature = pbhAggregator.aggregateSignatures(uoTestFixture);

        IEntryPoint.UserOpsPerAggregator[] memory userOpsPerAggregator = new IEntryPoint.UserOpsPerAggregator[](1);
        userOpsPerAggregator[0] = IEntryPoint.UserOpsPerAggregator({
            aggregator: pbhAggregator,
            userOps: uoTestFixture,
            signature: aggregatedSignature
        });

        pbhEntryPoint.handleAggregatedOps(userOpsPerAggregator, payable(address(this)));
    }

    function testAggregateSignatures(uint256 root, uint256 pbhExternalNullifier, uint256 nullifierHash) public {
        IPBHEntryPoint.PBHPayload memory proof = IPBHEntryPoint.PBHPayload({
            root: root,
            pbhExternalNullifier: pbhExternalNullifier,
            nullifierHash: nullifierHash,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = abi.encode(proof);
        proofs[1] = abi.encode(proof);
        PackedUserOperation[] memory uoTestFixture = createUOTestData(address(safe), proofs, 1);
        bytes memory aggregatedSignature = pbhAggregator.aggregateSignatures(uoTestFixture);
        IPBHEntryPoint.PBHPayload[] memory decodedProofs =
            abi.decode(aggregatedSignature, (IPBHEntryPoint.PBHPayload[]));
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

    function testAggregateSignatures_VariableThreshold(
        uint256 root,
        uint256 pbhExternalNullifier,
        uint256 nullifierHash,
        uint8 threshold
    ) public {
        deploySafeAccount(address(pbhAggregator), threshold);
        IPBHEntryPoint.PBHPayload memory proof = IPBHEntryPoint.PBHPayload({
            root: root,
            pbhExternalNullifier: pbhExternalNullifier,
            nullifierHash: nullifierHash,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = abi.encode(proof);
        proofs[1] = abi.encode(proof);
        PackedUserOperation[] memory uoTestFixture = createUOTestData(address(safe), proofs, threshold);
        bytes memory aggregatedSignature = pbhAggregator.aggregateSignatures(uoTestFixture);
        IPBHEntryPoint.PBHPayload[] memory decodedProofs =
            abi.decode(aggregatedSignature, (IPBHEntryPoint.PBHPayload[]));
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

    function testFailAggregateSignatures_InvalidSignatureLength(
        uint256 root,
        uint256 pbhExternalNullifier,
        uint256 nullifierHash
    ) public {
        IPBHEntryPoint.PBHPayload memory proof = IPBHEntryPoint.PBHPayload({
            root: root,
            pbhExternalNullifier: pbhExternalNullifier,
            nullifierHash: nullifierHash,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = abi.encode(proof);
        proofs[1] = abi.encode(proof);
        PackedUserOperation[] memory uoTestFixture = createUOTestData(address(safe), proofs, 1);
        uoTestFixture[0].signature = new bytes(12);
        pbhAggregator.aggregateSignatures(uoTestFixture);
        vm.expectRevert(PBHSignatureAggregator.InvalidSignatureLength.selector);
    }

    receive() external payable {}
}
