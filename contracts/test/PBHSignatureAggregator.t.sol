// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {TestSetup} from "./TestSetup.sol";
import {console} from "@forge-std/console.sol";
import {TestUtils} from "./TestUtils.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IPBHEntryPoint} from "../src/interfaces/IPBHEntryPoint.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@BokkyPooBahsDateTimeLibrary/BokkyPooBahsDateTimeLibrary.sol";
import "../src/helpers/PBHExternalNullifier.sol";
import {PBHSignatureAggregator} from "../src/PBHSignatureAggregator.sol";

contract PBHSignatureAggregatorTest is TestSetup {
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

        PackedUserOperation[] memory uoTestFixture =
            TestUtils.createUOTestData(vm, PBH_NONCE_KEY, address(pbh4337Module), address(safe), proofs, ownerKey);
        bytes memory aggregatedSignature = pbhAggregator.aggregateSignatures(uoTestFixture);

        IEntryPoint.UserOpsPerAggregator[] memory userOpsPerAggregator = new IEntryPoint.UserOpsPerAggregator[](1);
        userOpsPerAggregator[0] = IEntryPoint.UserOpsPerAggregator({
            aggregator: pbhAggregator,
            userOps: uoTestFixture,
            signature: aggregatedSignature
        });

        pbhEntryPoint.handleAggregatedOps(userOpsPerAggregator, payable(address(this)));
    }

    function testAggregateSignatures(
        uint256 root,
        uint256 pbhExternalNullifier,
        uint256 nullifierHash,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3,
        uint256 p4,
        uint256 p5,
        uint256 p6,
        uint256 p7
    ) public {
        IPBHEntryPoint.PBHPayload memory proof = IPBHEntryPoint.PBHPayload({
            root: root,
            pbhExternalNullifier: pbhExternalNullifier,
            nullifierHash: nullifierHash,
            proof: [p0, p1, p2, p3, p4, p5, p6, p7]
        });

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = abi.encode(proof);
        proofs[1] = abi.encode(proof);
        PackedUserOperation[] memory uoTestFixture = TestUtils.createUOTestData(
            vm, PBH_NONCE_KEY, address(pbh4337Module), address(pbh4337Module), proofs, ownerKey
        );
        bytes memory aggregatedSignature = pbhAggregator.aggregateSignatures(uoTestFixture);
        IPBHEntryPoint.PBHPayload[] memory decodedProofs =
            abi.decode(aggregatedSignature, (IPBHEntryPoint.PBHPayload[]));
        assertEq(decodedProofs.length, 2, "Decoded proof length should be 1");
        assertEq(decodedProofs[0].root, proof.root, "Root should match");
        assertEq(
            decodedProofs[0].pbhExternalNullifier, proof.pbhExternalNullifier, "PBH External Nullifier should match"
        );
        assertEq(decodedProofs[0].nullifierHash, proof.nullifierHash, "Nullifier Hash should match");
        assertEq(decodedProofs[0].proof[0], proof.proof[0], "Proof should match");
        assertEq(decodedProofs[0].proof[1], proof.proof[1], "Proof should match");
        assertEq(decodedProofs[0].proof[2], proof.proof[2], "Proof should match");
        assertEq(decodedProofs[0].proof[3], proof.proof[3], "Proof should match");
        assertEq(decodedProofs[0].proof[4], proof.proof[4], "Proof should match");
        assertEq(decodedProofs[0].proof[5], proof.proof[5], "Proof should match");
        assertEq(decodedProofs[0].proof[6], proof.proof[6], "Proof should match");
        assertEq(decodedProofs[0].proof[7], proof.proof[7], "Proof should match");
        assertEq(decodedProofs[1].root, proof.root, "Root should match");
        assertEq(
            decodedProofs[1].pbhExternalNullifier, proof.pbhExternalNullifier, "PBH External Nullifier should match"
        );
        assertEq(decodedProofs[1].nullifierHash, proof.nullifierHash, "Nullifier Hash should match");
        assertEq(decodedProofs[1].proof[0], proof.proof[0], "Proof should match");
        assertEq(decodedProofs[1].proof[1], proof.proof[1], "Proof should match");
        assertEq(decodedProofs[1].proof[2], proof.proof[2], "Proof should match");
        assertEq(decodedProofs[1].proof[3], proof.proof[3], "Proof should match");
        assertEq(decodedProofs[1].proof[4], proof.proof[4], "Proof should match");
        assertEq(decodedProofs[1].proof[5], proof.proof[5], "Proof should match");
        assertEq(decodedProofs[1].proof[6], proof.proof[6], "Proof should match");
        assertEq(decodedProofs[1].proof[7], proof.proof[7], "Proof should match");
    }

    // function testAggregateSignatures_VariableThreshold(
    //     uint256 root,
    //     uint256 pbhExternalNullifier,
    //     uint256 nullifierHash,
    //     uint8 threshold,
    //     uint256 p0,
    //     uint256 p1,
    //     uint256 p2,
    //     uint256 p3,
    //     uint256 p4,
    //     uint256 p5,
    //     uint256 p6,
    //     uint256 p7
    // ) public {
    //     deploySafeAndModule(address(pbhAggregator), threshold);
    //     IPBHEntryPoint.PBHPayload memory proof = IPBHEntryPoint.PBHPayload({
    //         root: root,
    //         pbhExternalNullifier: pbhExternalNullifier,
    //         nullifierHash: nullifierHash,
    //         proof: [p0, p1, p2, p3, p4, p5, p6, p7]
    //     });

    //     bytes[] memory proofs = new bytes[](2);
    //     proofs[0] = abi.encode(proof);
    //     proofs[1] = abi.encode(proof);
    //     PackedUserOperation[] memory uoTestFixture = createUOTestData(address(safe), proofs, threshold);
    //     bytes memory aggregatedSignature = pbhAggregator.aggregateSignatures(uoTestFixture);
    //     IPBHEntryPoint.PBHPayload[] memory decodedProofs =
    //         abi.decode(aggregatedSignature, (IPBHEntryPoint.PBHPayload[]));
    //     assertEq(decodedProofs.length, 2, "Decoded proof length should be 1");
    //     assertEq(decodedProofs[0].root, proof.root, "Root should match");
    //     assertEq(
    //         decodedProofs[0].pbhExternalNullifier, proof.pbhExternalNullifier, "PBH External Nullifier should match"
    //     );
    //     assertEq(decodedProofs[0].nullifierHash, proof.nullifierHash, "Nullifier Hash should match");
    //     assertEq(decodedProofs[0].proof[0], proof.proof[0], "Proof should match");
    //     assertEq(decodedProofs[0].proof[1], proof.proof[1], "Proof should match");
    //     assertEq(decodedProofs[0].proof[2], proof.proof[2], "Proof should match");
    //     assertEq(decodedProofs[0].proof[3], proof.proof[3], "Proof should match");
    //     assertEq(decodedProofs[0].proof[4], proof.proof[4], "Proof should match");
    //     assertEq(decodedProofs[0].proof[5], proof.proof[5], "Proof should match");
    //     assertEq(decodedProofs[0].proof[6], proof.proof[6], "Proof should match");
    //     assertEq(decodedProofs[0].proof[7], proof.proof[7], "Proof should match");
    //     assertEq(decodedProofs[1].root, proof.root, "Root should match");
    //     assertEq(
    //         decodedProofs[1].pbhExternalNullifier, proof.pbhExternalNullifier, "PBH External Nullifier should match"
    //     );
    //     assertEq(decodedProofs[1].nullifierHash, proof.nullifierHash, "Nullifier Hash should match");
    //     assertEq(decodedProofs[1].proof[0], proof.proof[0], "Proof should match");
    //     assertEq(decodedProofs[1].proof[1], proof.proof[1], "Proof should match");
    //     assertEq(decodedProofs[1].proof[2], proof.proof[2], "Proof should match");
    //     assertEq(decodedProofs[1].proof[3], proof.proof[3], "Proof should match");
    //     assertEq(decodedProofs[1].proof[4], proof.proof[4], "Proof should match");
    //     assertEq(decodedProofs[1].proof[5], proof.proof[5], "Proof should match");
    //     assertEq(decodedProofs[1].proof[6], proof.proof[6], "Proof should match");
    //     assertEq(decodedProofs[1].proof[7], proof.proof[7], "Proof should match");
    // }

    function testFailAggregateSignatures_InvalidSignatureLength() public {
        IPBHEntryPoint.PBHPayload memory proof = IPBHEntryPoint.PBHPayload({
            root: 0,
            pbhExternalNullifier: 0,
            nullifierHash: 0,
            proof: [uint256(1), 0, 0, 0, 0, 0, 0, 0]
        });

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = abi.encode(proof);
        proofs[1] = abi.encode(proof);
        PackedUserOperation[] memory uoTestFixture = TestUtils.createUOTestData(
            vm, PBH_NONCE_KEY, address(pbh4337Module), address(pbh4337Module), proofs, ownerKey
        );
        uoTestFixture[0].signature = new bytes(12);
        vm.expectRevert(PBHSignatureAggregator.InvalidSignatureLength.selector);
        pbhAggregator.aggregateSignatures(uoTestFixture);
    }

    receive() external payable {}
}
