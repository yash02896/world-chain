// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Setup} from "./Setup.sol";
import {IPBHVerifier} from "../src/interfaces/IPBHVerifier.sol";
import {console} from "@forge-std/console.sol";
import {TestUtils} from "./TestUtils.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract PBHSignatureAggregatorTest is TestUtils, Setup {
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

        PackedUserOperation[] memory uoTestFixture = createUOTestData(address(safe), abi.encode(proof));
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
}
