// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {PBHVerifierTest} from "./PBHVerifierTest.sol";
import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";

import {CheckInitialized} from "@world-id-contracts/utils/CheckInitialized.sol";
import {Ownable2StepUpgradeable} from "contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {OwnableUpgradeable} from "contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {WorldIDImpl} from "@world-id-contracts/abstract/WorldIDImpl.sol";
import {MockWorldIDGroups} from "./MockWorldIDGroups.sol";

import {PBHVerifierImplV1 as PBHVerifierImpl} from "../src/PBHVerifierImplV1.sol";
import {PBHVerifier} from "../src/PBHVerifier.sol";

/// @title World ID PBHVerifer Routing Tests
/// @notice Contains tests for the WorldID pbhVerifier
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract PBHVerifierRouting is PBHVerifierTest {
        // using ByteHasher for bytes;

    event PBH(
        uint256 indexed root,
        address indexed sender,
        uint256  nonce,
        bytes callData,
        uint256 indexed pbhExternalNullifier,
        uint256 nullifierHash,
        uint256[8] proof
    );

    // Mocks and addresses
    MockWorldIDGroups internal mockWorldIDGroups = new MockWorldIDGroups();
    address internal sender = address(0x123);
    uint256 internal testRoot = 1;
    uint256 internal testNonce = 1;
    bytes internal testCallData = hex"deadbeef";
    uint256 internal testPBHExternalNullifier = 1;//testVerifyPbhProofSuccess;
    uint256 internal testNullifierHash = 1;
    uint256[8] internal testProof = [uint256(0), 0, 0, 0, 0, 0, 0, 0];

    /// @notice Test that a valid proof is verified correctly.
    function testVerifyPbhProofSuccess() public {
        mockWorldIDGroups.setVerifyProofSuccess(true);

        // vm.expectEmit(true, true, true, true);
        emit PBH(
            testRoot,
            sender,
            testNonce,
            testCallData,
            testPBHExternalNullifier,
            testNullifierHash,
            testProof
        );

        vm.prank(sender); // Simulate the sender's context
        PBHVerifierImpl(address(pbhVerifier)).verifyPbhProof(
            testRoot,
            sender,
            testNonce,
            testCallData,
            testPBHExternalNullifier,
            testNullifierHash,
            testProof
        );

        // bool used = PBHVerifierImpl(address(pbhVerifier)).nullifierHashes(
        //     testNullifierHash
        // );
        // assertTrue(used, "Nullifier hash should be marked as used");
    }

}
