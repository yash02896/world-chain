// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import {MockWorldIDGroups} from "./mocks/MockWorldIDGroups.sol";
import {CheckInitialized} from "@world-id-contracts/utils/CheckInitialized.sol";
import {WorldIDImpl} from "@world-id-contracts/abstract/WorldIDImpl.sol";
import {ByteHasher} from "@helpers/ByteHasher.sol";
import {IPBHEntryPoint} from "../src/interfaces/IPBHEntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PBHEntryPointImplV1} from "../src/PBHEntryPointImplV1.sol";
import {PBHEntryPoint} from "../src/PBHEntryPoint.sol";
import {TestSetup} from "./TestSetup.sol";
import {TestUtils} from "./TestUtils.sol";
import "@helpers/PBHExternalNullifier.sol";

/// @title PBHVerifer Verify Tests
/// @notice Contains tests for the pbhVerifier
/// @author Worldcoin
contract PBHEntryPointImplV1Test is TestSetup {
    using ByteHasher for bytes;

    event PBH(address indexed sender, IPBHEntryPoint.PBHPayload payload);
    event NumPbhPerMonthSet(uint8 indexed numPbhPerMonth);
    event WorldIdSet(address indexed worldId);

    // TODO: move this to test utils
    /// @notice Test payload for the PBHVerifier
    IPBHEntryPoint.PBHPayload public testPayload = IPBHEntryPoint.PBHPayload({
        root: 1,
        pbhExternalNullifier: TestUtils.getValidPBHExternalNullifier(0),
        nullifierHash: 1,
        proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
    });

    uint256 internal nonce = 1;
    address internal sender = address(0x123);
    bytes internal testCallData = hex"deadbeef";

    // TODO:
    function test_verifyPbh() public {
        // uint256 signalHash = abi.encodePacked(sender, nonce, testCallData).hashToField();

        // pbhEntryPoint.verifyPbh(signalHash, testPayload);

        // // TODO: update to use mock work id
        // // Expect revert when proof verification fails
        // MockWorldIDGroups(address(worldIDGroups)).setVerifyProofSuccess(false);
        // vm.expectRevert("Proof verification failed");
        // pbhEntryPoint.verifyPbh(signalHash, testPayload);

        // // Now expect success
        // MockWorldIDGroups(address(worldIDGroups)).setVerifyProofSuccess(true);
        // pbhEntryPoint.verifyPbh(signalHash, testPayload);
    }

    // TODO:
    function test_verifyPbh_RevertIf_InvalidNullifier() public {}

    // TODO: verify proof if worldid addr is set?

    // TODO:
    function test_handleAggregatedOps() public {}

    // TODO:
    function test_handleAggregatedOps_RevertIf_Reentrancy() public {}

    // TODO:
    function test_valdiateSignaturesCallback() public {}

    // TODO:
    function test_validateSignaturesCallback_RevertIf_IncorrectHashedOps() public {}

    // TODO:
    function test_pbhMulticall() public {}

    // TODO:
    function test_pbhMulticall_RevertIf_Reentrancy() public {}

    function test_setNumPbhPerMonth(uint8 numPbh) public {
        vm.assume(numPbh > 0);

        vm.prank(OWNER);
        vm.expectEmit(true, true, true, true);
        emit NumPbhPerMonthSet(numPbh);
        pbhEntryPoint.setNumPbhPerMonth(numPbh);
    }

    function test_setNumPbhPerMonth_RevertIf_NotOwner(uint8 numPbh) public {
        vm.expectRevert("Ownable: caller is not the owner");
        pbhEntryPoint.setNumPbhPerMonth(numPbh);
    }

    function test_setNumPbhPerMonth_RevertIf_InvalidNumPbhPerMonth() public {
        vm.prank(OWNER);
        vm.expectRevert(PBHEntryPointImplV1.InvalidNumPbhPerMonth.selector);
        pbhEntryPoint.setNumPbhPerMonth(0);
    }

    function test_setWorldId(address addr) public {
        vm.assume(addr != address(0));

        vm.prank(OWNER);
        vm.expectEmit(true, false, false, false);
        emit WorldIdSet(addr);
        pbhEntryPoint.setWorldId(addr);
    }

    function test_setWorldId_RevertIf_NotOwner(address addr) public {
        vm.expectRevert("Ownable: caller is not the owner");
        pbhEntryPoint.setWorldId(addr);
    }

    // TODO: only init and onlyproxy tests?
}
