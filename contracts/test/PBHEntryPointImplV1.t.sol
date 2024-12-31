// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import {MockWorldIDGroups} from "./mocks/MockWorldIDGroups.sol";
import {CheckInitialized} from "@world-id-contracts/utils/CheckInitialized.sol";
import {WorldIDImpl} from "@world-id-contracts/abstract/WorldIDImpl.sol";
import {ByteHasher} from "@helpers/ByteHasher.sol";
import {IPBHEntryPoint} from "../src/interfaces/IPBHEntryPoint.sol";
import {PBHEntryPointImplV1} from "../src/PBHEntryPointImplV1.sol";

import "@helpers/PBHExternalNullifier.sol";
import {TestSetup} from "./TestSetup.sol";
import {TestUtils} from "./TestUtils.sol";

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
    function test_initialize() public {}

    // TODO:
    function test_verifyPbh() public {}

    // TODO:
    function test_verifyPbh_RevertIf_InvalidNullifier() public {}

    // TODO: verify proof if worldid addr is set?

    // TODO:
    function test_handleAggregatedOps() public {}

    // TODO:
    function test_valdiateSignaturesCallback() public {}

    // TODO:
    function test_validateSignaturesCallback_RevertIf_IncorrectHashedOps() public {}

    // TODO:
    function test_pbhMulticall() public {}

    function test_setNumPbhPerMonth(uint8 numPbh) public {
        vm.prank(OWNER);
        vm.expectEmit(true, true, true, true);
        emit NumPbhPerMonthSet(numPbh);
        pbhEntryPoint.setNumPbhPerMonth(numPbh);
    }

    function test_setNumPbhPerMonth_RevertIf_NotOwner(uint8 numPbh) public {
        vm.expectRevert("Ownable: caller is not the owner");
        pbhEntryPoint.setNumPbhPerMonth(numPbh);
    }

    function test_setWorldId(address addr) public {
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
