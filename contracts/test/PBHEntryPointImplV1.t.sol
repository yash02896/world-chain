// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import {MockWorldIDGroups} from "./mocks/MockWorldIDGroups.sol";
import {CheckInitialized} from "@world-id-contracts/utils/CheckInitialized.sol";
import {WorldIDImpl} from "@world-id-contracts/abstract/WorldIDImpl.sol";
import {ByteHasher} from "@helpers/ByteHasher.sol";
import {IPBHEntryPoint} from "../src/interfaces/IPBHEntryPoint.sol";
import {IWorldID} from "../src/interfaces/IWorldID.sol";
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
    function test_initialize(IWorldID worldId, IEntryPoint entryPoint, uint8 numPbh, address multicall) public {
        vm.assume(address(worldId) != address(0) && address(entryPoint) != address(0) && multicall != address(0));
        vm.assume(numPbh > 0);

        pbhEntryPointImpl = address(new PBHEntryPointImplV1());
        bytes memory initCallData =
            abi.encodeCall(PBHEntryPointImplV1.initialize, (worldId, entryPoint, numPbh, multicall));

        vm.expectEmit(true, true, true, true);
        emit PBHEntryPointImplV1.PBHEntryPointImplInitialized(worldId, entryPoint, numPbh, multicall);
        IPBHEntryPoint(address(new PBHEntryPoint(pbhEntryPointImpl, initCallData)));
    }

    function test_initialize_RevertIf_AddressZero() public {
        IWorldID worldId = IWorldID(address(1));
        IEntryPoint entryPoint = IEntryPoint(address(2));
        uint8 numPbh = 30;
        address multicall = address(3);

        pbhEntryPointImpl = address(new PBHEntryPointImplV1());

        // Expect revert when worldId is address(0)
        bytes memory initCallData =
            abi.encodeCall(PBHEntryPointImplV1.initialize, (IWorldID(address(0)), entryPoint, numPbh, multicall));
        vm.expectRevert(PBHEntryPointImplV1.AddressZero.selector);
        IPBHEntryPoint(address(new PBHEntryPoint(pbhEntryPointImpl, initCallData)));

        // Expect revert when entrypoint is address(0)
        initCallData =
            abi.encodeCall(PBHEntryPointImplV1.initialize, (worldId, IEntryPoint(address(0)), numPbh, multicall));
        vm.expectRevert(PBHEntryPointImplV1.AddressZero.selector);
        IPBHEntryPoint(address(new PBHEntryPoint(pbhEntryPointImpl, initCallData)));

        // Expect revert when multicall3 is address(0)
        initCallData = abi.encodeCall(PBHEntryPointImplV1.initialize, (worldId, entryPoint, numPbh, address(0)));
        vm.expectRevert(PBHEntryPointImplV1.AddressZero.selector);
        IPBHEntryPoint(address(new PBHEntryPoint(pbhEntryPointImpl, initCallData)));
    }

    function test_initialize_RevertIf_InvalidNumPbhPerMonth() public {
        IWorldID worldId = IWorldID(address(1));
        IEntryPoint entryPoint = IEntryPoint(address(2));
        uint8 numPbh = 0;
        address multicall = address(3);

        pbhEntryPointImpl = address(new PBHEntryPointImplV1());

        bytes memory initCallData =
            abi.encodeCall(PBHEntryPointImplV1.initialize, (worldId, entryPoint, numPbh, multicall));
        vm.expectRevert(PBHEntryPointImplV1.InvalidNumPbhPerMonth.selector);
        IPBHEntryPoint(address(new PBHEntryPoint(pbhEntryPointImpl, initCallData)));
    }

    function test_initialize_RevertIf_AlreadyInitialized() public {
        IWorldID worldId = IWorldID(address(1));
        IEntryPoint entryPoint = IEntryPoint(address(2));
        uint8 numPbh = 30;
        address multicall = address(3);

        pbhEntryPointImpl = address(new PBHEntryPointImplV1());
        bytes memory initCallData =
            abi.encodeCall(PBHEntryPointImplV1.initialize, (worldId, entryPoint, numPbh, multicall));

        vm.expectEmit(true, true, true, true);
        emit PBHEntryPointImplV1.PBHEntryPointImplInitialized(worldId, entryPoint, numPbh, multicall);
        IPBHEntryPoint pbhEntryPoint = IPBHEntryPoint(address(new PBHEntryPoint(pbhEntryPointImpl, initCallData)));

        vm.expectRevert("Initializable: contract is already initialized");
        pbhEntryPoint.initialize(worldId, entryPoint, numPbh, multicall);
    }

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
