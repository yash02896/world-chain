// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {MockWorldIDGroups} from "./mocks/MockWorldIDGroups.sol";
import {IPBHVerifier} from "../src/interfaces/IPBHVerifier.sol";
import {PBHVerifierImplV1} from "../src/PBHVerifierImplV1.sol";
import {PBHVerifier} from "../src/PBHVerifier.sol";
import {PBHSignatureAggregator} from "../src/PBHSignatureAggregator.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IAggregator} from "@account-abstraction/contracts/interfaces/IAggregator.sol";
import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import {PBHVerifierTest} from "./PBHVerifierTest.sol";
import {MockSafe} from "./mocks/MockSafe.sol";

contract Setup is Test {

    ///////////////////////////////////////////////////////////////////////////////
    ///                                TEST DATA                                ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice The Deployed EntryPoint on Ethereum Mainnet.
    IEntryPoint public immutable entryPoint = IEntryPoint(address(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789));

    /// @notice Worldcoin Contracts
    IPBHVerifier public pbhVerifier;
    IAggregator public pbhSignatureAggregator;
    IWorldIDGroups public worldIDGroups;
    IAccount public safe;

    /// @notice The VM contract.
    Vm public vm;

    /// @notice Test Fixture Data
    PackedUserOperation[] public testOps;

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  Setup                                  ///
    ///////////////////////////////////////////////////////////////////////////////

    function setUp() public {
        worldIDGroups = IWorldIDGroups(worldIDGroups());
        pbhVerifier = IPBHVerifier(pbhVerifier(address(worldIDGroups), address(entryPoint), 100));
        pbhSignatureAggregator = IAggregator(pbhSignatureAggregator(address(pbhVerifier)));
        safe = IAccount(mockSafe(address(pbhSignatureAggregator)));

        vm = new Vm(HEVM_ADDRESS);
        vm.deal(safe, type(uint128).max);
    }

    function _pbhVerifierImpl() internal view returns (address) {
        return new PBHVerifierImplV1();
    }

    function _mockSafe(address pbhAggregator) internal view returns (address) {
        return new MockSafe(pbhAggregator);
    }

    function _pbhSignatureAggregator(address pbhVerifier) internal view returns (address) {
        return new PBHSignatureAggregator(pbhVerifier);
    }

    function _pbhVerifier(address worldIDGroups, address entryPoint, uint256 maxOperations)
        internal
        view
        returns (address)
    {
        bytes memory initCallData =
            abi.encodeCall(PBHVerifierImpl.initialize, (worldIDGroups, entryPoint, maxOperations));
        return new PBHVerifier(pbhVerifierImpl(), initCallData);
    }

    function _worldIDGroups() internal view returns (address) {
        return new MockWorldIDGroups();
    }

    function _mockUserOperations() internal view returns (PackedUserOperation[] memory) {
//         struct PackedUserOperation {
//     address sender;
//     uint256 nonce;
//     bytes initCode;
//     bytes callData;
//     bytes32 accountGasLimits;
//     uint256 preVerificationGas;
//     bytes32 gasFees;
//     bytes paymasterAndData;
//     bytes signature;
// }
        return new PackedUserOperation[](0);
    }

    function _mockUserOperation() internal view returns (PackedUserOperation memory) {
        
        return PackedUserOperation(address(safe), 0, new bytes(0), bytes(0), 0, 0, 0, "", "");
    }
}
