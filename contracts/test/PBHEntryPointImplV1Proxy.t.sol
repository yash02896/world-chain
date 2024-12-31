// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import {CheckInitialized} from "@world-id-contracts/utils/CheckInitialized.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {WorldIDImpl} from "@world-id-contracts/abstract/WorldIDImpl.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PBHEntryPoint} from "../src/PBHEntryPoint.sol";
import {PBHEntryPointImplV1} from "../src/PBHEntryPointImplV1.sol";
import {IPBHEntryPoint} from "../src/interfaces/IPBHEntryPoint.sol";
import {IMulticall3} from "../src/interfaces/IMulticall3.sol";
import {IWorldID} from "../src/interfaces/IWorldID.sol";

/// @title PBHEntryPointImpV1ProxyTest
/// @notice Contains tests asserting that the contract can only be called by the proxy
/// @author Worldcoin
contract PBHEntryPointImpV1ProxyTest is Test {
    IPBHEntryPoint pBHEntryPoint;

    function setup() public {
        IWorldID worldId = IWorldID(address(1));
        IEntryPoint entryPoint = IEntryPoint(address(2));
        uint8 numPbh = 30;
        address multicall = address(3);

        pBHEntryPoint = IPBHEntryPoint(address(new PBHEntryPointImplV1()));
        pBHEntryPoint.initialize(worldId, entryPoint, numPbh, multicall);
    }

    function test_verifyPbh_RevertIf_NotProxy() public {
        IPBHEntryPoint.PBHPayload memory pbhPayload = IPBHEntryPoint.PBHPayload({
            root: 1,
            pbhExternalNullifier: 0,
            nullifierHash: 1,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        vm.expectRevert("Function must be called through active proxy");
        pBHEntryPoint.verifyPbh(0, pbhPayload);
    }

    function test_handleAggregatedOps_RevertIf_NotProxy() public {
        IEntryPoint.UserOpsPerAggregator[] memory opsPerAggregator;
        address payable beneficiary = payable(address(0));

        vm.expectRevert(CheckInitialized.ImplementationNotInitialized.selector);
        pBHEntryPoint.handleAggregatedOps(opsPerAggregator, beneficiary);
    }

    function test_validateSignaturesCallback_RevertIf_NotProxy() public {
        vm.expectRevert(CheckInitialized.ImplementationNotInitialized.selector);
        pBHEntryPoint.validateSignaturesCallback(bytes32(0));
    }

    function test_pbhMulticall_RevertIf_NotProxy() public {
        IMulticall3.Call3[] memory calls;
        IPBHEntryPoint.PBHPayload memory pbhPayload = IPBHEntryPoint.PBHPayload({
            root: 1,
            pbhExternalNullifier: 0,
            nullifierHash: 1,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        vm.expectRevert(CheckInitialized.ImplementationNotInitialized.selector);
        pBHEntryPoint.pbhMulticall(calls, pbhPayload);
    }

    function test_setNumPbhPerMonth_RevertIf_NotProxy() public {
        vm.expectRevert(CheckInitialized.ImplementationNotInitialized.selector);
        pBHEntryPoint.setNumPbhPerMonth(30);
    }

    function test_setWorldId_RevertIf_NotProxy() public {
        vm.expectRevert(CheckInitialized.ImplementationNotInitialized.selector);
        pBHEntryPoint.setWorldId(address(0));
    }
}
