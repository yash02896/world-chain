// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
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
import {IWorldID} from "@world-id-contracts/interfaces/IWorldID.sol";

/// @title PBHEntryPointImplV1ProxyTest
/// @notice Contains tests asserting the contract can only be called via proxy
/// @author Worldcoin
contract PBHEntryPointImplV1ProxyTest is Test {
    IPBHEntryPoint pbhEntryPoint;

    function setUp() public {
        pbhEntryPoint = IPBHEntryPoint(address(new PBHEntryPointImplV1()));
    }

    function test_verifyPbh_RevertIf_NotProxy() public {
        IPBHEntryPoint.PBHPayload memory pbhPayload = IPBHEntryPoint.PBHPayload({
            root: 1,
            pbhExternalNullifier: 0,
            nullifierHash: 1,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        vm.expectRevert("Function must be called through active proxy");
        address(pbhEntryPoint).delegatecall(abi.encodeWithSelector(pbhEntryPoint.verifyPbh.selector, 0, pbhPayload));
    }

    function test_handleAggregatedOps_RevertIf_NotProxy() public {
        IEntryPoint.UserOpsPerAggregator[] memory opsPerAggregator;
        address payable beneficiary = payable(address(0));

        vm.expectRevert("Function must be called through active proxy");
        address(pbhEntryPoint).delegatecall(
            abi.encodeWithSelector(pbhEntryPoint.handleAggregatedOps.selector, opsPerAggregator, beneficiary)
        );
    }

    function test_validateSignaturesCallback_RevertIf_NotProxy() public {
        vm.expectRevert("Function must be called through active proxy");
        address(pbhEntryPoint).delegatecall(
            abi.encodeWithSelector(pbhEntryPoint.validateSignaturesCallback.selector, bytes32(0))
        );
    }

    function test_pbhMulticall_RevertIf_Uninitialized() public {
        IMulticall3.Call3[] memory calls;
        IPBHEntryPoint.PBHPayload memory pbhPayload = IPBHEntryPoint.PBHPayload({
            root: 1,
            pbhExternalNullifier: 0,
            nullifierHash: 1,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        vm.expectRevert("Function must be called through active proxy");
        address(pbhEntryPoint).delegatecall(
            abi.encodeWithSelector(pbhEntryPoint.pbhMulticall.selector, calls, pbhPayload)
        );
    }

    function test_setNumPbhPerMonth_RevertIf_Uninitialized() public {
        vm.expectRevert("Function must be called through active proxy");
        address(pbhEntryPoint).delegatecall(abi.encodeWithSelector(pbhEntryPoint.setNumPbhPerMonth.selector, 30));
    }

    function test_setWorldId_RevertIf_Uninitialized() public {
        vm.expectRevert("Function must be called through active proxy");
        address(pbhEntryPoint).delegatecall(abi.encodeWithSelector(pbhEntryPoint.setWorldId.selector, address(0)));
    }
}
