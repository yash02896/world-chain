// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// import {CheckInitialized} from "../../utils/CheckInitialized.sol";
import {TestSetup} from "./TestSetup.sol";
import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";

import {CheckInitialized} from "@world-id-contracts/utils/CheckInitialized.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {WorldIDImpl} from "@world-id-contracts/abstract/WorldIDImpl.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PBHEntryPoint} from "../src/PBHEntryPoint.sol";
import {PBHEntryPointImplV1 as PBHEntryPointImpl} from "../src/PBHEntryPointImplV1.sol";
import {IPBHEntryPoint} from "../src/interfaces/IPBHEntryPoint.sol";
import {IMulticall3} from "../src/interfaces/IMulticall3.sol";

/// @title PBHEntryPoint Uninit Tests
/// @notice Contains tests for the pbhVerifier
/// @author Worldcoin
contract PBHEntryPointUninit is TestSetup {
    /// @notice Ensures that verifyPbh cannot be called on an uninit PBHEntryPoint.
    function testCannotVerifyPbhUninit() public {
        IPBHEntryPoint.PBHPayload memory pbhPayload = IPBHEntryPoint.PBHPayload({
            root: 1,
            pbhExternalNullifier: 0,
            nullifierHash: 1,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        makeUninitPBHEntryPoint();
        vm.prank(address(0));
        bytes memory callData = abi.encodeCall(IPBHEntryPoint.verifyPbh, (0, pbhPayload));
        bytes memory expectedError = abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);
        assertCallFailsOn(address(pbhEntryPoint), callData, expectedError);
    }

    /// @notice Ensures that HandleAggregatedOps cannot be called on an uninit PBHEntryPoint.
    function testCannotHandleAggregatedOpsUninit() public {
        IEntryPoint.UserOpsPerAggregator[] memory opsPerAggregator;
        address payable beneficiary = payable(address(0));

        makeUninitPBHEntryPoint();
        vm.prank(address(0));
        bytes memory callData = abi.encodeCall(IPBHEntryPoint.handleAggregatedOps, (opsPerAggregator, beneficiary));
        bytes memory expectedError = abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);
        assertCallFailsOn(address(pbhEntryPoint), callData, expectedError);
    }

    /// @notice Ensures that validateSignaturesCallback cannot be called on an uninit PBHEntryPoint.
    function testCannotValidateSignaturesCallbackUninit() public {
        makeUninitPBHEntryPoint();
        vm.prank(address(0));
        bytes memory callData = abi.encodeCall(IPBHEntryPoint.validateSignaturesCallback, (""));
        bytes memory expectedError = abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);
        assertCallFailsOn(address(pbhEntryPoint), callData, expectedError);
    }

    /// @notice Ensures that pbhMulticall cannot be called on an uninit PBHEntryPoint.
    function testCannotPbhMultiCallUninit() public {
        IMulticall3.Call3[] memory calls;
        IPBHEntryPoint.PBHPayload memory pbhPayload = IPBHEntryPoint.PBHPayload({
            root: 1,
            pbhExternalNullifier: 0,
            nullifierHash: 1,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        makeUninitPBHEntryPoint();
        vm.prank(address(0));
        bytes memory callData = abi.encodeCall(IPBHEntryPoint.pbhMulticall, (calls, pbhPayload));
        bytes memory expectedError = abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);
        assertCallFailsOn(address(pbhEntryPoint), callData, expectedError);
    }

    /// @notice Ensures that setNumPbhPerMonth cannot be called on an uninit PBHEntryPoint.
    function testCannotSetNumPbhPerMonthUninit() public {
        makeUninitPBHEntryPoint();
        vm.prank(address(0));
        bytes memory callData = abi.encodeCall(IPBHEntryPoint.setNumPbhPerMonth, (0));
        bytes memory expectedError = abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);
        assertCallFailsOn(address(pbhEntryPoint), callData, expectedError);
    }

    /// @notice Ensures that setWorldId cannot be called on an uninit PBHEntryPoint.
    function testCannotSetWorldIdUninit() public {
        makeUninitPBHEntryPoint();
        vm.prank(address(0));
        bytes memory callData = abi.encodeCall(IPBHEntryPoint.setWorldId, (address(0)));
        bytes memory expectedError = abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);
        assertCallFailsOn(address(pbhEntryPoint), callData, expectedError);
    }
}
