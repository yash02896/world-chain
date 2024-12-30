// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// import {CheckInitialized} from "../../utils/CheckInitialized.sol";
import {Setup} from "./Setup.sol";
import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";

import {CheckInitialized} from "@world-id-contracts/utils/CheckInitialized.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {WorldIDImpl} from "@world-id-contracts/abstract/WorldIDImpl.sol";

import {PBHEntryPoint} from "../src/PBHEntryPoint.sol";
// import {PBHVerifier} from "../src/PBHVerifier.sol";
import {PBHEntryPointImplV1 as PBHEntryPointImpl} from "../src/PBHEntryPointImplV1.sol";
import {IPBHEntryPoint} from "../src/interfaces/IPBHEntryPoint.sol";

/// @title PBHVerifier Uninit Tests
/// @notice Contains tests for the pbhVerifier
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract PBHEntryPointUninit is Setup {
    /// @notice Ensures that verifyPbh cannot be called on an uninit PBHEntryPoint.
    function testCannotVerifyUninit() public {
        IPBHEntryPoint.PBHPayload memory pbhPayload = IPBHEntryPoint.PBHPayload({
            root: 1,
            pbhExternalNullifier: 0,
            nullifierHash: 1,
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        });

        makeUninitPBHEntryPoint();
        bytes memory callData = abi.encodeCall(IPBHEntryPoint.verifyPbh, (0, pbhPayload));
        bytes memory expectedError = abi.encodeWithSelector(CheckInitialized.ImplementationNotInitialized.selector);

        assertCallFailsOn(pbhEntryPointImpl, callData, expectedError);
    }
}
