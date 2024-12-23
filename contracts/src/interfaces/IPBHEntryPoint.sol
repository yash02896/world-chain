// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IPBHVerifier} from "./IPBHVerifier.sol";

interface IPBHEntryPoint is IPBHVerifier {
    function handleAggregatedOps(
        IEntryPoint.UserOpsPerAggregator[] calldata opsPerAggregator,
        address payable beneficiary
    ) external;
    function initialize(IWorldIDGroups worldId, IEntryPoint entryPoint, uint8 _numPbhPerMonth) external;
    function validateSignaturesCallback(bytes32 hashedOps) external view;
}
