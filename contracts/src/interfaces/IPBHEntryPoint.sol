// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

interface IPBHEntryPoint {
    /// @notice The Packed World ID Proof data.
    /// @param root The root of the Merkle tree.
    /// @param pbhExternalNullifier The external nullifier for the PBH User Operation.
    /// @param nullifierHash The nullifier hash for the PBH User Operation.
    /// @param proof The Semaphore proof.
    struct PBHPayload {
        uint256 root;
        uint256 pbhExternalNullifier;
        uint256 nullifierHash;
        uint256[8] proof;
    }

    function handleAggregatedOps(
        IEntryPoint.UserOpsPerAggregator[] calldata opsPerAggregator,
        address payable beneficiary
    ) external;

    function initialize(IWorldIDGroups __worldId, IEntryPoint __entryPoint, uint8 _numPbhPerMonth) external;

    function validateSignaturesCallback(bytes32 hashedOps) external view;

    function setNumPbhPerMonth(uint8 _numPbhPerMonth) external;

    function setWorldId(address worldId) external;
}
