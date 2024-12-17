// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";

interface IPBHVerifier {
    function initialize(address __worldId, address __entryPoint, uint8 _numPbhPerMonth) external;

    function verifyPbhProof(
        uint256 root,
        address sender,
        uint256 nonce,
        bytes memory callData,
        uint256 pbhExternalNullifier,
        uint256 nullifierHash,
        uint256[8] memory proof
    ) external;

    function validateSignaturesCallback() external view;

    function setNumPbhPerMonth(uint8 _numPbhPerMonth) external;

    function setWorldId(address worldId) external;
}
