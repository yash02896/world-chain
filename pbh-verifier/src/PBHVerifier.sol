// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ByteHasher} from "./helpers/ByteHasher.sol";
import {PBHExternalNullifier} from "./helpers/PBHExternalNullifier.sol";
import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import "@BokkyPooBahsDateTimeLibrary/BokkyPooBahsDateTimeLibrary.sol";

contract PBHVerifier {
    using ByteHasher for bytes;

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  ERRORS                                ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when attempting to reuse a nullifier
    error InvalidNullifier();

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  Events                                ///
    //////////////////////////////////////////////////////////////////////////////
    
    /// @notice Emitted when a verifier is updated in the lookup table.
    ///
    /// @param nullifierHash The nullifier hash that was used.
    event PBH(
        uint256 indexed nullifierHash
    );
    
    ///////////////////////////////////////////////////////////////////////////////
    ///                                  Structs                               ///
    //////////////////////////////////////////////////////////////////////////////
    
    struct PBHPayload {
        uint256 root;
        uint256 nullifierHash;
        ExternalNullifier externalNullifier;
        uint256[8] proof;
    }

    /**
    * External Nullifier struct
    * @param pbhNonce              - A nonce between 0 and numPbhPerMonth.
    * @param month                 - An integer representing the current month.
    * @param year                  - An integer representing the current year.
    */
    struct ExternalNullifier {
        uint8 pbhNonce;
        uint16 month;
        uint8 year;
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  Vars                                  ///
    //////////////////////////////////////////////////////////////////////////////

    /// @dev The World ID instance that will be used for verifying proofs
    IWorldIDGroups internal immutable worldId;

    /// @dev The World ID group ID (always 1)
    uint256 internal immutable groupId = 1;
    
    /// @dev Make this configurable
    uint8 internal immutable numPbhPerMonth;

    /// @dev Whether a nullifier hash has been used already. Used to guarantee an action is only performed once by a single person
    mapping(uint256 => bool) internal nullifierHashes;
    
    ///////////////////////////////////////////////////////////////////////////////
    ///                                  Functions                             ///
    //////////////////////////////////////////////////////////////////////////////

    /// @param _worldId The WorldID instance that will verify the proofs
    constructor(
        IWorldIDGroups _worldId,
        uint8 _numPbhPerMonth
    ) {
        worldId = _worldId;
        numPbhPerMonth = _numPbhPerMonth;
    }

    /// @param root The root of the Merkle tree (returned by the JS widget).
    /// @param sender The root of the Merkle tree (returned by the JS widget).
    /// @param nonce The root of the Merkle tree (returned by the JS widget).
    /// @param callData The root of the Merkle tree (returned by the JS widget).
    /// @param nullifierHash The nullifier hash for this proof, preventing double signaling (returned by the JS widget).
    /// @param proof The zero-knowledge proof that demonstrates the claimer is registered with World ID (returned by the JS widget).
    function verifyPbhProof(
        uint256 root,
        address sender,
        uint256 nonce,
        bytes memory callData,
        uint256 pbhExternalNullifier,
        uint256 nullifierHash,
        uint256[8] memory proof
    ) external {
        // First, we make sure this person hasn't done this before
        if (nullifierHashes[nullifierHash]) revert InvalidNullifier();

        // We now generate the signal hash from the sender, nonce, and calldata
        uint256 signalHash = abi.encodePacked(
            sender,
            nonce,
            callData
        ).hashToField();

        // Verify the external nullifier
        PBHExternalNullifier.verify(pbhExternalNullifier, numPbhPerMonth);
         

        // We now verify the provided proof is valid and the user is verified by World ID
        worldId.verifyProof(
            root,
            groupId,
            signalHash,
            nullifierHash,
            pbhExternalNullifier,
            proof
        );

        // We now record the user has done this, so they can't do it again (proof of uniqueness)
        nullifierHashes[nullifierHash] = true;

        emit PBH(nullifierHash);
    }
}

