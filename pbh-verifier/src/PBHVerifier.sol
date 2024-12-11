// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ByteHasher} from "./helpers/ByteHasher.sol";
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
    
    /**
    * User Operation struct
    * @param sender                - The sender account of this request.
    * @param nonce                 - Unique value the sender uses to verify it is not a replay.
    * @param initCode              - If set, the account contract will be created by this constructor/
    * @param callData              - The method call to execute on this account.
    * @param accountGasLimits      - Packed gas limits for validateUserOp and gas limit passed to the callData method call.
    * @param preVerificationGas    - Gas not calculated by the handleOps method, but added to the gas paid.
    *                                Covers batch overhead.
    * @param gasFees               - packed gas fields maxPriorityFeePerGas and maxFeePerGas - Same as EIP-1559 gas parameters.
    * @param paymasterAndData      - If set, this field holds the paymaster address, verification gas limit, postOp gas limit and paymaster-specific extra data
    *                                The paymaster will pay for the transaction instead of the sender.
    * @param signature             - Sender-verified signature over the entire request, the EntryPoint address and the chain ID.
    */
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }

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
    uint256 internal immutable numPbhPerMonth = 30;

    /// @dev Whether a nullifier hash has been used already. Used to guarantee an action is only performed once by a single person
    mapping(uint256 => bool) internal nullifierHashes;
    
    ///////////////////////////////////////////////////////////////////////////////
    ///                                  Functions                             ///
    //////////////////////////////////////////////////////////////////////////////

    /// @param _worldId The WorldID instance that will verify the proofs
    constructor(
        IWorldIDGroups _worldId
    ) {
        worldId = _worldId;
    }

    function get(ExternalNullifier memory externalNullifer) public view {
        require(externalNullifer.year == BokkyPooBahsDateTimeLibrary.getYear(block.timestamp), InvalidExternalNullifierYear()); 
        require(externalNullifer.month == BokkyPooBahsDateTimeLibrary.getMonth(block.timestamp), InvalidExternalNullifierMonth()); 
        require(externalNullifer.pbhNonce <= numPbhPerMonth, InvalidPbhNonce()); 
    }
    
    /// @param externalNullifer The external nullifer is used to ensure that each pbhNonce can be used only once per month.
    ///        The value is encoded by bit shifting 3 uint8s corresponding to 
    ///        * pbhNonce              - An 8 bit nonce between 0 and numPbhPerMonth.
    ///        * month                 - An 8 bit value representing the current month.
    ///        * year                  - A 16 bit value representing the current year.
    ///        [0][0][0][0][0][0][0][0] [0][0][0][0][0][0][0][0] [0][0][0][0][0][0][0][0] [0][0][0][0][pbhNonce][month][yearA][yearB] 
    function verifyExternalNullifier(uint256 externalNullifer) public view {
        require(externalNullifer.year == BokkyPooBahsDateTimeLibrary.getYear(block.timestamp), InvalidExternalNullifierYear()); 
        require(externalNullifer.month == BokkyPooBahsDateTimeLibrary.getMonth(block.timestamp), InvalidExternalNullifierMonth()); 
        require(externalNullifer.pbhNonce <= numPbhPerMonth, InvalidPbhNonce()); 
    }
    function encodeExternalNullifier(uint8 pbhNonce, uint8 month, uint16 year) public pure returns (uint32) {
        require(month >= 1 && month <= 12, "Invalid month");
        require(year <= 9999, "Invalid year");
        return (uint32(year) << 16) | (uint32(month) << 8) | uint32(pbhNonce);
    } 

    /// @param userOp A packed user operation, used to generate the signal hash
    /// @param root The root of the Merkle tree (returned by the JS widget).
    /// @param nullifierHash The nullifier hash for this proof, preventing double signaling (returned by the JS widget).
    /// @param proof The zero-knowledge proof that demonstrates the claimer is registered with World ID (returned by the JS widget).
    function verifyPbhProof(
        PackedUserOperation memory userOp,
        uint256 root,
        uint256 nullifierHash,
        uint256 externalNullifier,
        uint256[8] memory proof
    ) external {
        // First, we make sure this person hasn't done this before
        if (nullifierHashes[nullifierHash]) revert InvalidNullifier();

        // We now generate the signal hash from the sender, nonce, and calldata
        uint256 signalHash = abi.encodePacked(
            userOp.sender,
            userOp.nonce,
            userOp.callData
        ).hashToField();

        // Verify the external nullifier
        verifyExternalNullifier(externalNullifier);

        uint256 externalNullifierHash = abi.encode(externalNullifier).hashToField();

        // We now verify the provided proof is valid and the user is verified by World ID
        worldId.verifyProof(
            root,
            groupId,
            signalHash,
            nullifierHash,
            externalNullifierHash,
            proof
        );

        // We now record the user has done this, so they can't do it again (proof of uniqueness)
        nullifierHashes[nullifierHash] = true;

        emit PBH(nullifierHash);
    }
}

