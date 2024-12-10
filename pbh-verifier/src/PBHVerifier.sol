// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ByteHasher} from "./helpers/ByteHasher.sol";
import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";

contract PBHVerifier {
    using ByteHasher for bytes;

    ///////////////////////////////////////////////////////////////////////////////
    ///                                  ERRORS                                ///
    //////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when attempting to reuse a nullifier
    error InvalidNullifier();
    
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
        uint256 groupId;
        uint256 signalHash;
        uint256 nullifierHash;
        uint256 externalNullifierHash;
        uint256[8] proof;
    }

    /// @dev The World ID instance that will be used for verifying proofs
    IWorldIDGroups internal immutable worldId;

    /// @dev The contract's external nullifier hash
    uint256 internal immutable externalNullifier;

    /// @dev The World ID group ID (always 1)
    uint256 internal immutable groupId = 1;

    /// @dev Whether a nullifier hash has been used already. Used to guarantee an action is only performed once by a single person
    mapping(uint256 => bool) internal nullifierHashes;

    /// @param _worldId The WorldID instance that will verify the proofs
    /// @param _appId The World ID app ID
    /// @param _actionId The World ID action ID
    constructor(
        IWorldIDGroups _worldId,
        string memory _appId,
        string memory _actionId
    ) {
        worldId = _worldId;
        externalNullifier = abi
            .encodePacked(abi.encodePacked(_appId).hashToField(), _actionId)
            .hashToField();
    }

    /// @param signal An arbitrary input from the user, usually the user's wallet address (check README for further details)
    /// @param root The root of the Merkle tree (returned by the JS widget).
    /// @param nullifierHash The nullifier hash for this proof, preventing double signaling (returned by the JS widget).
    /// @param proof The zero-knowledge proof that demonstrates the claimer is registered with World ID (returned by the JS widget).
    /// @dev Feel free to rename this method however you want! We've used `claim`, `verify` or `execute` in the past.
    function verifyAndExecute(
        address signal,
        uint256 root,
        uint256 nullifierHash,
        uint256[8] calldata proof
    ) public {
        // First, we make sure this person hasn't done this before
        if (nullifierHashes[nullifierHash]) revert InvalidNullifier();

        // We now verify the provided proof is valid and the user is verified by World ID
        worldId.verifyProof(
            root,
            groupId,
            abi.encodePacked(signal).hashToField(),
            nullifierHash,
            externalNullifier,
            proof
        );

        // We now record the user has done this, so they can't do it again (proof of uniqueness)
        nullifierHashes[nullifierHash] = true;

        // Finally, execute your logic here, for example issue a token, NFT, etc...
        // Make sure to emit some kind of event afterwards!
    }
    
	function validateUserOp(PackedUserOperation calldata userOp) external view override { 
		// Decode proof from signature
		(Proof proof, ) = abi.decode(userOp.signature, (Proof, bytes));
		
			// Validate proof inputs
			// --snip--
			
			// Verify proof
	    worldIdIdentityManager.verifyProof(proof);
	    
	    // Bump PBH nonce
	    pbhNonce = pbhNonces[proof.nullifierHash] + 1;
	    require(pbhNonce <= pbhNonceLimit);
	    pbhNonces[proof.nullifierHash] = pbhNonce;
	    
        // Emit PBH event after successful verification
        // The builder will prioritize bundles where every userop
        // in the bundle emits a PBH event
        emit PBH(proof.nullifierHash, userOpHash);
    }
}

