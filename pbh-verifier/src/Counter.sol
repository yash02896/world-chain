// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract PBHValidator {

  mapping (externalNullifier bytes32 => pbhNonce uint16) pbhNonces;

	function validateUserOp(PackedUserOperation calldata userOp)
	    external view override { 
		    // Decode proof from signature
		   (Proof proof, _) = abi.decode(userOp.signature, (Proof, bytes));
		   
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
}
