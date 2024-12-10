// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ByteHasher} from "./helpers/ByteHasher.sol";
import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import {BaseAccount} from "@account-abstraction/core/BaseAccount.sol";
import {BLSSignatureAggregator} from "@account-abstraction/samples/bls/BLSSignatureAggregator.sol";

contract PBHSignatureAggregator is BLSSignatureAggregator {

	function validateSignatures(PackedUserOperation[] calldata userOps, bytes calldata signature)
	    external view override {
			super.validateSignatures(userOps, signature)

          for (uint256 i = 0; i < userOpsLen; i++) {
            PackedUserOperation memory userOp = userOps[i];

						pbhValidator.validateUserOp(userOp);
						
        }
    }
}
