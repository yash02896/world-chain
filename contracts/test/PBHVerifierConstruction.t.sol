// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.21;

// import {PBHVerifierTest} from "./PBHVerifierTest.sol";
// import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
// import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
// import {PBHVerifierImplV1 as PBHVerifierImpl} from "../src/PBHVerifierImplV1.sol";
// import {PBHVerifier} from "../src/PBHVerifier.sol";

// /// @title PBHVerifier Construction Tests
// /// @notice Contains tests for the PBH Verifier construction
// /// @author Worldcoin
// /// @dev This test suite tests both the proxy and the functionality of the underlying implementation
// ///      so as to test everything in the context of how it will be deployed.
// contract PBHVerifierConstruction is PBHVerifierTest {
//     /// @notice Taken from Initializable.sol
//     event Initialized(uint8 version);

//     /// @notice Tests if it is possible to construct a router without a delegate.
//     function testCanConstructPBHVerifierWithNoDelegate() public {
//         // Setup
//         address dummy = address(this);
//         bytes memory data = new bytes(0x0);

//         // Test
//         pbhVerifier = new PBHVerifier(dummy, data);
//     }

//     /// @notice Tests that it is possible to properly construct and initialise a router.
//     function testCanConstructRouterWithDelegate(IWorldIDGroups dummy, IEntryPoint entryPoint) public {
//         // Setup
//         vm.expectEmit(true, true, true, true);
//         emit Initialized(1);
//         pbhVerifierImpl = new PBHVerifierImpl();
//         bytes memory callData = abi.encodeCall(PBHVerifierImpl.initialize, (dummy, entryPoint, 30));

//         // Test
//         pbhVerifier = new PBHVerifier(address(pbhVerifierImpl), callData);
//     }
// }
