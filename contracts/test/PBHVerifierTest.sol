// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./mocks/MockWorldIDGroups.sol";
import "../src/helpers/ByteHasher.sol";
import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import {WorldIDTest} from "@world-id-contracts/test/WorldIDTest.sol";
import {PBHVerifierImplV1 as PBHVerifierImpl} from "../src/PBHVerifier.sol";
import {PBHVerifier} from "../src/PBHVerifier.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

// import {WorldIDTest} from "@world-id-contracts/test/WorldIdTest.sol";

/// @title PBHVerifier Test.
/// @notice Contains tests for the PBHVerifier.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract PBHVerifierTest is WorldIDTest {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                TEST DATA                                ///
    ///////////////////////////////////////////////////////////////////////////////

    PBHVerifier internal pbhVerifier;
    PBHVerifierImpl internal pbhVerifierImpl;

    address internal pbhVerifierAddress;
    address internal pbhVerifierImplAddress;

    IWorldIDGroups internal nullManager = IWorldIDGroups(address(0));
    IWorldIDGroups internal thisWorldID;

    IEntryPoint internal entryPoint = IEntryPoint(address(0));

    ///////////////////////////////////////////////////////////////////////////////
    ///                            TEST ORCHESTRATION                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice This function runs before every single test.
    /// @dev It is run before every single iteration of a property-based fuzzing test.
    function setUp() public {
        thisWorldID = IWorldIDGroups(thisAddress);
        makeNewPBHVerifier(thisWorldID, entryPoint);

        // Label the addresses for better errors.
        hevm.label(thisAddress, "Sender");
        hevm.label(pbhVerifierAddress, "PBHVerifier");
        hevm.label(pbhVerifierImplAddress, "PBHVerifierImpl");
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              TEST UTILITIES                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Initializes a new router.
    /// @dev It is constructed in the globals.
    ///
    /// @param initialGroupAddress The initial group's identity manager.
    function makeNewPBHVerifier(IWorldIDGroups initialGroupAddress, IEntryPoint initialEntryPoint) public {
        pbhVerifierImpl = new PBHVerifierImpl();
        pbhVerifierImplAddress = address(pbhVerifierImpl);

        // TODO: why does this not work?
        // vm.expectEmit(true, true, true, true);

        bytes memory initCallData =
            abi.encodeCall(PBHVerifierImpl.initialize, (initialGroupAddress, initialEntryPoint, 30));

        pbhVerifier = new PBHVerifier(pbhVerifierImplAddress, initCallData);
        pbhVerifierAddress = address(pbhVerifier);
    }

    /// @notice Constructs a new router without initializing the delegate.
    /// @dev It is constructed in the globals.
    function makeUninitPBHVerifier() public {
        pbhVerifierImpl = new PBHVerifierImpl();
        pbhVerifierImplAddress = address(pbhVerifierImpl);
        pbhVerifier = new PBHVerifier(pbhVerifierImplAddress, new bytes(0x0));
        pbhVerifierAddress = address(pbhVerifier);
    }
}
