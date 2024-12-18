// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./MockWorldIDGroups.sol";
import "../src/helpers/ByteHasher.sol";
import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import {WorldIDTest} from "@world-id-contracts/test/WorldIDTest.sol";
import {PBHVerifierImplV1 as PBHVerifierImpl} from "../src/PBHVerifierImplV1.sol";
import {PBHVerifier} from "../src/PBHVerifier.sol";

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
    MockWorldIDGroups internal worldID;

    address internal pbhVerifierAddress;
    address internal pbhVerifierImplAddress;
    address internal worldIDAddress;

    ///////////////////////////////////////////////////////////////////////////////
    ///                            TEST ORCHESTRATION                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice This function runs before every single test.
    function setUp() public {
        makeNewPBHVerifier();

        // Label the addresses for better errors.
        hevm.label(thisAddress, "Sender");
        hevm.label(worldIDAddress, "World ID");
        hevm.label(pbhVerifierAddress, "PBHVerifier");
        hevm.label(pbhVerifierImplAddress, "PBHVerifierImpl");
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              TEST UTILITIES                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Initializes a new PBHVerifier.
    /// @dev It is constructed in the globals.
    function makeNewPBHVerifier() public {
        // IWorldIDGroups nullWorldID = IWorldIDGroups(address(0));
        worldID = new MockWorldIDGroups();
        worldIDAddress = address(worldID);

        pbhVerifierImpl = new PBHVerifierImpl();
        pbhVerifierImplAddress = address(pbhVerifierImpl);

        bytes memory initCallData = abi.encodeCall(PBHVerifierImpl.initialize, (worldID, 30));

        pbhVerifier = new PBHVerifier(pbhVerifierImplAddress, initCallData);
        pbhVerifierAddress = address(pbhVerifier);
    }

    /// @notice Constructs a new PBHVerifier without initializing the delegate.
    /// @dev It is constructed in the globals.
    function makeUninitPBHVerifier() public {
        pbhVerifierImpl = new PBHVerifierImpl();
        pbhVerifierImplAddress = address(pbhVerifierImpl);
        pbhVerifier = new PBHVerifier(pbhVerifierImplAddress, new bytes(0x0));
        pbhVerifierAddress = address(pbhVerifier);
    }
}
