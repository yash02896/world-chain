// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./MockWorldIDGroups.sol";
import "../src/helpers/ByteHasher.sol";
import {IWorldIDGroups} from "@world-id-contracts/interfaces/IWorldIDGroups.sol";
import {PBHVerifierImplV1} from "../src/PBHVerifierImplV1.sol";
import {PBHVerifier} from "../src/PBHVerifier.sol";
// import {WorldIDTest} from "@world-id-contracts/test/WorldIdTest.sol";

/// @title World ID Router Test.
/// @notice Contains tests for the WorldID Router.
/// @author Worldcoin
/// @dev This test suite tests both the proxy and the functionality of the underlying implementation
///      so as to test everything in the context of how it will be deployed.
contract PBHVerifierTest is Test {
    ///////////////////////////////////////////////////////////////////////////////
    ///                                TEST DATA                                ///
    ///////////////////////////////////////////////////////////////////////////////

    MockWorldIDGroups internal worldId;

    address internal worldIdAddress;

    IWorldIDGroups internal nullManager = IWorldIDGroups(nullAddress);
    IWorldIDGroups internal thisWorldID;

    /// @notice Emitted when a group is enabled in the router.
    ///
    /// @param initialGroupIdentityManager The address of the identity manager to be used for the first group
    event GroupIdentityManagerRouterImplInitialized(IWorldID initialGroupIdentityManager);

    ///////////////////////////////////////////////////////////////////////////////
    ///                            TEST ORCHESTRATION                           ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice This function runs before every single test.
    /// @dev It is run before every single iteration of a property-based fuzzing test.
    function setUp() public {
        thisWorldID = IWorldID(thisAddress);
        makeNewRouter(thisWorldID);

        // Label the addresses for better errors.
        hevm.label(thisAddress, "Sender");
        hevm.label(routerAddress, "Router");
        hevm.label(routerImplAddress, "RouterImplementation");
    }

    ///////////////////////////////////////////////////////////////////////////////
    ///                              TEST UTILITIES                             ///
    ///////////////////////////////////////////////////////////////////////////////

    /// @notice Initializes a new router.
    /// @dev It is constructed in the globals.
    ///
    /// @param initialGroupAddress The initial group's identity manager.
    function makeNewRouter(IWorldID initialGroupAddress) public {
        routerImpl = new RouterImpl();
        routerImplAddress = address(routerImpl);

        vm.expectEmit(true, true, true, true);

        emit GroupIdentityManagerRouterImplInitialized(initialGroupAddress);

        bytes memory initCallData = abi.encodeCall(RouterImpl.initialize, (initialGroupAddress));

        router = new Router(routerImplAddress, initCallData);
        routerAddress = address(router);
    }

    /// @notice Constructs a new router without initializing the delegate.
    /// @dev It is constructed in the globals.
    function makeUninitRouter() public {
        routerImpl = new RouterImpl();
        routerImplAddress = address(routerImpl);
        router = new Router(routerImplAddress, new bytes(0x0));
        routerAddress = address(router);
    }
}
