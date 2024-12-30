// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@helpers/PBHExternalNullifier.sol";
import "@BokkyPooBahsDateTimeLibrary/BokkyPooBahsDateTimeLibrary.sol";

contract PBHExternalNullifierTest is Test {
    // TODO: dont hard code these, use fuzzing

    uint8 constant VALID_VERSION = PBHExternalNullifier.V1;
    uint8 constant VALID_PBH_NONCE = 5;
    uint8 constant VALID_MONTH = 12;
    uint16 constant VALID_YEAR = 2024;
    uint8 constant MAX_PBH_PER_MONTH = 10;

    function testFuzz_encode(uint8 pbhNonce, uint8 month, uint16 year) public pure {
        vm.assume(month <= 12);
        PBHExternalNullifier.encode(PBHExternalNullifier.V1, pbhNonce, month, year);
    }

    function testFuzz_encode_RevertIf_InvalidMonth(uint8 pbhNonce, uint8 month, uint16 year) public {
        vm.assume(month > 12);
        vm.expectRevert(PBHExternalNullifier.InvalidExternalNullifierMonth.selector);
        PBHExternalNullifier.encode(PBHExternalNullifier.V1, pbhNonce, month, year);
    }

    function testFuzz_decode(uint8 pbhNonce, uint8 month, uint16 year) public {
        vm.assume(month <= 12);
        uint256 encoded = PBHExternalNullifier.encode(PBHExternalNullifier.V1, pbhNonce, month, year);

        (uint8 decodedVersion, uint8 decodedNonce, uint8 decodedMonth, uint16 decodedYear) =
            PBHExternalNullifier.decode(encoded);

        assertEq(decodedVersion, PBHExternalNullifier.V1);
        assertEq(decodedNonce, pbhNonce);
        assertEq(decodedMonth, month);
        assertEq(decodedYear, year);
    }

    // TODO:
    function testFuzz_verify() public {}

    // TODO:
    function testFuzz_verify_RevertIf_InvalidNullifierLeadingZeros() public {}

    // TODO:
    function testFuzz_verify_RevertIf_InvalidExternalNullifierVersion() public {}

    // TODO:
    function testFuzz_verify_RevertIf_InvalidExternalNullifierYear() public {}

    // TODO:
    function testFuzz_verify_RevertIf_InvalidExternalNullifierMonth() public {}

    // TODO:
    function testFuzz_verify_RevertIf_InvalidPbhNonce() public {}

    function testVerifyValidExternalNullifier() public {
        // Mock the current date to match VALID_YEAR and VALID_MONTH
        uint256 timestamp = BokkyPooBahsDateTimeLibrary.timestampFromDateTime(VALID_YEAR, VALID_MONTH, 1, 0, 0, 0);
        vm.warp(timestamp);

        uint256 encoded = PBHExternalNullifier.encode(VALID_VERSION, VALID_PBH_NONCE, VALID_MONTH, VALID_YEAR);

        PBHExternalNullifier.verify(encoded, MAX_PBH_PER_MONTH);
    }

    function testVerifyInvalidYear() public {
        uint256 currentTimestamp = BokkyPooBahsDateTimeLibrary.timestampFromDateTime(
            2023, // Mock the year to 2023
            VALID_MONTH,
            1,
            0,
            0,
            0
        );
        vm.warp(currentTimestamp);

        uint256 encoded = PBHExternalNullifier.encode(VALID_VERSION, VALID_PBH_NONCE, VALID_MONTH, VALID_YEAR);

        vm.expectRevert(PBHExternalNullifier.InvalidExternalNullifierYear.selector);
        PBHExternalNullifier.verify(encoded, MAX_PBH_PER_MONTH);
    }

    function testVerifyInvalidMonth() public {
        uint256 currentTimestamp = BokkyPooBahsDateTimeLibrary.timestampFromDateTime(
            VALID_YEAR,
            11, // Mock the month to November
            1,
            0,
            0,
            0
        );
        vm.warp(currentTimestamp);

        uint256 encoded = PBHExternalNullifier.encode(VALID_VERSION, VALID_PBH_NONCE, VALID_MONTH, VALID_YEAR);

        vm.expectRevert(PBHExternalNullifier.InvalidExternalNullifierMonth.selector);
        PBHExternalNullifier.verify(encoded, MAX_PBH_PER_MONTH);
    }

    function testVerifyInvalidPbhNonce() public {
        uint256 timestamp = BokkyPooBahsDateTimeLibrary.timestampFromDateTime(VALID_YEAR, VALID_MONTH, 1, 0, 0, 0);
        vm.warp(timestamp);

        uint256 encoded = PBHExternalNullifier.encode(
            VALID_VERSION,
            MAX_PBH_PER_MONTH + 1, // Invalid nonce exceeding max
            VALID_MONTH,
            VALID_YEAR
        );

        vm.expectRevert(PBHExternalNullifier.InvalidPbhNonce.selector);
        PBHExternalNullifier.verify(encoded, MAX_PBH_PER_MONTH);
    }

    function testVerifyInvalidVersion() public {
        uint256 timestamp = BokkyPooBahsDateTimeLibrary.timestampFromDateTime(VALID_YEAR, VALID_MONTH, 1, 0, 0, 0);
        vm.warp(timestamp);

        uint256 encoded = PBHExternalNullifier.encode(2, VALID_PBH_NONCE, VALID_MONTH, VALID_YEAR);

        vm.expectRevert(PBHExternalNullifier.InvalidExternalNullifierVersion.selector);
        PBHExternalNullifier.verify(encoded, MAX_PBH_PER_MONTH);
    }
}
