// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "@helpers/PBHExternalNullifierLib.sol";
import "@BokkyPooBahsDateTimeLibrary/BokkyPooBahsDateTimeLibrary.sol";

contract PBHExternalNullifierLibTest is Test {
    using PBHExternalNulliferLib for PBHExternalNullifier;

    uint8 constant VALID_PBH_NONCE = 5;
    uint8 constant VALID_MONTH = 12;
    uint16 constant VALID_YEAR = 2024;
    uint8 constant MAX_PBH_PER_MONTH = 10;

    function testEncodeDecodeValidInput() public pure {
        // Arrange
        uint8 pbhNonce = VALID_PBH_NONCE;
        uint8 month = VALID_MONTH;
        uint16 year = VALID_YEAR;

        // Act
        PBHExternalNullifier encoded = PBHExternalNulliferLib.encode(pbhNonce, month, year);
        (uint8 decodedNonce, uint8 decodedMonth, uint16 decodedYear) = PBHExternalNulliferLib.decode(encoded);

        // Assert
        assertEq(decodedNonce, pbhNonce, "Decoded nonce should match the original");
        assertEq(decodedMonth, month, "Decoded month should match the original");
        assertEq(decodedYear, year, "Decoded year should match the original");
    }

    function testEncodeInvalidMonth() public {
        uint8 invalidMonth = 13;

        vm.expectRevert(PBHExternalNulliferLib.InvalidExternalNullifierMonth.selector);
        PBHExternalNulliferLib.encode(VALID_PBH_NONCE, invalidMonth, VALID_YEAR);
    }

    function testEncodeInvalidYear() public {
        uint16 invalidYear = 10000;

        vm.expectRevert(PBHExternalNulliferLib.InvalidExternalNullifierYear.selector);
        PBHExternalNulliferLib.encode(VALID_PBH_NONCE, VALID_MONTH, invalidYear);
    }

    function testVerifyValidExternalNullifier() public {
        // Mock the current date to match VALID_YEAR and VALID_MONTH
        uint256 timestamp = BokkyPooBahsDateTimeLibrary.timestampFromDateTime(
            VALID_YEAR,
            VALID_MONTH,
            1,
            0,
            0,
            0
        );
        vm.warp(timestamp);

        PBHExternalNullifier encoded = PBHExternalNulliferLib.encode(VALID_PBH_NONCE, VALID_MONTH, VALID_YEAR);

        // Act & Assert
        PBHExternalNulliferLib.verify(encoded, MAX_PBH_PER_MONTH);
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

        PBHExternalNullifier encoded = PBHExternalNulliferLib.encode(VALID_PBH_NONCE, VALID_MONTH, VALID_YEAR);

        vm.expectRevert(PBHExternalNulliferLib.InvalidExternalNullifierYear.selector);
        PBHExternalNulliferLib.verify(encoded, MAX_PBH_PER_MONTH);
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

        PBHExternalNullifier encoded = PBHExternalNulliferLib.encode(VALID_PBH_NONCE, VALID_MONTH, VALID_YEAR);

        vm.expectRevert(PBHExternalNulliferLib.InvalidExternalNullifierMonth.selector);
        PBHExternalNulliferLib.verify(encoded, MAX_PBH_PER_MONTH);
    }

    function testVerifyInvalidPbhNonce() public {
        PBHExternalNullifier encoded = PBHExternalNulliferLib.encode(
            MAX_PBH_PER_MONTH + 1, // Invalid nonce exceeding max
            VALID_MONTH,
            VALID_YEAR
        );

        vm.expectRevert(PBHExternalNulliferLib.InvalidPbhNonce.selector);
        PBHExternalNulliferLib.verify(encoded, MAX_PBH_PER_MONTH);
    }
}