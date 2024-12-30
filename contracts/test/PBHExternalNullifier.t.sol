// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@helpers/PBHExternalNullifier.sol";
import "@BokkyPooBahsDateTimeLibrary/BokkyPooBahsDateTimeLibrary.sol";

contract PBHExternalNullifierTest is Test {
    function testFuzz_encode(uint8 pbhNonce, uint8 month, uint16 year) public pure {
        vm.assume(month > 0 && month <= 12);
        PBHExternalNullifier.encode(PBHExternalNullifier.V1, pbhNonce, month, year);
    }

    function testFuzz_encode_RevertIf_InvalidMonth(uint8 pbhNonce, uint8 month, uint16 year) public {
        vm.assume(month == 0 || month > 12);
        vm.expectRevert(PBHExternalNullifier.InvalidExternalNullifierMonth.selector);
        PBHExternalNullifier.encode(PBHExternalNullifier.V1, pbhNonce, month, year);
    }

    function testFuzz_decode(uint8 pbhNonce, uint8 month, uint16 year) public {
        vm.assume(month > 0 && month <= 12);
        uint256 encoded = PBHExternalNullifier.encode(PBHExternalNullifier.V1, pbhNonce, month, year);

        (uint8 decodedVersion, uint8 decodedNonce, uint8 decodedMonth, uint16 decodedYear) =
            PBHExternalNullifier.decode(encoded);

        assertEq(decodedVersion, PBHExternalNullifier.V1);
        assertEq(decodedNonce, pbhNonce);
        assertEq(decodedMonth, month);
        assertEq(decodedYear, year);
    }

    function testFuzz_verify(uint8 pbhNonce, uint8 month, uint16 year, uint8 maxPbh) public {
        vm.assume(month > 0 && month <= 12);
        vm.assume(year >= 2023);
        vm.assume(maxPbh > 0 && pbhNonce <= maxPbh);

        // Warp to timestamp
        uint256 timestamp = BokkyPooBahsDateTimeLibrary.timestampFromDate(year, month, 1);
        vm.warp(timestamp);

        uint256 encoded = PBHExternalNullifier.encode(PBHExternalNullifier.V1, pbhNonce, month, year);
        PBHExternalNullifier.verify(encoded, maxPbh);
    }

    // TODO:
    function testFuzz_verify_RevertIf_InvalidNullifierLeadingZeros(
        uint8 pbhNonce,
        uint8 month,
        uint16 year,
        uint8 maxPbh
    ) public {}

    function testFuzz_verify_RevertIf_InvalidExternalNullifierVersion(
        uint8 pbhVersion,
        uint8 pbhNonce,
        uint8 month,
        uint16 year,
        uint8 maxPbh
    ) public {
        vm.assume(pbhVersion != PBHExternalNullifier.V1);
        vm.assume(month > 0 && month <= 12);
        vm.assume(year >= 2023);
        vm.assume(maxPbh > 0 && pbhNonce <= maxPbh);

        // Warp to timestamp
        uint256 timestamp = BokkyPooBahsDateTimeLibrary.timestampFromDate(year, month, 1);
        vm.warp(timestamp);

        uint256 encoded = PBHExternalNullifier.encode(pbhVersion, pbhNonce, month, year);
        vm.expectRevert(PBHExternalNullifier.InvalidExternalNullifierVersion.selector);
        PBHExternalNullifier.verify(encoded, maxPbh);
    }

    function testFuzz_verify_RevertIf_InvalidExternalNullifierYear(
        uint8 pbhNonce,
        uint8 month,
        uint16 year,
        uint8 maxPbh
    ) public {
        vm.assume(month > 0 && month <= 12);
        vm.assume(year >= 2023 && year < type(uint16).max);
        vm.assume(maxPbh > 0 && pbhNonce <= maxPbh);

        // Warp to timestamp
        uint256 timestamp = BokkyPooBahsDateTimeLibrary.timestampFromDate(year + 1, month, 1);
        vm.warp(timestamp);

        uint256 encoded = PBHExternalNullifier.encode(PBHExternalNullifier.V1, pbhNonce, month, year);
        vm.expectRevert(PBHExternalNullifier.InvalidExternalNullifierYear.selector);
        PBHExternalNullifier.verify(encoded, maxPbh);
    }

    function testFuzz_verify_RevertIf_InvalidExternalNullifierMonth(
        uint8 pbhNonce,
        uint8 month,
        uint16 year,
        uint8 maxPbh
    ) public {
        vm.assume(month > 0 && month <= 11);
        vm.assume(year >= 2023 && year < type(uint16).max);
        vm.assume(maxPbh > 0 && pbhNonce <= maxPbh);

        // Warp to timestamp
        uint256 timestamp = BokkyPooBahsDateTimeLibrary.timestampFromDate(year, month + 1, 1);
        vm.warp(timestamp);

        uint256 encoded = PBHExternalNullifier.encode(PBHExternalNullifier.V1, pbhNonce, month, year);
        vm.expectRevert(PBHExternalNullifier.InvalidExternalNullifierYear.selector);
        PBHExternalNullifier.verify(encoded, maxPbh);
    }

    function testFuzz_verify_RevertIf_InvalidPbhNonce(uint8 pbhNonce, uint8 month, uint16 year, uint8 maxPbh) public {
        vm.assume(month > 0 && month <= 12);
        vm.assume(year >= 2023 && year < type(uint16).max);
        vm.assume(maxPbh > 0);
        vm.assume(pbhNonce > maxPbh);

        // Warp to timestamp
        uint256 timestamp = BokkyPooBahsDateTimeLibrary.timestampFromDate(year, month, 1);
        vm.warp(timestamp);

        uint256 encoded = PBHExternalNullifier.encode(PBHExternalNullifier.V1, pbhNonce, month, year);
        vm.expectRevert(PBHExternalNullifier.InvalidPbhNonce.selector);
        PBHExternalNullifier.verify(encoded, maxPbh);
    }
}
