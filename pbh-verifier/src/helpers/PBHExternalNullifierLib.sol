// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "@BokkyPooBahsDateTimeLibrary/BokkyPooBahsDateTimeLibrary.sol";

/// @title PBHExternalNullifierLib
/// @notice Library for encoding, decoding, and verifying PBH external nullifiers.
///         External nullifiers are used to uniquely identify actions or events 
///         within a specific year and month using a nonce.
/// @dev Utilizes `PBHExternalNullifier` as a custom type for encoded nullifiers.
/// @dev The encoding format is as follows:
///      - Bits 32-255: Empty
///      - Bits 16-31: Year
///      - Bits 8-15: Month
///      - Bits 0-7: Nonce
type PBHExternalNullifier is uint256;

library PBHExternalNulliferLib {
    /// @notice Thrown when the provided external nullifier year doesn't
    /// match the current year
    error InvalidExternalNullifierYear();
    
    /// @notice Thrown when the provided external nullifier month doesn't
    /// match the current month
    error InvalidExternalNullifierMonth();
    
    /// @notice Thrown when the provided external 
    /// nullifier pbhNonce >= numPbhPerMonth
    error InvalidPbhNonce();

    /// @notice Encodes a PBH external nullifier using the provided year, month, and nonce.
    /// @param pbhNonce An 8-bit nonce value (0-255) used to uniquely identify the nullifier within a month.
    /// @param month An 8-bit 1-indexed value representing the month (1-12).
    /// @param year A 16-bit value representing the year (e.g., 2024).
    /// @return The encoded PBHExternalNullifier.
    function encode(uint8 pbhNonce, uint8 month, uint16 year) internal pure returns (PBHExternalNullifier) {
        require(month > 0 && month < 13, InvalidExternalNullifierMonth());
        require(year <= 9999, InvalidExternalNullifierYear());
        uint256 encoded = (uint32(year) << 16) | (uint32(month) << 8) | uint32(pbhNonce);
        return PBHExternalNullifier.wrap(encoded);
    }

    /// @notice Decodes an encoded PBHExternalNullifier into its constituent components.
    /// @param externalNullifier The encoded external nullifier to decode.
    /// @return pbhNonce The 8-bit nonce extracted from the external nullifier.
    /// @return month The 8-bit month extracted from the external nullifier.
    /// @return year The 16-bit year extracted from the external nullifier.
    function decode(PBHExternalNullifier externalNullifier) internal pure returns (uint8 pbhNonce, uint8 month, uint16 year) {
        uint256 encoded = PBHExternalNullifier.unwrap(externalNullifier);
        year = uint16(encoded >> 16);
        month = uint8((encoded >> 8) & 0xFF);
        pbhNonce = uint8(encoded & 0xFF);
    }
    
    /// @notice Verifies the validity of a PBHExternalNullifier by checking its components.
    /// @param externalNullifier The external nullifier to verify.
    /// @param numPbhPerMonth The maximum allowed value for the `pbhNonce` in the nullifier.
    /// @dev This function ensures the external nullifier matches the current year and month,
    ///      and that the nonce does not exceed `numPbhPerMonth`.
    function verify(PBHExternalNullifier externalNullifier, uint8 numPbhPerMonth) public view {
        (uint8 pbhNonce, uint8 month, uint16 year) = PBHExternalNulliferLib.decode(externalNullifier);
        require(year == BokkyPooBahsDateTimeLibrary.getYear(block.timestamp), InvalidExternalNullifierYear()); 
        require(month == BokkyPooBahsDateTimeLibrary.getMonth(block.timestamp), InvalidExternalNullifierMonth()); 
        require(pbhNonce <= numPbhPerMonth, InvalidPbhNonce()); 
    }
}
