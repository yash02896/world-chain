// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
`
import {Safe4337Module} from "@4337/Safe4337Module.sol";

contract PBHSafe4337Module is Safe4337Module {

    address public immutable PBH_SIGNATURE_AGGREGATOR;

    constructor(address _safe, address _pbhSignatureAggregator) Safe4337Module(_safe) {
        PBH_SIGNATURE_AGGREGATOR = _pbhSignatureAggregator;
    }
}