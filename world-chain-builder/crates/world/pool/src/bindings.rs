use alloy_sol_types::sol;

sol! {
    #[derive(Default)]
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }

    #[derive(Default)]
    struct UserOpsPerAggregator {
        PackedUserOperation[] userOps;
        address aggregator;
        bytes signature;
    }

    contract IEntryPoint {
        function handleOps(
            PackedUserOperation[] calldata,
            address payable
        ) external;

        function handleAggregatedOps(
            UserOpsPerAggregator[] calldata,
            address payable
        ) public;
    }

    // TODO: WIP
    contract PBH {
        function handleAggregatedOps(
            UserOpsPerAggregator[] calldata,
            address payable
        ) public;
    }
}
