use crate::rpc::WorldChainEthApi;
use alloy_rpc_types::TransactionRequest;
use reth::api::ConfigureEvm;
use reth::rpc::api::eth::helpers::{Call, EthCall, LoadPendingBlock, LoadState, SpawnBlocking};
use reth::rpc::eth::{EthApiTypes, RpcNodeCore};
use reth_optimism_rpc::OpEthApi;
use reth_primitives::{
    revm_primitives::{BlockEnv, TxEnv},
    Header,
};

impl<N> EthCall for WorldChainEthApi<N>
where
    Self: Call + LoadPendingBlock,
    N: RpcNodeCore,
{
}

impl<N> Call for WorldChainEthApi<N>
where
    Self: LoadState<Evm: ConfigureEvm<Header = Header>> + SpawnBlocking,
    OpEthApi<N>: Call,
    Self::Error: From<<OpEthApi<N> as EthApiTypes>::Error>,
    N: RpcNodeCore,
{
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.call_gas_limit()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.max_simulate_blocks()
    }

    fn create_txn_env(
        &self,
        block_env: &BlockEnv,
        request: TransactionRequest,
    ) -> Result<TxEnv, Self::Error> {
        Ok(self.inner.create_txn_env(block_env, request)?)
    }
}
