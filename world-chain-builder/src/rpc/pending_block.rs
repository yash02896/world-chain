//! Loads OP pending block for a RPC response.

use crate::rpc::WorldChainEthApi;
use alloy_primitives::{BlockNumber, B256};
use reth::api::ConfigureEvm;
use reth::chainspec::{EthChainSpec, EthereumHardforks};
use reth::rpc::api::eth::helpers::{LoadPendingBlock, SpawnBlocking};
use reth::rpc::eth::{EthApiTypes, RpcNodeCore};
use reth::rpc::server_types::eth::PendingBlock;
use reth::transaction_pool::TransactionPool;
use reth_optimism_rpc::OpEthApi;
use reth_primitives::{revm_primitives::BlockEnv, Header, Receipt, SealedBlockWithSenders};
use reth_provider::{
    BlockReaderIdExt, ChainSpecProvider, EvmEnvProvider, ExecutionOutcome, StateProviderFactory,
};

impl<N> LoadPendingBlock for WorldChainEthApi<N>
where
    Self: SpawnBlocking,
    N: RpcNodeCore<
        Provider: BlockReaderIdExt
                      + EvmEnvProvider
                      + ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>
                      + StateProviderFactory,
        Pool: TransactionPool,
        Evm: ConfigureEvm<Header = Header>,
    >,
    Self::Error: From<<OpEthApi<N> as EthApiTypes>::Error>,
{
    #[inline]
    fn pending_block(&self) -> &tokio::sync::Mutex<Option<PendingBlock>> {
        self.inner.pending_block()
    }

    /// Returns the locally built pending block
    async fn local_pending_block(
        &self,
    ) -> Result<Option<(SealedBlockWithSenders, Vec<Receipt>)>, Self::Error> {
        Ok(self.inner.local_pending_block().await?)
    }

    fn receipts_root(
        &self,
        _block_env: &BlockEnv,
        execution_outcome: &ExecutionOutcome,
        block_number: BlockNumber,
    ) -> B256 {
        self.inner
            .receipts_root(_block_env, execution_outcome, block_number)
    }
}
