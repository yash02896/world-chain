//! Loads and formats OP block RPC response.

use crate::rpc::WorldChainEthApi;
use alloy_network::Network;
use op_alloy_rpc_types::OpTransactionReceipt;
use reth::rpc::api::eth::helpers::{
    EthBlocks, LoadBlock, LoadPendingBlock, LoadReceipt, SpawnBlocking,
};
use reth::rpc::api::eth::RpcReceipt;
use reth::rpc::eth::RpcNodeCore;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_rpc::{OpEthApi, OpEthApiError};
use reth_primitives::BlockId;
use reth_provider::{ChainSpecProvider, HeaderProvider};

impl<N> EthBlocks for WorldChainEthApi<N>
where
    Self: LoadBlock<
        Error = OpEthApiError,
        NetworkTypes: Network<ReceiptResponse = OpTransactionReceipt>,
    >,
    OpEthApi<N>: EthBlocks
        + LoadBlock<
            Error = OpEthApiError,
            NetworkTypes: Network<ReceiptResponse = OpTransactionReceipt>,
        > + LoadReceipt,
    N: RpcNodeCore<Provider: ChainSpecProvider<ChainSpec = OpChainSpec> + HeaderProvider>,
{
    async fn block_receipts(
        &self,
        block_id: BlockId,
    ) -> Result<Option<Vec<RpcReceipt<Self::NetworkTypes>>>, Self::Error>
    where
        Self: LoadReceipt,
    {
        self.inner.block_receipts(block_id).await
    }
}

impl<N> LoadBlock for WorldChainEthApi<N>
where
    OpEthApi<N>: LoadPendingBlock + SpawnBlocking,
    Self: LoadPendingBlock + SpawnBlocking,
    N: RpcNodeCore,
{
}
