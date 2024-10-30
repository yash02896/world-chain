//! Loads and formats OP receipt RPC response.

use crate::rpc::WorldChainEthApi;
use reth::{
    api::{FullNodeComponents, NodeTypes},
    rpc::api::eth::{helpers::LoadReceipt, RpcReceipt},
};
use reth_optimism_chainspec::OpChainSpec;
use reth_primitives::{Receipt, TransactionMeta, TransactionSigned};

impl<N> LoadReceipt for WorldChainEthApi<N>
where
    Self: Send + Sync,
    N: FullNodeComponents<Types: NodeTypes<ChainSpec = OpChainSpec>>,
{
    async fn build_transaction_receipt(
        &self,
        tx: TransactionSigned,
        meta: TransactionMeta,
        receipt: Receipt,
    ) -> Result<RpcReceipt<Self::NetworkTypes>, Self::Error> {
        self.inner
            .build_transaction_receipt(tx, meta, receipt)
            .await
    }
}
