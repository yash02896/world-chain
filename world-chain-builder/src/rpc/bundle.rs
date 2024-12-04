use alloy_rpc_types::erc4337::ConditionalOptions;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth::{
    rpc::{api::eth::helpers::LoadTransaction, eth::RpcNodeCore},
    transaction_pool::TransactionPool,
};
use reth_provider::BlockReaderIdExt;
use revm_primitives::{Bytes, B256};

use crate::pool::tx::WorldChainPooledTransaction;

use super::WorldChainEthApi;

/// Trait interface for `eth_sendRawTransactionConditional`
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
pub trait EthTransactionsExt: LoadTransaction<Provider = BlockReaderIdExt> {
    #[method(name = "sendRawTransactionConditional")]
    fn send_raw_transaction_conditional(&self, tx: Bytes, options: ConditionalOptions) -> RpcResult<B256>;
}

/// WorldChainEthApi Extension for ERC-4337 Conditionally Included 
/// 
/// Bundled Transactions
pub struct WorldChainEthApiExt<N: RpcNodeCore> {
    inner: WorldChainEthApi<N>,
}

impl<N> EthTransactionsExtServer for WorldChainEthApiExt<N>
where
    Self: LoadTransaction<
        Pool: TransactionPool<Transaction = WorldChainPooledTransaction>,
        Provider: BlockReaderIdExt,
    >,
    N: RpcNodeCore,
{
    fn send_raw_transaction_conditional(&self, tx: Bytes, options: ConditionalOptions) -> RpcResult<B256> {
        Ok(B256::default())
    }
}
