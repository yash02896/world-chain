use alloy_primitives::{Bytes, B256};
use alloy_rpc_types::erc4337::ConditionalOptions;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_optimism_rpc::SequencerClient;
pub mod eth;

/// Trait interface for EthApi Extension
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
#[async_trait]
pub trait EthTransactionsExt {
    #[method(name = "sendRawTransactionConditional")]
    async fn send_raw_transaction_conditional(
        &self,
        tx: Bytes,
        options: ConditionalOptions,
    ) -> RpcResult<B256>;

    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(&self, tx: Bytes) -> RpcResult<B256>;
}

/// WorldChainEthApi Extension for `sendRawTransactionConditional` and `sendRawTransaction`
#[derive(Clone, Debug)]
pub struct WorldChainEthApiExt<Pool, Client> {
    pool: Pool,
    client: Client,
    sequencer_client: Option<SequencerClient>,
}
