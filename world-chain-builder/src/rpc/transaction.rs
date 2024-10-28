//! Loads and formats OP transaction RPC response.

use crate::pool::tx::WorldChainPooledTransaction;
use crate::{primitives::recover_raw_transaction, rpc::WorldChainEthApi};

use alloy_primitives::{Bytes, B256};
use reth::rpc::api::eth::helpers::{EthSigner, EthTransactions, LoadTransaction, SpawnBlocking};
use reth::rpc::api::eth::{FromEthApiError, FullEthApiTypes};
use reth::rpc::eth::RpcNodeCore;
use reth::transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use reth_optimism_rpc::SequencerClient;
use reth_provider::{BlockReaderIdExt, TransactionsProvider};

impl<N> EthTransactions for WorldChainEthApi<N>
where
    Self: LoadTransaction<
        Pool: TransactionPool<Transaction = WorldChainPooledTransaction>,
        Provider: BlockReaderIdExt,
    >,
    N: RpcNodeCore,
{
    fn signers(&self) -> &parking_lot::RwLock<Vec<Box<dyn EthSigner>>> {
        self.inner.signers()
    }

    /// Decodes and recovers the transaction and submits it to the pool.
    ///
    /// Returns the hash of the transaction.
    async fn send_raw_transaction(&self, tx: Bytes) -> Result<B256, Self::Error> {
        let (recovered, inner_tx) = recover_raw_transaction(tx.clone())?;
        let pool_transaction = <Self::Pool as TransactionPool>::Transaction::from_pooled(recovered);
        let pbh_tx = pool_transaction.pbh_payload.is_some();

        // submit the transaction to the pool with a `Local` origin
        let hash = self
            .pool()
            .add_transaction(TransactionOrigin::Local, pool_transaction)
            .await
            .map_err(Self::Error::from_eth_err)?;

        // On optimism, transactions are forwarded directly to the sequencer to be included in
        // blocks that it builds.
        if let Some(client) = self.raw_tx_forwarder().as_ref() {
            if !pbh_tx {
                tracing::debug!( target: "rpc::eth",  "forwarding raw transaction to");
                let _ = client.forward_raw_transaction(&inner_tx).await.inspect_err(|err| {
                    tracing::debug!(target: "rpc::eth", %err, hash=?*hash, "failed to forward raw transaction");
                });
            }
        }

        Ok(hash)
    }
}

impl<N> LoadTransaction for WorldChainEthApi<N>
where
    Self: SpawnBlocking + FullEthApiTypes,
    N: RpcNodeCore<Provider: TransactionsProvider, Pool: TransactionPool>,
{
}

impl<N> WorldChainEthApi<N>
where
    N: RpcNodeCore,
{
    /// Returns the [`SequencerClient`] if one is set.
    pub fn raw_tx_forwarder(&self) -> Option<SequencerClient> {
        self.inner.raw_tx_forwarder()
    }
}
