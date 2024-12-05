use crate::pool::tx::WorldChainPooledTransaction;
use alloy_eips::BlockId;
use alloy_rpc_types::erc4337::{AccountStorage, ConditionalOptions};
use derive_more::derive::Deref;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    types::{ErrorCode, ErrorObjectOwned},
};

use reth::{
    rpc::{api::eth::helpers::{EthTransactions, LoadTransaction}, eth::RpcNodeCore},
    transaction_pool::TransactionPool,
};
use reth_provider::{BlockReaderIdExt, StateProviderFactory};
use revm_primitives::{Address, Bytes, FixedBytes, HashMap, B256};

/// Trait interface for `eth_sendRawTransactionConditional`
#[cfg_attr(not(test), rpc(server, namespace = "eth"))]
#[cfg_attr(test, rpc(server, client, namespace = "eth"))]
#[async_trait]
pub trait EthTransactionsExt: LoadTransaction<Provider = BlockReaderIdExt> {
    #[method(name = "sendRawTransactionConditional")]
    async fn send_raw_transaction_conditional(
        &self,
        tx: Bytes,
        options: ConditionalOptions,
    ) -> RpcResult<B256>;
}

/// WorldChainEthApi Extension for ERC-4337 Conditionally Included
///
/// Bundled Transactions
#[derive(Clone, Deref, Debug)]
pub struct WorldChainEthApiExt<S: EthTransactions> {
    #[deref]
    inner: S,
}

#[async_trait]
impl<S> EthTransactionsExtServer for WorldChainEthApiExt<S>
where
    Self: LoadTransaction<
        Pool: TransactionPool<Transaction = WorldChainPooledTransaction>,
        Provider: BlockReaderIdExt + StateProviderFactory,
    >,
    S: EthTransactions,
    <S as RpcNodeCore>::Provider: StateProviderFactory
{
    async fn send_raw_transaction_conditional(
        &self,
        tx: Bytes,
        options: ConditionalOptions,
    ) -> RpcResult<B256> {
        self.validate_options(options)?;
        self.inner
            .send_raw_transaction(tx)
            .await
            .map_err(Into::into)
    }
}

impl<S> WorldChainEthApiExt<S>
where
    Self: LoadTransaction<
        Pool: TransactionPool<Transaction = WorldChainPooledTransaction>,
        Provider: BlockReaderIdExt + StateProviderFactory,
    >,
    S: EthTransactions,
    <S as RpcNodeCore>::Provider: StateProviderFactory
{
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    /// Validates the conditional inclusion options provided by the client.
    /// 
    /// reference for the implementation <https://notes.ethereum.org/@yoav/SkaX2lS9j#>
    /// See also <https://pkg.go.dev/github.com/aK0nshin/go-ethereum/arbitrum_types#ConditionalOptions>
    pub fn validate_options(&self, options: ConditionalOptions) -> RpcResult<()> {
        let latest = self
            .provider()
            .block_by_id(BlockId::latest())
            .map_err(|_| ErrorObjectOwned::from(ErrorCode::InternalError))?
            .ok_or(ErrorObjectOwned::from(ErrorCode::InternalError))?;

        if let Some(min_block) = options.block_number_min {
            if min_block > latest.number {
                return Err(ErrorObjectOwned::from(ErrorCode::from(-32003)));
            }
        }

        if let Some(max_block) = options.block_number_max {
            if max_block <= latest.number {
                return Err(ErrorObjectOwned::from(ErrorCode::from(-32003)));
            }
        }

        if let Some(min_timestamp) = options.timestamp_min {
            if min_timestamp > latest.timestamp {
                return Err(ErrorObjectOwned::from(ErrorCode::from(-32003)));
            }
        }

        if let Some(max_timestamp) = options.timestamp_max {
            if max_timestamp <= latest.timestamp {
                return Err(ErrorObjectOwned::from(ErrorCode::from(-32003)));
            }
        }

        Ok(())
    }

    /// Validates the account storage slots/storage root provided by the client
    /// 
    /// Matches the current state of the account storage slots/storage root.
    /// TODO: We need to throttle the number of accounts that can be validated at once for DOS protection.
    pub fn validate_known_accounts(&self, known_accounts: HashMap<Address, AccountStorage>) -> RpcResult<()> {
        let state = self
            .provider().state_by_block_id(BlockId::latest()).map_err(|_| ErrorObjectOwned::from(ErrorCode::InternalError))?;

        for (address, storage) in known_accounts.iter() {
            match storage {
                AccountStorage::Slots(slots) => {
                    for (slot, value) in slots.iter() {
                        let current = state.storage(*address, slot.clone().into()).map_err(|_| ErrorObjectOwned::from(ErrorCode::InternalError))?;
                        if let Some(current) = current {
                            if FixedBytes::<32>::from_slice(&current.to_be_bytes::<32>()) != *value {
                                return Err(ErrorObjectOwned::from(ErrorCode::from(-32003)));
                            }
                        } else {
                            return Err(ErrorObjectOwned::from(ErrorCode::from(-32003)));
                        }
                    }
                }
                AccountStorage::RootHash(root) => {
                    
                }
            }
        }
        Ok(())
    }
}
