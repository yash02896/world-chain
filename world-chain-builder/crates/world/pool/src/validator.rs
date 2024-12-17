//! World Chain transaction pool types
use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::Decodable;
use alloy_sol_types::{SolCall, SolValue};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use reth::transaction_pool::{
    Pool, TransactionOrigin, TransactionValidationOutcome, TransactionValidationTaskExecutor,
    TransactionValidator,
};
use reth_optimism_node::txpool::OpTransactionValidator;
use reth_primitives::{Block, SealedBlock, TransactionSigned};
use reth_provider::{BlockReaderIdExt, StateProviderFactory};
use semaphore::hash_to_field;
use semaphore::protocol::verify_proof;
use world_chain_builder_pbh::date_marker::DateMarker;
use world_chain_builder_pbh::external_nullifier::ExternalNullifier;
use world_chain_builder_pbh::payload::{PbhPayload, TREE_DEPTH};

use super::error::{TransactionValidationError, WorldChainTransactionPoolInvalid};
use super::ordering::WorldChainOrdering;
use super::root::WorldChainRootValidator;
use super::tx::{WorldChainPoolTransaction, WorldChainPooledTransaction};
use crate::bindings::IPBHValidator;

/// Type alias for World Chain transaction pool
pub type WorldChainTransactionPool<Client, S> = Pool<
    TransactionValidationTaskExecutor<
        WorldChainTransactionValidator<Client, WorldChainPooledTransaction>,
    >,
    WorldChainOrdering<WorldChainPooledTransaction>,
    S,
>;

/// Validator for World Chain transactions.
#[derive(Debug, Clone)]
pub struct WorldChainTransactionValidator<Client, Tx>
where
    Client: StateProviderFactory + BlockReaderIdExt,
{
    inner: OpTransactionValidator<Client, Tx>,
    root_validator: WorldChainRootValidator<Client>,
    num_pbh_txs: u16,
    pbh_validator: Address,
    pbh_signature_aggregator: Address,
}

impl<Client, Tx> WorldChainTransactionValidator<Client, Tx>
where
    Client: StateProviderFactory + BlockReaderIdExt<Block = reth_primitives::Block>,
    Tx: WorldChainPoolTransaction<Consensus = TransactionSigned>,
{
    /// Create a new [`WorldChainTransactionValidator`].
    pub fn new(
        inner: OpTransactionValidator<Client, Tx>,
        root_validator: WorldChainRootValidator<Client>,
        num_pbh_txs: u16,
        pbh_validator: Address,
        pbh_signature_aggregator: Address,
    ) -> Self {
        Self {
            inner,
            root_validator,
            num_pbh_txs,
            pbh_validator,
            pbh_signature_aggregator,
        }
    }

    /// Get a reference to the inner transaction validator.
    pub fn inner(&self) -> &OpTransactionValidator<Client, Tx> {
        &self.inner
    }

    /// Ensure the provided root is on chain and valid
    pub fn validate_root(
        &self,
        pbh_payload: &PbhPayload,
    ) -> Result<(), TransactionValidationError> {
        let is_valid = self.root_validator.validate_root(pbh_payload.root);
        if !is_valid {
            return Err(WorldChainTransactionPoolInvalid::InvalidRoot.into());
        }
        Ok(())
    }

    /// External nullifiers must be of the form
    /// `<prefix>-<periodId>-<PbhNonce>`.
    /// example:
    /// `v1-012025-11`
    pub fn validate_external_nullifier(
        &self,
        date: chrono::DateTime<chrono::Utc>,
        pbh_payload: &PbhPayload,
    ) -> Result<(), TransactionValidationError> {
        // In most cases these will be the same value, but at the month boundary
        // we'll still accept the previous month if the transaction is at most a minute late
        // or the next month if the transaction is at most a minute early
        let valid_dates = [
            DateMarker::from(date - chrono::Duration::minutes(1)),
            DateMarker::from(date),
            DateMarker::from(date + chrono::Duration::minutes(1)),
        ];
        if valid_dates
            .iter()
            .all(|d| pbh_payload.external_nullifier.date_marker != *d)
        {
            return Err(WorldChainTransactionPoolInvalid::InvalidExternalNullifierPeriod.into());
        }

        if pbh_payload.external_nullifier.nonce >= self.num_pbh_txs {
            return Err(WorldChainTransactionPoolInvalid::InvalidExternalNullifierNonce.into());
        }

        Ok(())
    }

    pub fn validate_pbh_payload(
        &self,
        payload: &PbhPayload,
        signal: U256,
    ) -> Result<(), TransactionValidationError> {
        self.validate_root(payload)?;
        let date = chrono::Utc::now();
        self.validate_external_nullifier(date, payload)?;

        let res = verify_proof(
            payload.root,
            payload.nullifier_hash,
            signal,
            payload.external_nullifier.hash(),
            &payload.proof.0,
            TREE_DEPTH,
        );

        match res {
            Ok(true) => Ok(()),
            Ok(false) => Err(WorldChainTransactionPoolInvalid::InvalidSemaphoreProof.into()),
            Err(e) => Err(TransactionValidationError::Error(e.into())),
        }
    }

    pub fn is_valid_eip4337_pbh_bundle(
        &self,
        tx: &Tx,
    ) -> Option<IPBHValidator::handleAggregatedOpsCall> {
        if !tx
            .input()
            .starts_with(&IPBHValidator::handleAggregatedOpsCall::SELECTOR)
        {
            return None;
        }

        let Ok(decoded) = IPBHValidator::handleAggregatedOpsCall::abi_decode(tx.input(), true)
        else {
            return None;
        };

        let are_aggregators_valid = decoded
            ._0
            .iter()
            .cloned()
            .all(|per_aggregator| per_aggregator.aggregator == self.pbh_signature_aggregator);

        if are_aggregators_valid {
            Some(decoded)
        } else {
            None
        }
    }

    pub fn validate_pbh_bundle(
        &self,
        transaction: &mut Tx,
    ) -> Result<(), TransactionValidationError> {
        let Some(calldata) = self.is_valid_eip4337_pbh_bundle(transaction) else {
            return Ok(());
        };

        for aggregated_ops in calldata._0 {
            let mut buff = aggregated_ops.signature.as_ref();
            let pbh_payloads = <Vec<PbhPayload>>::decode(&mut buff)
                .map_err(WorldChainTransactionPoolInvalid::from)
                .map_err(TransactionValidationError::from)?;

            pbh_payloads
                .par_iter()
                .zip(aggregated_ops.userOps)
                .try_for_each(|(payload, op)| {
                    let signal = alloy_primitives::keccak256(
                        <(Address, U256, Bytes) as SolValue>::abi_encode_packed(&(
                            op.sender,
                            op.nonce,
                            op.callData,
                        )),
                    );

                    self.validate_pbh_payload(&payload, hash_to_field(signal.as_ref()))?;

                    Ok::<(), TransactionValidationError>(())
                })?;
        }

        transaction.set_valid_pbh();

        Ok(())
    }
}

impl<Client, Tx> TransactionValidator for WorldChainTransactionValidator<Client, Tx>
where
    Client: StateProviderFactory + BlockReaderIdExt<Block = Block>,
    Tx: WorldChainPoolTransaction<Consensus = TransactionSigned>,
{
    type Transaction = Tx;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        mut transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        if transaction.to().unwrap_or_default() == self.pbh_validator {
            if let Err(e) = self.validate_pbh_bundle(&mut transaction) {
                return e.to_outcome(transaction);
            }
        };

        self.inner.validate_one(origin, transaction.clone())
    }

    fn on_new_head_block(&self, new_tip_block: &SealedBlock) {
        self.inner.on_new_head_block(new_tip_block);
        // TODO: Handle reorgs
        self.root_validator.on_new_block(new_tip_block);
    }
}

#[cfg(test)]
pub mod tests {
    use std::time::Instant;

    use alloy_primitives::Address;
    use alloy_signer_local::coins_bip39::English;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::SolCall;
    use bon::builder;
    use chrono::{TimeZone, Utc};
    use ethers_core::types::U256;
    use reth::transaction_pool::blobstore::InMemoryBlobStore;
    use reth::transaction_pool::{
        Pool, PoolTransaction as _, TransactionPool, TransactionValidator,
    };
    use reth_primitives::{BlockBody, SealedBlock, SealedHeader};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use semaphore::identity::Identity;
    use semaphore::poseidon_tree::PoseidonTree;
    use semaphore::Field;
    use test_case::test_case;
    use world_chain_builder_pbh::ext_nullifier;
    use world_chain_builder_pbh::external_nullifier::ExternalNullifier;
    use world_chain_builder_pbh::payload::{PbhPayload, Proof};

    use super::WorldChainTransactionValidator;
    use crate::ordering::WorldChainOrdering;
    use crate::root::{LATEST_ROOT_SLOT, OP_WORLD_ID};
    use crate::test_utils::{
        self, get_pbh_4337_transaction, get_pbh_transaction, world_chain_validator,
        PBH_TEST_VALIDATOR,
    };
    use crate::tx::WorldChainPooledTransaction;

    #[builder(on(String, into))]
    pub fn signer(
        #[builder(default = "test test test test test test test test test test test junk")]
        mnemonic: String,
        #[builder(default = 0)] index: u32,
    ) -> PrivateKeySigner {
        let signer = alloy_signer_local::MnemonicBuilder::<English>::default()
            .phrase(&mnemonic)
            .index(index)
            .expect("Failed to set index")
            .build()
            .expect("Failed to create signer");

        signer
    }

    #[builder(on(String, into))]
    pub fn account(
        #[builder(default = "test test test test test test test test test test test junk")]
        mnemonic: String,
        #[builder(default = 0)] index: u32,
    ) -> Address {
        let signer = signer().mnemonic(mnemonic).index(index).call();

        signer.address()
    }

    #[test_case(0, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")]
    #[test_case(1, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")]
    #[test_case(2, "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")]
    #[test_case(3, "0x90F79bf6EB2c4f870365E785982E1f101E93b906")]
    #[test_case(4, "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65")]
    #[test_case(5, "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc")]
    #[test_case(6, "0x976EA74026E726554dB657fA54763abd0C3a0aa9")]
    #[test_case(7, "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955")]
    #[test_case(8, "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f")]
    #[test_case(9, "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720")]
    fn mnemonic_accounts(index: u32, exp_address: &str) {
        let exp: Address = exp_address.parse().unwrap();

        assert_eq!(exp, account().index(index).call());
    }

    async fn setup() -> Pool<
        WorldChainTransactionValidator<MockEthProvider, WorldChainPooledTransaction>,
        WorldChainOrdering<WorldChainPooledTransaction>,
        InMemoryBlobStore,
    > {
        let start = Instant::now();

        let validator = world_chain_validator();

        // TODO: Remove
        let transaction = get_pbh_transaction(0);
        validator.inner.client().add_account(
            transaction.sender(),
            ExtendedAccount::new(transaction.nonce(), alloy_primitives::U256::MAX),
        );

        // Fund 10 test accounts
        for acc in 0..10 {
            let account_address = account().index(acc).call();

            validator.inner.client().add_account(
                account_address,
                ExtendedAccount::new(0, alloy_primitives::U256::MAX),
            );
        }

        // Prep a merkle tree with first 5 accounts
        let tree = test_utils::tree();
        let root = tree.root();

        // Insert a world id root into the OpWorldId Account
        validator.inner.client().add_account(
            OP_WORLD_ID,
            ExtendedAccount::new(0, alloy_primitives::U256::ZERO)
                .extend_storage(vec![(LATEST_ROOT_SLOT.into(), root)]),
        );

        let header = SealedHeader::default();
        let body = BlockBody::default();
        let block = SealedBlock::new(header, body);

        // Propogate the block to the root validator
        validator.on_new_head_block(&block);

        let ordering = WorldChainOrdering::default();

        let pool = Pool::new(
            validator,
            ordering,
            InMemoryBlobStore::default(),
            Default::default(),
        );

        println!("Building the pool took {:?}", start.elapsed());

        pool
    }

    #[tokio::test]
    async fn validate_noop_non_pbh() {
        const ACC: u32 = 0;

        let pool = setup().await;

        let account = test_utils::account(ACC);
        let tx = test_utils::eip1559().to(account).call();
        let tx = test_utils::eth_tx(ACC, tx).await;

        pool.add_external_transaction(tx.clone().into())
            .await
            .expect("Failed to add transaction");
    }

    #[tokio::test]
    async fn validate_no_duplicates() {
        const ACC: u32 = 0;

        let pool = setup().await;

        let account = test_utils::account(ACC);
        let tx = test_utils::eip1559().to(account).call();
        let tx = test_utils::eth_tx(ACC, tx).await;

        pool.add_external_transaction(tx.clone().into())
            .await
            .expect("Failed to add transaction");

        let res = pool.add_external_transaction(tx.clone().into()).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn validate_pbh_bundle() {
        const BUNDLER_ACCOUNT: u32 = 9;
        const USER_ACCOUNT: u32 = 0;

        let pool = setup().await;

        let user_op = test_utils::user_op().acc(USER_ACCOUNT).call();
        let bundle = test_utils::pbh_bundle(vec![user_op]);
        let calldata = bundle.abi_encode();

        let tx = test_utils::eip1559()
            .to(PBH_TEST_VALIDATOR)
            .input(calldata)
            .call();

        let tx = test_utils::eth_tx(BUNDLER_ACCOUNT, tx).await;

        pool.add_external_transaction(tx.clone().into())
            .await
            .expect("Failed to add transaction");
    }

    #[tokio::test]
    async fn validate_4337_bundle() {
        let validator = world_chain_validator();
        let (transaction, root) = get_pbh_4337_transaction().await;
        validator.inner.client().add_account(
            transaction.sender(),
            ExtendedAccount::new(transaction.nonce(), alloy_primitives::U256::MAX),
        );
        // Insert a world id root into the OpWorldId Account
        // TODO: This should be set to the root on the Payloads of a Bundle Tx
        validator.inner.client().add_account(
            OP_WORLD_ID,
            ExtendedAccount::new(0, alloy_primitives::U256::ZERO)
                .extend_storage(vec![(LATEST_ROOT_SLOT.into(), root)]),
        );
        let header = SealedHeader::default();
        let body = BlockBody::default();
        let block = SealedBlock::new(header, body);

        // Propogate the block to the root validator
        validator.on_new_head_block(&block);

        let ordering = WorldChainOrdering::default();

        let pool = Pool::new(
            validator,
            ordering,
            InMemoryBlobStore::default(),
            Default::default(),
        );

        let start = chrono::Utc::now();
        let res = pool.add_external_transaction(transaction.clone()).await;
        let first_insert = chrono::Utc::now() - start;
        println!("first_insert: {first_insert:?}");
        println!("res = {res:#?}");
        assert!(res.is_ok());
        let tx = pool.get(transaction.hash());
        assert!(tx.is_some());

        let start = chrono::Utc::now();
        let res = pool.add_external_transaction(transaction.clone()).await;

        let second_insert = chrono::Utc::now() - start;
        println!("second_insert: {second_insert:?}");

        // Check here that we're properly caching the transaction
        assert!(first_insert > second_insert * 10);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn invalid_external_nullifier_hash() {
        let validator = world_chain_validator();
        let transaction = get_pbh_transaction(0);

        validator.inner.client().add_account(
            transaction.sender(),
            ExtendedAccount::new(transaction.nonce(), alloy_primitives::U256::MAX),
        );

        let ordering = WorldChainOrdering::default();

        let pool = Pool::new(
            validator,
            ordering,
            InMemoryBlobStore::default(),
            Default::default(),
        );

        let res = pool.add_external_transaction(transaction.clone()).await;

        println!("res = {res:#?}");
        assert!(res.is_err());

        assert!(false);
    }

    #[tokio::test]
    async fn invalid_signal_hash() {
        let validator = world_chain_validator();
        let transaction = get_pbh_transaction(0);

        validator.inner.client().add_account(
            transaction.sender(),
            ExtendedAccount::new(transaction.nonce(), alloy_primitives::U256::MAX),
        );

        let ordering = WorldChainOrdering::default();

        let pool = Pool::new(
            validator,
            ordering,
            InMemoryBlobStore::default(),
            Default::default(),
        );

        let res = pool.add_external_transaction(transaction.clone()).await;
        assert!(res.is_err());
    }

    #[test]
    fn test_validate_root() {
        let mut validator = world_chain_validator();
        let root = Field::from(1u64);
        let proof = Proof(semaphore::protocol::Proof(
            (U256::from(1u64), U256::from(2u64)),
            (
                [U256::from(3u64), U256::from(4u64)],
                [U256::from(5u64), U256::from(6u64)],
            ),
            (U256::from(7u64), U256::from(8u64)),
        ));
        let payload = PbhPayload {
            external_nullifier: ExternalNullifier::v1(1, 2025, 11),
            nullifier_hash: Field::from(10u64),
            root,
            proof,
        };
        let header = SealedHeader::default();
        let body = BlockBody::default();
        let block = SealedBlock::new(header, body);
        let client = MockEthProvider::default();
        // Insert a world id root into the OpWorldId Account
        client.add_account(
            OP_WORLD_ID,
            ExtendedAccount::new(0, alloy_primitives::U256::ZERO)
                .extend_storage(vec![(LATEST_ROOT_SLOT.into(), Field::from(1u64))]),
        );
        validator.root_validator.set_client(client);
        validator.on_new_head_block(&block);
        let res = validator.validate_root(&payload);
        assert!(res.is_ok());
    }

    #[test]
    fn test_invalidate_root() {
        let mut validator = world_chain_validator();
        let root = Field::from(0);
        let proof = Proof(semaphore::protocol::Proof(
            (U256::from(1u64), U256::from(2u64)),
            (
                [U256::from(3u64), U256::from(4u64)],
                [U256::from(5u64), U256::from(6u64)],
            ),
            (U256::from(7u64), U256::from(8u64)),
        ));
        let payload = PbhPayload {
            external_nullifier: ExternalNullifier::v1(1, 2025, 11),
            nullifier_hash: Field::from(10u64),
            root,
            proof,
        };
        let header = SealedHeader::default();
        let body = BlockBody::default();
        let block = SealedBlock::new(header, body);
        let client = MockEthProvider::default();
        // Insert a world id root into the OpWorldId Account
        client.add_account(
            OP_WORLD_ID,
            ExtendedAccount::new(0, alloy_primitives::U256::ZERO)
                .extend_storage(vec![(LATEST_ROOT_SLOT.into(), Field::from(1u64))]),
        );
        validator.root_validator.set_client(client);
        validator.on_new_head_block(&block);
        let res = validator.validate_root(&payload);
        assert!(res.is_err());
    }

    #[test_case("v1-012025-0")]
    #[test_case("v1-012025-1")]
    #[test_case("v1-012025-29")]
    fn validate_external_nullifier_valid(external_nullifier: &str) {
        let validator = world_chain_validator();
        let date = chrono::Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        let payload = PbhPayload {
            external_nullifier: external_nullifier.parse().unwrap(),
            nullifier_hash: Field::ZERO,
            root: Field::ZERO,
            proof: Default::default(),
        };

        validator
            .validate_external_nullifier(date, &payload)
            .unwrap();
    }

    #[test_case("v1-012025-0", "2024-12-31 23:59:30Z" ; "a minute early")]
    #[test_case("v1-012025-0", "2025-02-01 00:00:30Z" ; "a minute late")]
    fn validate_external_nullifier_at_time(external_nullifier: &str, time: &str) {
        let validator = world_chain_validator();
        let date: chrono::DateTime<Utc> = time.parse().unwrap();

        let payload = PbhPayload {
            external_nullifier: external_nullifier.parse().unwrap(),
            nullifier_hash: Field::ZERO,
            root: Field::ZERO,
            proof: Default::default(),
        };

        validator
            .validate_external_nullifier(date, &payload)
            .unwrap();
    }
