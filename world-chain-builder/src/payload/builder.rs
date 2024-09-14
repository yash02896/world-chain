use std::sync::Arc;

use reth_basic_payload_builder::{
    BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig, BuildArguments, BuildOutcome,
    Cancelled, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
};
use reth_chainspec::ChainSpec;
use reth_db::cursor::DbCursorRW;
use reth_db::mdbx::tx::Tx;
use reth_db::mdbx::{RO, RW};
use reth_db::transaction::{DbTx, DbTxMut};
use reth_db::{Database as _, DatabaseEnv, DatabaseError};
use reth_evm::ConfigureEvm;
use reth_evm_optimism::OptimismEvmConfig;
use reth_node_builder::components::PayloadServiceBuilder;
use reth_node_builder::{BuilderContext, FullNodeTypes, NodeTypesWithEngine, PayloadBuilderConfig};
use reth_node_optimism::node::OptimismPayloadBuilder;
use reth_node_optimism::{
    OptimismBuiltPayload, OptimismEngineTypes, OptimismPayloadBuilderAttributes,
};
use reth_payload_builder::error::PayloadBuilderError;
use reth_payload_builder::{PayloadBuilderHandle, PayloadBuilderService};
use reth_primitives::transaction::WithEncoded;
use reth_primitives::{TransactionSigned, TxHash};
use reth_provider::{CanonStateSubscriptions, ProviderError, StateProviderFactory};
use reth_revm::database::StateProviderDatabase;
use reth_revm::{Database, State};
use reth_transaction_pool::TransactionPool;
use revm_primitives::FixedBytes;
use semaphore::Field;

use crate::node::builder::load_world_chain_db;
use crate::pbh::db::{EmptyValue, ExecutedPbhNullifierTable, ValidatedPbhTransactionTable};

/// Priority blockspace for humans builder
#[derive(Debug, Clone)]
pub struct WorldChainPayloadBuilder<EvmConfig> {
    inner: OptimismPayloadBuilder<EvmConfig>,
    database_env: Arc<DatabaseEnv>,
}

impl<EvmConfig> WorldChainPayloadBuilder<EvmConfig> {
    /// `OptimismPayloadBuilder` constructor.
    pub const fn new(
        compute_pending_block: bool,
        evm_config: EvmConfig,
        database_env: Arc<DatabaseEnv>,
    ) -> Self {
        let inner = OptimismPayloadBuilder::new(compute_pending_block, evm_config);

        Self {
            inner,
            database_env,
        }
    }

    /// Constructs an Ethereum transaction payload from the transactions sent through the
    /// Payload attributes by the sequencer. If the `no_tx_pool` argument is passed in
    /// the payload attributes, the transaction pool will be ignored and the only transactions
    /// included in the payload will be those sent through the attributes.
    ///
    /// Given build arguments including an Ethereum client, transaction pool,
    /// and configuration, this function creates a transaction payload. Returns
    /// a result indicating success with the payload or an error in case of failure.
    fn build_payload<Pool, Client>(
        &self,
        evm_config: EvmConfig,
        args: BuildArguments<Pool, Client, OptimismPayloadBuilderAttributes, OptimismBuiltPayload>,
        _compute_pending_block: bool,
    ) -> Result<BuildOutcome<OptimismBuiltPayload>, PayloadBuilderError>
    where
        EvmConfig: ConfigureEvm,
        Client: StateProviderFactory,
        Pool: TransactionPool,
    {
        let BuildArguments {
            client,
            pool,
            mut cached_reads,
            config,
            cancel,
            best_payload,
        } = args;

        let state_provider = client.state_by_block_hash(config.parent_block.hash())?;
        let state = StateProviderDatabase::new(state_provider);
        let mut db = State::builder()
            .with_database_ref(cached_reads.as_db(state))
            .with_bundle_update()
            .build();

        // self.inner
        //  .init_pre_block_state(&config, evm_config, &mut db)?;

        // let world_chain_block_attributes = match self
        //     .construct_block_attributes(pool, &config, &mut db, &cancel)
        // {
        //     Ok(outcome) => Ok(outcome),
        //     Err(PayloadBuilderError::BuildOutcomeCancelled) => return Ok(BuildOutcome::Cancelled),
        //     Err(err) => Err(err),
        // }?;

        // // check if we have a better block
        // if !is_better_payload(best_payload.as_ref(), op_block_attributes.total_fees) {
        //     // can skip building the block
        //     return Ok(BuildOutcome::Aborted { fees: op_block_attributes.total_fees, cached_reads });
        // }

        // let (withdrawals_outcome, execution_outcome) =
        //     self.inner.construct_outcome(&op_block_attributes, &mut db)?;

        // // calculate the state root
        // let parent_block = config.parent_block;
        // let hashed_state = HashedPostState::from_bundle_state(&execution_outcome.state().state);
        // let (state_root, trie_output) = {
        //     let state_provider = db.database.0.inner.borrow_mut();
        //     state_provider.db.state_root_with_updates(hashed_state.clone()).inspect_err(|err| {
        //         warn!(target: "payload_builder",
        //             parent_hash=%parent_block.hash(),
        //             %err,
        //             "failed to calculate state root for empty payload"
        //         );
        //     })?
        // };

        // let payload = self.inner.construct_built_payload(
        //     world_chain_block_attributes.inner,
        //     execution_outcome,
        //     state_root,
        //     withdrawals_outcome,
        //     hashed_state,
        //     trie_output,
        // );

        // Ok(BuildOutcome::Better { payload, cached_reads })

        todo!()
    }

    /// Constructs new block attributes with a populated list of transactions
    /// This method uses the provided payload attributes and transaction pool to populate the
    /// block attributes.
    ///
    /// # Returns
    ///
    /// * `Ok(OptimismBlockAttributes<EvmConfig>)` with populated block attributes on success
    /// * `Err(PayloadBuilderError::BuildOutcomeCancelled)` if the operation was cancelled
    /// * `Err(PayloadBuilderError::BlobTransactionRejected)` if a blob transaction is encountered
    /// * `Err(PayloadBuilderError::TransactionEcRecoverFailed)` if EC recovery fails for a
    ///   transaction
    /// * `Err(PayloadBuilderError::EvmExecutionError(_))` if an EVM execution error occurs
    // pub fn construct_block_attributes<Pool, DB>(
    //     &self,
    //     pool: Pool,
    //     payload_config: &PayloadConfig<OptimismPayloadBuilderAttributes>,
    //     db: &mut State<DB>,
    //     cancel: &Cancelled,
    // ) -> Result<OptimismBlockAttributes<EvmConfig>, PayloadBuilderError>
    // where
    //     Pool: TransactionPool,
    //     DB: Database<Error = ProviderError>,
    //     EvmConfig: ConfigureEvm,
    // {
    //     let mut world_chain_block_attributes =
    //         WorldChainBlockAttributes::new(payload_config, self.evm_config.clone());

    //     // add sequencer transactions to block
    //     world_chain_block_attributes.add_sequencer_transactions(
    //         &payload_config.attributes.transactions,
    //         db,
    //         cancel,
    //     )?;

    //     world_chain_block_attributes.add_pbh_transactions();

    //     // add pooled transactions to block
    //     world_chain_block_attributes.add_pooled_transactions(&pool, db, cancel)?;

    //     Ok(op_block_attributes)
    // }

    /// Check the database to see if a tx has been validated for PBH
    /// If so return the nullifier
    pub fn get_pbh_validated(
        &self,
        db_tx: Tx<RW>,
        tx: TxHash,
    ) -> Result<Option<FixedBytes<32>>, DatabaseError> {
        db_tx.get::<ValidatedPbhTransactionTable>(tx)
    }

    /// Set the store the nullifier for a tx after it
    /// has been included in the block
    /// don't forget to call db_tx.commit() at the very end
    fn set_pbh_nullifier(
        &self,
        db_tx: Tx<RW>,
        nullifier: FixedBytes<32>,
    ) -> Result<(), DatabaseError> {
        let mut cursor = db_tx.cursor_write::<ExecutedPbhNullifierTable>()?;
        cursor.insert(nullifier, EmptyValue)?;
        Ok(())
    }
}

/// Represents the attributes and state required to build a World Chain block
///
/// This struct holds all necessary data for constructing a block on World Chain
/// including executed transactions, receipts, gas usage, and EVM-specific
/// configuration parameters
// #[derive(Debug)]
// pub struct WorldChainBlockAttributes<EvmConfig: ConfigureEvm> {
//     inner: OptimismBlockAttributes<EvmConfig>,
// }

// impl<EvmConfig> WorldChainBlockAttributes<EvmConfig>
// where
//     EvmConfig: ConfigureEvm,
// {
//     // /// Creates a new `OptimismBlockAttributes` instance.
//     // /// Initializes the block attributes based on the provided payload configuration
//     // /// and EVM configuration.
//     // pub fn new(
//     //     payload_config: &PayloadConfig<OptimismPayloadBuilderAttributes>,
//     //     evm_config: EvmConfig,
//     // ) -> Self {
//     //     let inner = OptimismBlockAttributes::new(payload_config, evm_config);
//     //     Self { inner }
//     // }

//     /// Adds sequencer transactions to the block
//     ///
//     /// # Returns
//     ///
//     /// * `Ok(())` on successful addition of all valid sequencer transactions
//     /// * `Err(PayloadBuilderError::BuildOutcomeCancelled)` if the operation was cancelled
//     /// * `Err(PayloadBuilderError::BlobTransactionRejected)` if a blob transaction is encountered
//     /// * `Err(PayloadBuilderError::TransactionEcRecoverFailed)` if EC recovery fails for a
//     ///   transaction
//     /// * `Err(PayloadBuilderError::EvmExecutionError(EVMError::Transaction(_)))` if an EVM
//     ///   execution error occurs
//     pub fn add_sequencer_transactions<DB>(
//         &mut self,
//         transactions: &[WithEncoded<TransactionSigned>],
//         db: &mut State<DB>,
//         cancel: &Cancelled,
//     ) -> Result<(), PayloadBuilderError>
//     where
//         DB: Database<Error = ProviderError>,
//     {
//         self.inner
//             .add_sequencer_transactions(transactions, db, cancel)
//     }

//     pub fn add_pbh_transactions<DB>(
//         &mut self,
//         transactions: &[WithEncoded<TransactionSigned>],
//         db: &mut State<DB>,
//         cancel: &Cancelled,
//     ) -> Result<(), PayloadBuilderError>
//     where
//         DB: Database<Error = ProviderError>,
//     {
//         todo!()
//     }

//     /// Adds transactions to the block from the transaction pool
//     ///
//     /// # Returns
//     ///
//     /// * `Ok(())` on successful addition of all valid pooled transactions
//     /// * `Err(PayloadBuilderError::BuildOutcomeCancelled)` if the operation was cancelled
//     /// * `Err(PayloadBuilderError::EvmExecutionError(_))` if an EVM execution error occurs
//     pub fn add_pooled_transactions<DB, Pool>(
//         &mut self,
//         pool: &Pool,
//         db: &mut State<DB>,
//         cancel: &Cancelled,
//     ) -> Result<(), PayloadBuilderError>
//     where
//         DB: Database<Error = ProviderError>,
//         Pool: TransactionPool,
//     {
//         self.inner.add_pooled_transactions(pool, db, cancel)
//     }
// }

/// Implementation of the [`PayloadBuilder`] trait for [`PBHBuilder`].
impl<Pool, Client, EvmConfig> PayloadBuilder<Pool, Client> for WorldChainPayloadBuilder<EvmConfig>
where
    Client: StateProviderFactory,
    Pool: TransactionPool,
    EvmConfig: ConfigureEvm,
{
    type Attributes = OptimismPayloadBuilderAttributes;
    type BuiltPayload = OptimismBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Pool, Client, OptimismPayloadBuilderAttributes, OptimismBuiltPayload>,
    ) -> Result<BuildOutcome<OptimismBuiltPayload>, PayloadBuilderError> {
        todo!()
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Pool, Client, OptimismPayloadBuilderAttributes, OptimismBuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        MissingPayloadBehaviour::AwaitInProgress
    }

    fn build_empty_payload(
        &self,
        client: &Client,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<OptimismBuiltPayload, PayloadBuilderError> {
        todo!()
    }
}

#[derive(Debug, Default, Clone)]
pub struct WorldChainPayloadServiceBuilder<EvmConfig = OptimismEvmConfig> {
    /// The EVM configuration to use for the payload builder.
    pub evm_config: EvmConfig,
}

impl<EvmConfig> WorldChainPayloadServiceBuilder<EvmConfig> {
    pub const fn new(evm_config: EvmConfig) -> Self {
        Self { evm_config }
    }
}

impl<Node, EvmConfig, Pool> PayloadServiceBuilder<Node, Pool>
    for WorldChainPayloadServiceBuilder<EvmConfig>
where
    Node: FullNodeTypes<
        Types: NodeTypesWithEngine<Engine = OptimismEngineTypes, ChainSpec = ChainSpec>,
    >,
    Pool: TransactionPool + Unpin + 'static,
    EvmConfig: ConfigureEvm,
{
    async fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<PayloadBuilderHandle<OptimismEngineTypes>> {
        let data_dir = ctx.config().datadir();
        let db = load_world_chain_db(data_dir.data_dir(), false)?;
        let payload_builder = WorldChainPayloadBuilder::new(true, self.evm_config, db);

        let conf = ctx.payload_builder_config();

        let payload_job_config = BasicPayloadJobGeneratorConfig::default()
            .interval(conf.interval())
            .deadline(conf.deadline())
            .max_payload_tasks(conf.max_payload_tasks())
            // no extradata for OP
            .extradata(Default::default());

        let payload_generator = BasicPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            pool,
            ctx.task_executor().clone(),
            payload_job_config,
            ctx.chain_spec(),
            payload_builder,
        );
        let (payload_service, payload_builder) =
            PayloadBuilderService::new(payload_generator, ctx.provider().canonical_state_stream());

        ctx.task_executor()
            .spawn_critical("payload builder service", Box::pin(payload_service));

        Ok(payload_builder)
    }
}
