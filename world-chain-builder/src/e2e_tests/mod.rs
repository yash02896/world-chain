//! Utilities for running world chain builder end-to-end tests.
use crate::{
    node::{
        args::{ExtArgs, WorldChainBuilderArgs},
        builder::{WorldChainAddOns, WorldChainBuilder},
    },
    pool::{
        ordering::WorldChainOrdering,
        root::{LATEST_ROOT_SLOT, OP_WORLD_ID},
        tx::WorldChainPooledTransaction,
        validator::{tests::valid_proof, WorldChainTransactionValidator},
    },
    primitives::{recover_raw_transaction, WorldChainPooledTransactionsElement},
};
use alloy_signer_local::PrivateKeySigner;
use reth_chainspec::ChainSpec;
use reth_consensus::Consensus;
use reth_db::{
    test_utils::{tempdir_path, TempDatabase},
    DatabaseEnv,
};
use reth_e2e_test_utils::{
    node::NodeTestContext, transaction::TransactionTestContext, wallet::Wallet,
};
use reth_evm_optimism::{OpExecutorProvider, OptimismEvmConfig};
use reth_node_api::{FullNodeTypesAdapter, NodeTypesWithDBAdapter};
use reth_node_builder::{components::Components, NodeAdapter, NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::RpcServerArgs;
use reth_node_optimism::OptimismPayloadBuilderAttributes;
use reth_payload_builder::{EthPayloadBuilderAttributes, PayloadId};
use reth_primitives::{
    Genesis, GenesisAccount, PooledTransactionsElement, Withdrawals, BASE_MAINNET,
};
use reth_provider::providers::BlockchainProvider;
use reth_tasks::TaskManager;
use reth_transaction_pool::{
    blobstore::DiskFileBlobStore, Pool, TransactionValidationTaskExecutor,
};
use revm_primitives::{address, Address, FixedBytes, B256, U256};
use semaphore::Field;
use std::{collections::BTreeMap, sync::Arc};
use tracing::{span, Level};

pub const DEV_SIGNER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
pub const DEV_WALLET: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// Creates a new test node with a world chain builder.
pub async fn setup(
    chain_spec: Arc<ChainSpec>,
) -> eyre::Result<(NodeTestContextType, Vec<PrivateKeySigner>, u64, TaskManager)> {
    let tasks = TaskManager::current();
    let exec = tasks.executor();
    let chain_id = chain_spec.chain.id();
    let node_config = NodeConfig::test()
        .with_chain(chain_spec)
        .with_unused_ports()
        .with_rpc(
            RpcServerArgs::default()
                .with_unused_ports()
                .with_http_unused_port(),
        );
    let path = tempdir_path();
    let NodeHandle {
        node,
        node_exit_future: _,
    } = NodeBuilder::new(node_config.clone())
        .testing_node(exec.clone())
        .node(WorldChainBuilder::new(
            ExtArgs {
                builder_args: WorldChainBuilderArgs {
                    num_pbh_txs: 30,
                    verified_blockspace_capacity: 70,
                    ..Default::default()
                },
                ..Default::default()
            },
            &path,
        )?)
        .launch()
        .await?;

    let wallets = Wallet::new(10).with_chain_id(chain_id).gen();

    return Ok((NodeTestContext::new(node).await?, wallets, chain_id, tasks));
}

type Adapter = NodeAdapter<
    FullNodeTypesAdapter<
        NodeTypesWithDBAdapter<WorldChainBuilder, Arc<TempDatabase<DatabaseEnv>>>,
        BlockchainProvider<
            NodeTypesWithDBAdapter<WorldChainBuilder, Arc<TempDatabase<DatabaseEnv>>>,
        >,
    >,
    Components<
        FullNodeTypesAdapter<
            NodeTypesWithDBAdapter<WorldChainBuilder, Arc<TempDatabase<DatabaseEnv>>>,
            BlockchainProvider<
                NodeTypesWithDBAdapter<WorldChainBuilder, Arc<TempDatabase<DatabaseEnv>>>,
            >,
        >,
        Pool<
            TransactionValidationTaskExecutor<
                WorldChainTransactionValidator<
                    BlockchainProvider<
                        NodeTypesWithDBAdapter<WorldChainBuilder, Arc<TempDatabase<DatabaseEnv>>>,
                    >,
                    WorldChainPooledTransaction,
                >,
            >,
            WorldChainOrdering<WorldChainPooledTransaction>,
            DiskFileBlobStore,
        >,
        OptimismEvmConfig,
        OpExecutorProvider,
        Arc<dyn Consensus>,
    >,
>;

pub type NodeTestContextType = NodeTestContext<Adapter, WorldChainAddOns>;

#[tokio::test]
async fn test_can_build_mixed_pbh_payload() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    // Create a raw signed transfer
    let raw_tx = TransactionTestContext::transfer_tx_bytes(8453, DEV_SIGNER.parse().unwrap()).await;

    let mut data = raw_tx.as_ref();
    // Decode the tx envelope
    let recovered = PooledTransactionsElement::decode_enveloped(&mut data).unwrap();
    let proof = valid_proof(
        &mut [0; 32],
        recovered.hash().as_slice(),
        chrono::Utc::now(),
        0,
    );
    // Create a pbh pooled transaction element
    let world_chain_pooled_tx_element = WorldChainPooledTransactionsElement {
        inner: recovered,
        semaphore_proof: Some(proof.clone()),
    };

    // Re-encode the envolope
    let mut buff = Vec::<u8>::new();
    world_chain_pooled_tx_element.encode_enveloped(&mut buff);

    // Pre-validate the decoding
    let pooled_transaction_element = recover_raw_transaction(buff.clone().into());
    assert!(
        pooled_transaction_element.is_ok_and(|e| e.0.semaphore_proof.is_some_and(|p| p == proof))
    );

    let chain_spec = get_chain_spec(proof.root);

    let (mut node, mut dev_wallets, id, _tasks) = setup(chain_spec).await?;
    let std_wallet = dev_wallets.pop().unwrap();
    // inject normal tx
    let raw_tx = TransactionTestContext::transfer_tx_bytes(id, std_wallet.clone()).await;
    // Call eth_sendRawTransaction with the enveloped semaphore tx.
    let semaphore_res = node.rpc.inject_tx(buff.into()).await;
    let res = node.rpc.inject_tx(raw_tx).await;

    assert!(res.is_ok());
    assert!(semaphore_res.is_ok());

    let (payload, _) = node
        .advance_block(vec![], optimism_payload_attributes)
        .await?;

    // Should have both transactions in the block
    assert_eq!(payload.block().body.len(), 2);
    let block_hash = payload.block().hash();
    let block_number = payload.block().number;
    // should be head
    let tip = semaphore_res?;

    // assert the block has been committed with priority ordering
    node.assert_new_block(tip, block_hash, block_number).await?;

    Ok(())
}

#[tokio::test]
async fn test_can_build_non_pbh_payload() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let span = span!(Level::INFO, "node");
    let chain_spec = get_chain_spec(U256::ZERO);
    let _enter = span.enter();
    // Create a raw signed transfer
    let (mut node, mut dev_wallets, id, _tasks) = setup(chain_spec).await?;
    let std_wallet = dev_wallets.pop().unwrap();
    // inject normal tx
    let raw_tx = TransactionTestContext::transfer_tx_bytes(id, std_wallet.clone()).await;
    let res = node.rpc.inject_tx(raw_tx).await;
    assert!(res.is_ok());
    let tx_hash = res?;
    let (payload, _) = node
        .advance_block(vec![], optimism_payload_attributes)
        .await?;
    let block_hash = payload.block().hash();
    let block_number = payload.block().number;

    // assert the block has been committed to the blockchain
    node.assert_new_block(tx_hash, block_hash, block_number)
        .await?;
    Ok(())
}

/// Helper function to create a new eth payload attributes
pub fn optimism_payload_attributes(timestamp: u64) -> OptimismPayloadBuilderAttributes {
    let attributes = EthPayloadBuilderAttributes {
        timestamp,
        prev_randao: B256::ZERO,
        suggested_fee_recipient: Address::ZERO,
        withdrawals: Withdrawals::default(),
        parent_beacon_block_root: Some(B256::ZERO),
        id: PayloadId(FixedBytes::<8>::random()),
        parent: FixedBytes::default(),
    };

    OptimismPayloadBuilderAttributes {
        payload_attributes: attributes,
        transactions: vec![],
        gas_limit: None,
        no_tx_pool: false,
    }
}

/// Builds an OP Mainnet chain spec with the given merkle root
/// Populated in the OpWorldID contract.
fn get_chain_spec(merkle_root: Field) -> Arc<ChainSpec> {
    let genesis: Genesis = serde_json::from_str(include_str!("assets/genesis.json")).unwrap();
    let chain_spec = ChainSpec::builder()
        .chain(BASE_MAINNET.chain)
        .genesis(genesis.extend_accounts(vec![
            (
                OP_WORLD_ID,
                GenesisAccount::default().with_storage(Some(BTreeMap::from_iter(vec![(
                    LATEST_ROOT_SLOT.into(),
                    merkle_root.into(),
                )]))),
            ),
            (
                DEV_WALLET,
                GenesisAccount::default().with_balance(U256::MAX),
            ),
        ]))
        .ecotone_activated()
        .build();
    Arc::new(chain_spec)
}
