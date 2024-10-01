//! Utilities for running world chain builder end-to-end tests.
use alloy_rlp::Encodable;
use reth_chainspec::ChainSpec;
use reth_chainspec::EthChainSpec;
use reth_consensus::Consensus;
use reth_db::test_utils::tempdir_path;
use reth_db::test_utils::TempDatabase;
use reth_db::DatabaseEnv;
use reth_e2e_test_utils::transaction::TransactionTestContext;
use reth_e2e_test_utils::{node::NodeTestContext, wallet::Wallet};
use reth_evm_optimism::OpExecutorProvider;
use reth_evm_optimism::OptimismEvmConfig;
use reth_node_api::FullNodeTypesAdapter;
use reth_node_api::NodeTypesWithDBAdapter;
use reth_node_builder::components::Components;
use reth_node_builder::NodeAdapter;
use reth_node_builder::{NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::{DiscoveryArgs, NetworkArgs, RpcServerArgs};
use reth_node_optimism::OptimismPayloadBuilderAttributes;
use reth_payload_builder::EthPayloadBuilderAttributes;
use reth_payload_builder::PayloadId;
use reth_primitives::GenesisAccount;
use reth_primitives::PooledTransactionsElement;
use reth_primitives::Withdrawals;
use reth_primitives::OP_MAINNET;
use reth_provider::providers::BlockchainProvider;
use reth_tasks::TaskManager;
use reth_transaction_pool::blobstore::DiskFileBlobStore;
use reth_transaction_pool::Pool;
use reth_transaction_pool::TransactionValidationTaskExecutor;
use revm_primitives::address;
use revm_primitives::Address;
use revm_primitives::FixedBytes;
use revm_primitives::B256;
use revm_primitives::U256;
use semaphore::Field;
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{span, Level};

use crate::node::args::ExtArgs;
use crate::node::builder::WorldChainAddOns;
use crate::node::builder::WorldChainBuilder;
use crate::pool::ordering::WorldChainOrdering;
use crate::pool::root::LATEST_ROOT_SLOT;
use crate::pool::root::OP_WORLD_ID;
use crate::pool::tx::WorldChainPooledTransaction;
use crate::pool::validator::tests::valid_proof;
use crate::pool::validator::WorldChainTransactionValidator;
use crate::primitives::recover_raw_transaction;
use crate::primitives::WorldChainPooledTransactionsElement;

pub const DEV_SIGNER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
pub const DEV_WALLET: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// Creates the initial setup with `num_nodes` started and interconnected.
pub async fn setup(
    num_nodes: usize,
    chain_spec: Arc<ChainSpec>,
    is_dev: bool,
) -> eyre::Result<(Vec<NodeTestContextType>, TaskManager, Wallet)> {
    let tasks = TaskManager::current();
    let exec = tasks.executor();

    let network_config = NetworkArgs {
        discovery: DiscoveryArgs {
            disable_discovery: true,
            ..DiscoveryArgs::default()
        },
        ..NetworkArgs::default()
    };

    // Create nodes and peer them
    let mut nodes: Vec<NodeTestContext<_, _>> = Vec::with_capacity(num_nodes);

    for idx in 0..num_nodes {
        let node_config = NodeConfig::test()
            .with_chain(chain_spec.clone())
            .with_network(network_config.clone())
            .with_unused_ports()
            .with_rpc(RpcServerArgs::default().with_unused_ports().with_http())
            .set_dev(is_dev);

        let span = span!(Level::INFO, "node", idx);
        let _enter = span.enter();
        let NodeHandle {
            node,
            node_exit_future: _,
        } = NodeBuilder::new(node_config.clone())
            .testing_node(exec.clone())
            .node(WorldChainBuilder::new(ExtArgs::default(), &tempdir_path())?)
            .launch()
            .await?;

        let mut node = NodeTestContext::new(node).await?;

        // Connect each node in a chain.
        if let Some(previous_node) = nodes.last_mut() {
            previous_node.connect(&mut node).await;
        }

        // Connect last node with the first if there are more than two
        if idx + 1 == num_nodes && num_nodes > 2 {
            if let Some(first_node) = nodes.first_mut() {
                node.connect(first_node).await;
            }
        }

        nodes.push(node);
    }

    Ok((
        nodes,
        tasks,
        Wallet::default().with_chain_id(chain_spec.chain().into()),
    ))
}

// TODO: There's definetely a better way to write this. lol
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
async fn test_can_send_raw_pbh_encoded_envelope() -> eyre::Result<()> {
    // Create a raw signed transfer
    let raw_tx = TransactionTestContext::transfer_tx_bytes(1, DEV_SIGNER.parse().unwrap()).await;
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
    world_chain_pooled_tx_element.encode(&mut buff);

    // Pre-validate the decoding
    let pooled_transaction_element = recover_raw_transaction(buff.clone().into());
    assert!(
        pooled_transaction_element.is_ok_and(|e| e.0.semaphore_proof.is_some_and(|p| p == proof))
    );

    let chain_spec = get_chain_spec(proof.root);

    // Boot up a network of nodes on the chain spec
    let (mut nodes, _, _) = setup(2, chain_spec.into(), false).await?;
    let mut node = nodes.pop().unwrap();

    // make the node advance
    // Failing here with
    // Error: validation service unreachable
    let tx_hash = node.rpc.inject_tx(buff.into()).await?;

    // make the node advance
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
    let chain_spec = ChainSpec::builder()
        .granite_activated()
        .genesis(OP_MAINNET.genesis.clone().extend_accounts(vec![
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
        .chain(OP_MAINNET.chain())
        .build();
    Arc::new(chain_spec)
}
