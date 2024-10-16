//! Utilities for running world chain builder end-to-end tests.
use crate::{
    node::{
        args::{ExtArgs, WorldChainBuilderArgs},
        builder::{WorldChainAddOns, WorldChainBuilder},
    },
    pbh::date_marker::DateMarker,
    pbh::external_nullifier::{ExternalNullifier, Prefix},
    pbh::payload::{PbhPayload, Proof},
    pool::{
        ordering::WorldChainOrdering,
        root::{LATEST_ROOT_SLOT, OP_WORLD_ID},
        tx::WorldChainPooledTransaction,
        validator::WorldChainTransactionValidator,
    },
    primitives::WorldChainPooledTransactionsElement,
};
use alloy_genesis::{Genesis, GenesisAccount};
use alloy_network::eip2718::Encodable2718;
use alloy_network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy_rpc_types::{TransactionInput, TransactionRequest};
use alloy_signer_local::PrivateKeySigner;
use chrono::Utc;
use reth::api::{FullNodeTypesAdapter, NodeTypesWithDBAdapter};
use reth::builder::{components::Components, NodeAdapter, NodeBuilder, NodeConfig, NodeHandle};
use reth::chainspec::ChainSpec;
use reth::payload::{EthPayloadBuilderAttributes, PayloadId};
use reth::tasks::TaskManager;
use reth::transaction_pool::{
    blobstore::DiskFileBlobStore, Pool, TransactionValidationTaskExecutor,
};
use reth_consensus::Consensus;
use reth_db::{
    test_utils::{tempdir_path, TempDatabase},
    DatabaseEnv,
};
use reth_e2e_test_utils::{
    node::NodeTestContext, transaction::TransactionTestContext, wallet::Wallet,
};
use reth_node_core::args::RpcServerArgs;
use reth_optimism_chainspec::{OpChainSpec, BASE_MAINNET};
use reth_optimism_evm::{OpExecutorProvider, OptimismEvmConfig};
use reth_optimism_node::{engine::OptimismEngineValidator, OptimismPayloadBuilderAttributes};
use reth_primitives::{PooledTransactionsElement, Withdrawals};
use reth_provider::providers::BlockchainProvider;
use revm_primitives::{bytes, Address, Bytes, FixedBytes, TxKind, B256, U256};
use semaphore::{
    hash_to_field,
    identity::Identity,
    poseidon_tree::LazyPoseidonTree,
    protocol::{generate_nullifier_hash, generate_proof},
    Field,
};
use serial_test::serial;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};

pub const DEV_CHAIN_ID: u64 = 8453;

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
        OptimismEngineValidator,
    >,
>;

pub struct WorldChainBuilderTestContext {
    pub pbh_wallets: Vec<PrivateKeySigner>,
    pub tree: LazyPoseidonTree,
    pub node: NodeTestContext<Adapter, WorldChainAddOns>,
    pub tasks: TaskManager,
    pub identities: HashMap<Address, usize>,
}

impl WorldChainBuilderTestContext {
    pub async fn setup() -> eyre::Result<Self> {
        let wallets = Wallet::new(20).with_chain_id(DEV_CHAIN_ID).gen();
        let mut tree = LazyPoseidonTree::new(30, Field::from(0)).derived();
        let mut identities = HashMap::new();
        for (i, signer) in wallets.iter().enumerate() {
            let address = signer.address();
            identities.insert(address, i);
            let identity = Identity::from_secret(signer.address().as_mut_slice(), None);
            tree = tree.update(i, &identity.commitment());
        }

        let op_chain_spec = Arc::new(OpChainSpec {
            inner: get_chain_spec(tree.root()),
        });

        let tasks = TaskManager::current();
        let exec = tasks.executor();

        let node_config: NodeConfig<OpChainSpec> = NodeConfig::new(op_chain_spec.clone())
            .with_chain(op_chain_spec.clone())
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

        Ok(Self {
            pbh_wallets: wallets,
            tree,
            node: NodeTestContext::new(node).await?,
            tasks,
            identities,
        })
    }

    pub async fn raw_pbh_tx_bytes(
        &self,
        signer: PrivateKeySigner,
        pbh_nonce: u16,
        tx_nonce: u64,
    ) -> Bytes {
        let tx = tx(DEV_CHAIN_ID, None, tx_nonce);
        let envelope = TransactionTestContext::sign_tx(signer.clone(), tx).await;
        let raw_tx = envelope.encoded_2718();
        let mut data = raw_tx.as_ref();
        let recovered = PooledTransactionsElement::decode_enveloped(&mut data).unwrap();
        let proof = self.valid_proof(
            signer.address(),
            recovered.hash().as_slice(),
            chrono::Utc::now(),
            pbh_nonce,
        );

        let world_chain_pooled_tx_element = WorldChainPooledTransactionsElement {
            inner: recovered,
            semaphore_proof: Some(proof.clone()),
        };

        let mut buff = Vec::<u8>::new();
        world_chain_pooled_tx_element.encode_enveloped(&mut buff);
        buff.into()
    }

    fn valid_proof(
        &self,
        identity: Address,
        tx_hash: &[u8],
        time: chrono::DateTime<Utc>,
        pbh_nonce: u16,
    ) -> PbhPayload {
        let external_nullifier =
            ExternalNullifier::new(Prefix::V1, DateMarker::from(time), pbh_nonce).to_string();

        self.create_proof(identity, external_nullifier, tx_hash)
    }

    fn create_proof(
        &self,
        mut identity: Address,
        external_nullifier: String,
        signal: &[u8],
    ) -> PbhPayload {
        let idx = self.identities.get(&identity).unwrap();
        let secret = identity.as_mut_slice();
        // generate identity
        let id = Identity::from_secret(secret, None);
        let merkle_proof = self.tree.proof(*idx);

        let signal_hash = hash_to_field(signal);
        let external_nullifier_hash = hash_to_field(external_nullifier.as_bytes());
        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);

        let proof = Proof(
            generate_proof(&id, &merkle_proof, external_nullifier_hash, signal_hash).unwrap(),
        );

        PbhPayload {
            root: self.tree.root(),
            nullifier_hash,
            external_nullifier,
            proof,
        }
    }
}

#[test]
fn extract_root() -> eyre::Result<()> {
    let raw = bytes!("02f8698320d5e480018409514a3582520894deadbeefdeadbeefdeadbeefdeadbeefdeadbeef8080c080a06992b735670fe604ff62c8c72916e3c9d30d5c8af20b0e3db76ba4edf5c401caa078e576904ab9f8712096a76a96ba3fe1b7142ccebe90f747f13b11ad2e0208b8f901518b76312d3130323032342d30a00fb52a8c913bf166574034087d5f1f5323dba5b972bdf6e0b879f82ec876f004a0133dbdee27c5f1171b0417dddf26d9664b775cc41f5676693d9c5184f42097c9b901000bf19cb5c47d0d44b2d89efa1abcce029d70480245f525c506862158114ce7e40a39ac91e8a218f532383a6bbd1d10f019a2b8db391762c701ca5d17bbbddb6a156d3164ba22de36ef22d26245752e7ff829a8a335d3e68537c9339d22ca01a316ed3d10f14b85002c0302290c048e3e20450521ba6dbd90ca9aa58ce5fabfd22f33a2b2b1b98b813e9092e80e5653129e90646cdb00ff71bf358702ca8afacd2a49ba91f5a5c6958398ed2f6c31fc29c5325068f9187f0bbea469188fef573a1c8fb32e1b087152482f326cba212c3f7a15139938c460d51e020d4fd2950cc50c2d1047a338170a4178a3f50039dec10a4300be09740f3e8d48aa8bc36d5405");
    let envelope =
        WorldChainPooledTransactionsElement::decode_enveloped(&mut raw.as_ref()).unwrap();
    println!("{:?}", envelope.semaphore_proof.unwrap().root);
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_can_build_pbh_payload() -> eyre::Result<()> {
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut ctx = WorldChainBuilderTestContext::setup().await?;
    let mut pbh_tx_hashes = vec![];
    for signer in ctx.pbh_wallets.iter() {
        let raw_tx = ctx.raw_pbh_tx_bytes(signer.clone(), 0, 0).await;
        let pbh_hash = ctx.node.rpc.inject_tx(raw_tx.clone()).await?;
        pbh_tx_hashes.push(pbh_hash);
    }

    let (payload, _) = ctx
        .node
        .advance_block(vec![], optimism_payload_attributes)
        .await?;

    assert_eq!(payload.block().body.transactions.len(), pbh_tx_hashes.len());
    let block_hash = payload.block().hash();
    let block_number = payload.block().number;

    let tip = pbh_tx_hashes[0];
    ctx.node
        .assert_new_block(tip, block_hash, block_number)
        .await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_transaction_pool_ordering() -> eyre::Result<()> {
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut ctx = WorldChainBuilderTestContext::setup().await?;
    let non_pbh_tx = tx(ctx.node.inner.chain_spec().chain.id(), None, 0);
    let wallet = ctx.pbh_wallets[0].clone();
    let signer = EthereumWallet::from(wallet);
    let signed = <TransactionRequest as TransactionBuilder<Ethereum>>::build(non_pbh_tx, &signer)
        .await
        .unwrap();
    let non_pbh_hash = ctx.node.rpc.inject_tx(signed.encoded_2718().into()).await?;
    let mut pbh_tx_hashes = vec![];
    for signer in ctx.pbh_wallets.iter().skip(1) {
        let raw_tx = ctx.raw_pbh_tx_bytes(signer.clone(), 0, 0).await;
        let pbh_hash = ctx.node.rpc.inject_tx(raw_tx.clone()).await?;
        pbh_tx_hashes.push(pbh_hash);
    }

    let (payload, _) = ctx
        .node
        .advance_block(vec![], optimism_payload_attributes)
        .await?;

    assert_eq!(
        payload.block().body.transactions.len(),
        pbh_tx_hashes.len() + 1
    );
    // Assert the non-pbh transaction is included in the block last
    assert_eq!(
        payload.block().body.transactions.last().unwrap().hash(),
        non_pbh_hash
    );
    let block_hash = payload.block().hash();
    let block_number = payload.block().number;

    let tip = pbh_tx_hashes[0];
    ctx.node
        .assert_new_block(tip, block_hash, block_number)
        .await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_invalidate_dup_tx_and_nullifier() -> eyre::Result<()> {
    tokio::time::sleep(Duration::from_secs(1)).await;
    let ctx = WorldChainBuilderTestContext::setup().await?;
    let signer = ctx.pbh_wallets[0].clone();
    let raw_tx = ctx.raw_pbh_tx_bytes(signer.clone(), 0, 0).await;
    ctx.node.rpc.inject_tx(raw_tx.clone()).await?;
    let dup_pbh_hash_res = ctx.node.rpc.inject_tx(raw_tx.clone()).await;
    assert!(dup_pbh_hash_res.is_err());
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_dup_pbh_nonce() -> eyre::Result<()> {
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut ctx = WorldChainBuilderTestContext::setup().await?;
    let signer = ctx.pbh_wallets[0].clone();

    let raw_tx_0 = ctx.raw_pbh_tx_bytes(signer.clone(), 0, 0).await;
    ctx.node.rpc.inject_tx(raw_tx_0.clone()).await?;

    let raw_tx_1 = ctx.raw_pbh_tx_bytes(signer.clone(), 0, 1).await;
    ctx.node.rpc.inject_tx(raw_tx_1.clone()).await?;

    let (payload, _) = ctx
        .node
        .advance_block(vec![], optimism_payload_attributes)
        .await?;

    // Both transactions should be successfully validated
    // but only one should be included in the block
    assert_eq!(payload.block().body.transactions.len(), 1);

    // Now that the nullifier has successfully been stored in
    // the `ExecutedPbhNullifierTable`, inserting a new tx with the
    // same pbh_nonce should fail to validate.
    let raw_tx_2 = ctx.raw_pbh_tx_bytes(signer.clone(), 0, 2).await;
    assert!(ctx.node.rpc.inject_tx(raw_tx_2.clone()).await.is_err());

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

fn tx(chain_id: u64, data: Option<Bytes>, nonce: u64) -> TransactionRequest {
    TransactionRequest {
        nonce: Some(nonce),
        value: Some(U256::from(100)),
        to: Some(TxKind::Call(Address::random())),
        gas: Some(210000),
        max_fee_per_gas: Some(20e10 as u128),
        max_priority_fee_per_gas: Some(20e10 as u128),
        chain_id: Some(chain_id),
        input: TransactionInput { input: None, data },
        ..Default::default()
    }
}

/// Builds an OP Mainnet chain spec with the given merkle root
/// Populated in the OpWorldID contract.
fn get_chain_spec(merkle_root: Field) -> ChainSpec {
    let genesis: Genesis = serde_json::from_str(include_str!("assets/genesis.json")).unwrap();
    ChainSpec::builder()
        .chain(BASE_MAINNET.chain)
        .genesis(genesis.extend_accounts(vec![(
            OP_WORLD_ID,
            GenesisAccount::default().with_storage(Some(BTreeMap::from_iter(vec![(
                LATEST_ROOT_SLOT.into(),
                merkle_root.into(),
            )]))),
        )]))
        .ecotone_activated()
        .build()
}
