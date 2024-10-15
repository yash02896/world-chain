use core::time;
use std::{
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::Bytes;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::BlockNumberOrTag;
use alloy_transport::Transport;
use clap::Parser;
use eyre::eyre::{eyre, Result};
use serde::Deserialize;
use tokio::time::sleep;
use tracing::info;

const PBH_FIXTURE: &str = include_str!("../../../../devnet/fixtures/fixture.json");

/// The endpoint of the WorldChain Builder client.
const BUILDER_SOCKET: &str = "http://localhost:54542";

/// The endpoint of the Sequencer client.
const SEQUENCER_SOCKET: &str = "http://localhost:TODO";

#[derive(Deserialize, Clone)]
pub struct PbhFixture {
    pub fixture: Vec<Bytes>,
}

#[derive(Parser)]
pub struct Args {
    /// Build a PBH block from transaction fixtures with the given number of transactions
    #[clap(short, long, conflicts_with = "fallback_test")]
    pub build_test: Option<u16>,
    /// Run a Fallback test
    #[clap(short, long, conflicts_with = "build_test")]
    pub fallback_test: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let sequencer_provider =
        Arc::new(ProviderBuilder::default().on_http(SEQUENCER_SOCKET.parse().unwrap()));
    let builder_provider =
        Arc::new(ProviderBuilder::default().on_http(BUILDER_SOCKET.parse().unwrap()));
    let timeout = std::time::Duration::from_secs(30);
    info!("Waiting for the devnet");
    let f = async {
        let wait_0 = wait(sequencer_provider.clone(), timeout);
        let wait_1 = wait(builder_provider.clone(), timeout);
        tokio::join!(wait_0, wait_1);
    };
    f.await;

    // Wait for the denvet to be ready
    info!("Devnet is ready");

    if let Some(num_txs) = args.build_test {
        info!("Running block building test");
        assert_build(builder_provider, num_txs).await?;
    }

    if let Some(_num_txs) = args.fallback_test {
        info!("Running Sequencer fallback test");
        // fallback(sequencer_provider, builder_provider).unwrap();
    }

    Ok(())
}

async fn wait<T, P>(provider: P, timeout: time::Duration)
where
    T: Transport + Clone,
    P: Provider<T>,
{
    let start = Instant::now();
    loop {
        if let Ok(_) = provider
            .get_block_by_number(BlockNumberOrTag::Latest, false)
            .await
        {
            break;
        }
        sleep(Duration::from_secs(1)).await;
        if start.elapsed() > timeout {
            panic!("Timeout waiting for the devnet");
        }
    }
}

pub async fn assert_build<T, P>(builder_provider: Arc<P>, num_txs: u16) -> Result<()>
where
    T: Transport + Clone,
    P: Provider<T>,
{
    let fixture = serde_json::from_str::<PbhFixture>(PBH_FIXTURE)?;
    let transactions = fixture.fixture[..num_txs as usize - 1].to_vec();
    let futs = transactions
        .iter()
        .map(|tx| async {
            // Pbh Transactions are isolated within the builder.
            // This ensures that the builder is building the block(s).
            let builder_provider = builder_provider.clone();
            let tx = builder_provider
                .send_raw_transaction(tx)
                .await
                .expect("Failed to send tx");
            let receipt = builder_provider
                .get_transaction_receipt(*tx.tx_hash())
                .await
                .expect("Failed to get receipt for transaction");
            assert!(
                receipt.is_some_and(|r| r.status() == true),
                "Transaction failed"
            );
        })
        .collect::<Vec<_>>();

    futures::future::join_all(futs).await;
    Ok(())
}

pub fn assert_fallback<T, P>(sequencer_provider: P, builder_provider: P) -> Result<()>
where
    T: Transport + Clone,
    P: Provider<T>,
{
    // TODO:
    Ok(())
}

pub fn run_command(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd).args(args).output()?;
    if output.status.success() {
        Ok(String::from_utf8(output.stdout)?)
    } else {
        Err(eyre!(
            "Command failed: {:?}",
            String::from_utf8(output.stdout).unwrap(),
        ))
    }
}
