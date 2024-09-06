use clap::Parser;
use reth_node_optimism::{args::RollupArgs, OptimismNode};
use reth_optimism_cli::Cli;

#[cfg(all(feature = "jemalloc", unix))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) = Cli::<RollupArgs>::parse().run(|builder, rollup_args| async move {
        let handle = builder
            .node(OptimismNode::new(rollup_args.clone()))
            .launch()
            .await?;

        handle.node_exit_future.await
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
