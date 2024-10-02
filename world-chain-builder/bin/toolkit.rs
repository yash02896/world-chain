use clap::Parser;

#[derive(Debug, Clone, Parser)]
struct Args {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Clone, Parser)]
enum Cmd {
    Prove(ProveArgs),
}

#[derive(Debug, Clone, Parser)]
struct ProveArgs {
    #[clap(short, long)]
    tx_index: usize,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    dotenvy::dotenv().ok();

    let args = Args::parse();
    println!("{:?}", args);

    Ok(())
}
