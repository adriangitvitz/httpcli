#[cfg(feature = "mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod cache;
mod cli;
mod client;
mod config;
mod error;
mod http_parser;
mod request;
mod response;
mod syntax;
mod tls;

use clap::Parser;
use cli::Cli;
use client::HttpClient;
use config::Config;
use error::Result;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .init();

    info!("Starting httpcli - High-performance HTTP CLI");

    let cli = Cli::parse();
    let config = Config::load(&cli)?;
    let client = HttpClient::new(config.clone()).await?;

    client.execute(cli).await?;

    Ok(())
}
