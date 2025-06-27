use anyhow::Result;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod config;
mod error;
mod api;
mod auth;
mod wallet;
mod ledger;
mod signer;
mod ffi;
mod grpc;
mod cli;

use crate::config::Config;
use crate::api::ApiServer;
use crate::grpc::GrpcServer;
use crate::ledger::LedgerStore;
use crate::wallet::WalletManager;
use crate::auth::AuthManager;
use crate::cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    // Check if CLI arguments are provided
    use clap::Parser;
    let cli = Cli::parse();
    
    // Handle CLI commands first
    if let Some(ref command) = cli.command {
        match command {
            Commands::Start { background: _ } => {
                // Continue to start daemon
            }
            _ => {
                // Handle other CLI commands
                return crate::cli::run_cli().await;
            }
        }
    }
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    info!("🔐 Starting walletd - GhostChain Secure Wallet Daemon");
    
    // Load configuration
    let config = Config::load()?;
    info!("📁 Configuration loaded from: {}", config.config_path.display());
    
    // Initialize database/ledger
    let ledger: Arc<LedgerStore> = Arc::new(LedgerStore::new(&config.database_path).await?);
    info!("💾 Ledger store initialized");
    
    // Initialize authentication manager
    let auth_manager: Arc<AuthManager> = Arc::new(AuthManager::new(config.clone()).await?);
    info!("🔐 Authentication manager initialized");
    
    // Initialize wallet manager
    let wallet_manager: Arc<WalletManager> = Arc::new(
        WalletManager::new(
            config.clone(),
            ledger.clone(),
            auth_manager.clone()
        ).await?
    );
    info!("💼 Wallet manager initialized");
    
    // Start gRPC server
    let grpc_server = GrpcServer::new(
        config.clone(),
        wallet_manager.clone(),
        ledger.clone(),
    );
    
    let grpc_handle = tokio::spawn(async move {
        if let Err(e) = grpc_server.serve().await {
            warn!("gRPC server error: {}", e);
        }
    });
    
    // Start REST API server
    let api_server = ApiServer::new(
        config.clone(),
        wallet_manager.clone(),
        ledger.clone(),
        auth_manager.clone(),
    );
    
    let api_handle = tokio::spawn(async move {
        if let Err(e) = api_server.serve().await {
            warn!("API server error: {}", e);
        }
    });
    
    info!("🚀 walletd started successfully");
    info!("📡 gRPC server listening on: {}", config.grpc_bind_address);
    info!("🌐 REST API server listening on: {}", config.api_bind_address);
    
    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("🛑 Shutdown signal received, stopping walletd...");
    
    // Graceful shutdown
    grpc_handle.abort();
    api_handle.abort();
    
    info!("👋 walletd stopped");
    Ok(())
}
