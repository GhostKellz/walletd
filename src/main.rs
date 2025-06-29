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
mod quic;  // GQUIC transport module
mod zquic; // NEW: ZQUIC transport module (primary)
mod crypto; // Enhanced crypto module

use crate::config::Config;
use crate::api::ApiServer;
use crate::grpc::GrpcServer;
use crate::quic::QuicServer; // GQUIC server
use crate::zquic::ZQuicTransport; // NEW: ZQUIC transport (primary)
use crate::crypto::EnhancedCrypto; // Enhanced crypto
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
    
    // Initialize enhanced crypto backend if available
    let enhanced_crypto = if cfg!(feature = "enhanced-crypto") {
        match EnhancedCrypto::new() {
            Ok(crypto) => {
                info!("🔐 Enhanced gcrypt backend initialized with algorithms: {:?}", crypto.supported_algorithms());
                Some(Arc::new(crypto))
            }
            Err(e) => {
                warn!("⚠️  Failed to initialize enhanced crypto: {}", e);
                None
            }
        }
    } else {
        info!("ℹ️  Using standard crypto backend (enhanced-crypto feature not enabled)");
        None
    };

    // Initialize database/ledger
    let ledger: Arc<LedgerStore> = Arc::new(LedgerStore::new(&config.database_path).await?);
    info!("💾 Ledger store initialized");
    
    // Initialize authentication manager
    let auth_manager: Arc<AuthManager> = Arc::new(AuthManager::new(config.clone()).await?);
    info!("🔐 Authentication manager initialized");
    
    // Initialize wallet manager with enhanced crypto support
    let wallet_manager: Arc<WalletManager> = Arc::new(
        WalletManager::new(
            config.clone(),
            ledger.clone(),
            auth_manager.clone(),
            enhanced_crypto.clone(),
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
    
    // Start ZQUIC server (NEW - Primary QUIC transport)
    let zquic_enabled = ZQuicTransport::is_enabled() && config.quic.enabled;
    let zquic_handle = if zquic_enabled {
        info!("⚡ Starting ZQUIC server (primary transport)");
        Some(tokio::spawn(async move {
            if let Err(e) = crate::zquic::start_zquic_server(
                config.clone(),
                wallet_manager.clone(),
                ledger.clone(),
                auth_manager.clone(),
            ).await {
                error!("ZQUIC server error: {}", e);
            }
        }))
    } else {
        info!("📡 ZQUIC server disabled (enable with --features zquic)");
        None
    };

    // Start QUIC server (GQUIC - Legacy)
    let quic_enabled = config.quic.enabled && !zquic_enabled; // Only if ZQUIC is not available
    let quic_handle = if quic_enabled {
        info!("⚡ Starting GQUIC server (fallback transport)");
        let quic_server = QuicServer::new(
            config.clone(),
            wallet_manager.clone(),
            ledger.clone(),
            auth_manager.clone(),
        );
        
        Some(tokio::spawn(async move {
            if let Err(e) = quic_server.serve().await {
                warn!("GQUIC server error: {}", e);
            }
        }))
    } else if !zquic_enabled {
        info!("📡 QUIC transport disabled in configuration");
        None
    } else {
        None
    };

    // Start REST API server (with ZQUIC integration)
    let api_server = ApiServer::new(
        config.clone(),
        wallet_manager.clone(),
        ledger.clone(),
        auth_manager.clone(),
        enhanced_crypto.clone(),
        zquic_transport.clone(), // NEW: Pass ZQUIC transport to API
    );
    
    let api_handle = tokio::spawn(async move {
        if let Err(e) = api_server.serve().await {
            warn!("API server error: {}", e);
        }
    });
    
    info!("🚀 walletd started successfully");
    info!("📡 gRPC server listening on: {}", config.grpc_bind_address);
    info!("🌐 REST API server listening on: {}", config.api_bind_address);
    if zquic_enabled {
        info!("⚡ ZQUIC server (primary) listening on: {}", config.quic.bind_address);
        info!("🔌 ZQUIC ALPN protocols: {:?}", config.quic.alpn_protocols);
    } else if quic_enabled {
        info!("⚡ GQUIC server (fallback) listening on: {}", config.quic.bind_address);
        info!("🔌 GQUIC ALPN protocols: {:?}", config.quic.alpn_protocols);
    }
    
    // Show feature status
    info!("🔧 Transport features enabled:");
    info!("   • ZQUIC transport: {}", ZQuicTransport::is_enabled());
    info!("   • GQUIC transport: {}", crate::quic::is_quic_enabled());
    info!("   • Enhanced crypto: {}", crate::quic::is_enhanced_crypto_enabled());
    info!("   • Zig FFI: {}", config.crypto.enable_zig_ffi);
    if let Some(ref crypto) = enhanced_crypto {
        info!("   • Supported algorithms: {:?}", crypto.supported_algorithms());
    }
    
    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("🛑 Shutdown signal received, stopping walletd...");
    
    // Graceful shutdown
    grpc_handle.abort();
    api_handle.abort();
    if let Some(zquic_handle) = zquic_handle {
        zquic_handle.abort();
    }
    if let Some(quic_handle) = quic_handle {
        quic_handle.abort();
    }
    
    info!("👋 walletd stopped");
    Ok(())
}
