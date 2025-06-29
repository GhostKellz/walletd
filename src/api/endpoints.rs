use std::sync::Arc;
use axum::{
    extract::{State, Path},
    response::Json,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use crate::api::ApiState;
use crate::wallet::{CreateWalletRequest, Wallet};

#[derive(Deserialize)]
pub struct CreateWalletRequestApi {
    pub name: String,
    pub network: Option<String>,
    pub account_type: Option<String>,
    pub passphrase: Option<String>,
    pub use_zquic: Option<bool>, // NEW: Whether to use ZQUIC for operations
}

#[derive(Serialize)]
pub struct CreateWalletResponse {
    pub wallet: Wallet,
    pub zquic_enabled: bool,
}

/// Create a new wallet with optional ZQUIC support
pub async fn create_wallet(
    State(state): State<ApiState>,
    Json(request): Json<CreateWalletRequestApi>,
) -> Result<Json<CreateWalletResponse>, StatusCode> {
    info!("📝 Creating wallet: {}", request.name);
    
    let wallet_request = CreateWalletRequest {
        name: request.name,
        network: request.network,
        account_type: request.account_type,
        passphrase: request.passphrase,
        // Add ZQUIC-specific parameters here if needed
    };
    
    match state.wallet_manager.create_wallet(wallet_request).await {
        Ok(wallet) => {
            let zquic_enabled = state.zquic_transport.is_some() && 
                               request.use_zquic.unwrap_or(true);
            
            if zquic_enabled {
                info!("✅ Wallet created with ZQUIC support enabled");
                
                // Initialize ZQUIC connection for this wallet if requested
                if let Some(ref zquic) = state.zquic_transport {
                    // TODO: Register wallet with ZQUIC transport for real-time updates
                    info!("🔗 Registering wallet {} with ZQUIC transport", wallet.id);
                }
            }
            
            Ok(Json(CreateWalletResponse {
                wallet,
                zquic_enabled,
            }))
        }
        Err(e) => {
            error!("❌ Failed to create wallet: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get wallet information
pub async fn get_wallet(
    State(state): State<ApiState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<Wallet>, StatusCode> {
    info!("🔍 Getting wallet: {}", wallet_id);
    
    match state.wallet_manager.get_wallet(&wallet_id).await {
        Ok(Some(wallet)) => Ok(Json(wallet)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("❌ Failed to get wallet: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Serialize)]
pub struct ZQuicStatusResponse {
    pub enabled: bool,
    pub connected_peers: usize,
    pub active_connections: usize,
    pub transport_type: String,
    pub crypto_backend: String,
}

/// Get ZQUIC transport status
pub async fn zquic_status(
    State(state): State<ApiState>,
) -> Json<ZQuicStatusResponse> {
    let enabled = state.zquic_transport.is_some();
    let transport_type = if crate::zquic::is_zquic_enabled() {
        "zig-zquic".to_string()
    } else if cfg!(feature = "quic") {
        "rust-gquic".to_string()
    } else {
        "none".to_string()
    };
    
    let crypto_backend = if crate::zquic::is_zcrypto_enabled() {
        "zig-zcrypto".to_string()
    } else if state.enhanced_crypto.is_some() {
        "rust-gcrypt".to_string()
    } else {
        "ed25519-dalek".to_string()
    };
    
    // TODO: Get actual connection stats from ZQUIC transport
    let (connected_peers, active_connections) = if let Some(ref _zquic) = state.zquic_transport {
        // zquic.get_connection_stats().await.unwrap_or((0, 0))
        (0, 0) // Placeholder
    } else {
        (0, 0)
    };
    
    Json(ZQuicStatusResponse {
        enabled,
        connected_peers,
        active_connections,
        transport_type,
        crypto_backend,
    })
}

#[derive(Serialize)]
pub struct ZQuicPeer {
    pub peer_id: String,
    pub address: String,
    pub connected_at: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct ZQuicPeersResponse {
    pub peers: Vec<ZQuicPeer>,
    pub total_count: usize,
}

/// Get ZQUIC connected peers
pub async fn zquic_peers(
    State(state): State<ApiState>,
) -> Json<ZQuicPeersResponse> {
    let peers = if let Some(ref _zquic) = state.zquic_transport {
        // TODO: Get actual peer list from ZQUIC transport
        // zquic.get_connected_peers().await.unwrap_or_default()
        Vec::new() // Placeholder
    } else {
        Vec::new()
    };
    
    Json(ZQuicPeersResponse {
        total_count: peers.len(),
        peers,
    })
}
