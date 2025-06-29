pub mod endpoints;
pub mod transactions;
pub mod balance;
pub mod multisig;

use std::sync::Arc;
use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
    extract::State,
    response::Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::Config;
use crate::wallet::WalletManager;
use crate::ledger::LedgerStore;
use crate::auth::AuthManager;
use crate::crypto::EnhancedCrypto;
use crate::zquic::ZQuicTransport;

#[derive(Clone)]
pub struct ApiState {
    pub config: Config,
    pub wallet_manager: Arc<WalletManager>,
    pub ledger: Arc<LedgerStore>,
    pub auth_manager: Arc<AuthManager>,
    pub enhanced_crypto: Option<Arc<EnhancedCrypto>>,
    pub zquic_transport: Option<Arc<ZQuicTransport>>,
}

pub struct ApiServer {
    state: ApiState,
}

impl ApiServer {
    pub fn new(
        config: Config,
        wallet_manager: Arc<WalletManager>,
        ledger: Arc<LedgerStore>,
        auth_manager: Arc<AuthManager>,
        enhanced_crypto: Option<Arc<EnhancedCrypto>>,
        zquic_transport: Option<Arc<ZQuicTransport>>,
    ) -> Self {
        let state = ApiState {
            config,
            wallet_manager,
            ledger,
            auth_manager,
            enhanced_crypto,
            zquic_transport,
        };

        Self { state }
    }

    pub async fn serve(self) -> Result<()> {
        let bind_addr = self.state.config.api_bind_address.parse()?;
        
        let app = Router::new()
            // Wallet operations
            .route("/api/v1/wallets", post(endpoints::create_wallet))
            .route("/api/v1/wallets/:id", get(endpoints::get_wallet))
            .route("/api/v1/wallets/:id/balance", get(balance::get_balance))
            .route("/api/v1/wallets/:id/balance/stream", get(balance::stream_balance))
            
            // Transaction operations  
            .route("/api/v1/transactions", post(transactions::submit_transaction))
            .route("/api/v1/transactions/:id", get(transactions::get_transaction))
            .route("/api/v1/transactions/sign", post(transactions::sign_transaction))
            
            // Multi-signature operations
            .route("/api/v1/multisig/create", post(multisig::create_multisig))
            .route("/api/v1/multisig/:id/sign", post(multisig::sign_multisig))
            .route("/api/v1/multisig/:id/broadcast", post(multisig::broadcast_multisig))
            
            // ZQUIC-specific endpoints
            .route("/api/v1/zquic/status", get(endpoints::zquic_status))
            .route("/api/v1/zquic/peers", get(endpoints::zquic_peers))
            
            // Health check
            .route("/health", get(health_check))
            .with_state(self.state);

        info!("🌐 API server starting on {}", bind_addr);
        
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        axum::serve(listener, app).await?;
        
        Ok(())
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    features: Vec<String>,
}

async fn health_check(State(state): State<ApiState>) -> Json<HealthResponse> {
    let mut features = Vec::new();
    
    if state.zquic_transport.is_some() {
        features.push("zquic".to_string());
    }
    if state.enhanced_crypto.is_some() {
        features.push("enhanced-crypto".to_string());
    }
    if crate::zquic::is_zquic_enabled() {
        features.push("zquic-enabled".to_string());
    }
    if crate::zquic::is_zcrypto_enabled() {
        features.push("zcrypto-enabled".to_string());
    }

    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        features,
    })
}
