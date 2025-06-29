use std::sync::Arc;
use axum::{
    extract::{State, Path, ws::{WebSocket, Message}},
    response::Json,
    http::StatusCode,
    extract::WebSocketUpgrade,
    response::Response,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use tokio::time::{interval, Duration};

use crate::api::ApiState;
use crate::ledger::Balance;

#[derive(Serialize)]
pub struct BalanceResponse {
    pub wallet_id: String,
    pub balance: Balance,
    pub updated_via_zquic: bool,
    pub last_updated: String,
}

/// Get current balance for a wallet
pub async fn get_balance(
    State(state): State<ApiState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<BalanceResponse>, StatusCode> {
    info!("💰 Getting balance for wallet: {}", wallet_id);
    
    // Check if wallet exists
    match state.wallet_manager.get_wallet(&wallet_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("❌ Failed to get wallet: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    
    // Get balance from ledger
    match state.ledger.get_balance(&wallet_id).await {
        Ok(balance) => {
            let updated_via_zquic = state.zquic_transport.is_some();
            
            Ok(Json(BalanceResponse {
                wallet_id,
                balance,
                updated_via_zquic,
                last_updated: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(e) => {
            error!("❌ Failed to get balance: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Stream real-time balance updates via WebSocket with ZQUIC backend
pub async fn stream_balance(
    ws: WebSocketUpgrade,
    State(state): State<ApiState>,
    Path(wallet_id): Path<String>,
) -> Response {
    info!("📡 Starting balance stream for wallet: {}", wallet_id);
    
    ws.on_upgrade(move |socket| stream_balance_updates(socket, state, wallet_id))
}

/// Handle WebSocket connection for real-time balance streaming
async fn stream_balance_updates(
    mut socket: WebSocket,
    state: ApiState,
    wallet_id: String,
) {
    info!("🔄 Balance stream connected for wallet: {}", wallet_id);
    
    // Check if wallet exists
    match state.wallet_manager.get_wallet(&wallet_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            let _ = socket.send(Message::Text(
                serde_json::json!({
                    "error": "wallet_not_found",
                    "message": "Wallet not found"
                }).to_string()
            )).await;
            return;
        }
        Err(e) => {
            error!("❌ Failed to get wallet: {}", e);
            let _ = socket.send(Message::Text(
                serde_json::json!({
                    "error": "internal_error",
                    "message": "Failed to get wallet"
                }).to_string()
            )).await;
            return;
        }
    }
    
    // Send initial balance
    if let Ok(balance) = state.ledger.get_balance(&wallet_id).await {
        let balance_update = BalanceUpdate {
            wallet_id: wallet_id.clone(),
            balance: balance.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            source: if state.zquic_transport.is_some() { "zquic" } else { "local" }.to_string(),
            event_type: "initial".to_string(),
        };
        
        if let Ok(msg) = serde_json::to_string(&balance_update) {
            if socket.send(Message::Text(msg)).await.is_err() {
                return;
            }
        }
    }
    
    // Set up real-time updates
    let use_zquic = state.zquic_transport.is_some();
    
    if use_zquic {
        info!("⚡ Using ZQUIC for real-time balance updates");
        stream_with_zquic(&mut socket, &state, &wallet_id).await;
    } else {
        info!("🔄 Using polling for balance updates");
        stream_with_polling(&mut socket, &state, &wallet_id).await;
    }
}

/// Stream balance updates using ZQUIC real-time notifications
async fn stream_with_zquic(
    socket: &mut WebSocket,
    state: &ApiState,
    wallet_id: &str,
) {
    // TODO: Set up ZQUIC real-time subscription
    // This would involve:
    // 1. Subscribing to balance change events via ZQUIC
    // 2. Receiving real-time notifications from GhostD
    // 3. Forwarding updates to WebSocket client
    
    if let Some(ref _zquic) = state.zquic_transport {
        // Placeholder implementation
        let mut interval = interval(Duration::from_secs(5)); // Reduced polling with ZQUIC
        
        loop {
            interval.tick().await;
            
            // TODO: Check for ZQUIC balance updates
            // let balance_update = zquic.get_balance_update(wallet_id).await;
            
            // For now, get balance from ledger
            if let Ok(balance) = state.ledger.get_balance(wallet_id).await {
                let balance_update = BalanceUpdate {
                    wallet_id: wallet_id.to_string(),
                    balance,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    source: "zquic".to_string(),
                    event_type: "update".to_string(),
                };
                
                if let Ok(msg) = serde_json::to_string(&balance_update) {
                    if socket.send(Message::Text(msg)).await.is_err() {
                        break;
                    }
                }
            }
            
            // Check if client disconnected
            if let Ok(Some(msg)) = socket.recv().await {
                match msg {
                    Message::Close(_) => break,
                    Message::Pong(_) => continue,
                    _ => {} // Ignore other messages
                }
            }
        }
    }
}

/// Stream balance updates using polling (fallback)
async fn stream_with_polling(
    socket: &mut WebSocket,
    state: &ApiState,
    wallet_id: &str,
) {
    let mut interval = interval(Duration::from_secs(10)); // Standard polling interval
    let mut last_balance: Option<Balance> = None;
    
    loop {
        interval.tick().await;
        
        // Get current balance
        if let Ok(balance) = state.ledger.get_balance(wallet_id).await {
            // Only send update if balance changed
            let balance_changed = match &last_balance {
                Some(last) => last != &balance,
                None => true,
            };
            
            if balance_changed {
                let balance_update = BalanceUpdate {
                    wallet_id: wallet_id.to_string(),
                    balance: balance.clone(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    source: "polling".to_string(),
                    event_type: "update".to_string(),
                };
                
                if let Ok(msg) = serde_json::to_string(&balance_update) {
                    if socket.send(Message::Text(msg)).await.is_err() {
                        break;
                    }
                }
                
                last_balance = Some(balance);
            }
        }
        
        // Check if client disconnected
        if let Ok(Some(msg)) = socket.recv().await {
            match msg {
                Message::Close(_) => break,
                Message::Pong(_) => continue,
                _ => {} // Ignore other messages
            }
        }
    }
}

#[derive(Serialize)]
struct BalanceUpdate {
    wallet_id: String,
    balance: Balance,
    timestamp: String,
    source: String, // "zquic", "polling", etc.
    event_type: String, // "initial", "update", "transaction"
}

#[derive(Deserialize)]
pub struct SubscribeBalanceRequest {
    pub wallet_ids: Vec<String>,
    pub enable_zquic: Option<bool>,
}

#[derive(Serialize)]
pub struct SubscribeBalanceResponse {
    pub subscribed_wallets: Vec<String>,
    pub using_zquic: bool,
    pub update_frequency: String,
}

/// Subscribe to balance updates for multiple wallets
pub async fn subscribe_balance_updates(
    State(state): State<ApiState>,
    Json(request): Json<SubscribeBalanceRequest>,
) -> Result<Json<SubscribeBalanceResponse>, StatusCode> {
    info!("📝 Subscribing to balance updates for {} wallets", request.wallet_ids.len());
    
    // Validate all wallet IDs exist
    let mut valid_wallets = Vec::new();
    for wallet_id in &request.wallet_ids {
        match state.wallet_manager.get_wallet(wallet_id).await {
            Ok(Some(_)) => valid_wallets.push(wallet_id.clone()),
            Ok(None) => warn!("⚠️  Wallet not found: {}", wallet_id),
            Err(e) => {
                error!("❌ Failed to validate wallet {}: {}", wallet_id, e);
            }
        }
    }
    
    let using_zquic = request.enable_zquic.unwrap_or(true) && state.zquic_transport.is_some();
    let update_frequency = if using_zquic {
        "real-time (ZQUIC)".to_string()
    } else {
        "10s polling".to_string()
    };
    
    // TODO: Set up actual subscription management
    // This would involve storing subscription preferences and managing
    // active WebSocket connections for each wallet
    
    Ok(Json(SubscribeBalanceResponse {
        subscribed_wallets: valid_wallets,
        using_zquic,
        update_frequency,
    }))
}
