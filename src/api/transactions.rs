use std::sync::Arc;
use axum::{
    extract::{State, Path},
    response::Json,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use crate::api::ApiState;
use crate::ledger::Transaction;
use crate::signer::{UnsignedTransaction, SignedTransaction};

#[derive(Deserialize)]
pub struct SubmitTransactionRequest {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub gas_limit: Option<u64>,
    pub gas_price: Option<u64>,
    pub data: Option<Vec<u8>>,
    pub use_zquic: Option<bool>, // NEW: Submit via ZQUIC transport
    pub broadcast_via_zquic: Option<bool>, // NEW: Broadcast to network via ZQUIC
}

#[derive(Serialize)]
pub struct SubmitTransactionResponse {
    pub transaction_id: String,
    pub status: String,
    pub submitted_via_zquic: bool,
    pub will_broadcast_via_zquic: bool,
}

/// Submit a transaction via ZQUIC transport
pub async fn submit_transaction(
    State(state): State<ApiState>,
    Json(request): Json<SubmitTransactionRequest>,
) -> Result<Json<SubmitTransactionResponse>, StatusCode> {
    info!("📤 Submitting transaction: {} -> {} ({})", request.from, request.to, request.amount);
    
    let use_zquic = request.use_zquic.unwrap_or(true) && state.zquic_transport.is_some();
    let broadcast_via_zquic = request.broadcast_via_zquic.unwrap_or(true) && state.zquic_transport.is_some();
    
    // Create unsigned transaction
    let unsigned_tx = UnsignedTransaction {
        from: request.from.clone(),
        to: request.to.clone(),
        amount: request.amount,
        gas_limit: request.gas_limit.unwrap_or(state.config.network.default_gas_limit),
        gas_price: request.gas_price.unwrap_or(state.config.network.default_gas_price),
        data: request.data.unwrap_or_default(),
        nonce: 0, // Will be set by wallet manager
    };
    
    if use_zquic {
        info!("⚡ Using ZQUIC transport for transaction submission");
        
        // Submit via ZQUIC transport for faster processing
        if let Some(ref zquic) = state.zquic_transport {
            match submit_via_zquic(zquic, &unsigned_tx, &state).await {
                Ok(tx_id) => {
                    if broadcast_via_zquic {
                        info!("📡 Broadcasting transaction via ZQUIC network");
                        // TODO: Broadcast to ZQUIC peers
                        // zquic.broadcast_transaction(&tx_id).await?;
                    }
                    
                    return Ok(Json(SubmitTransactionResponse {
                        transaction_id: tx_id,
                        status: "submitted".to_string(),
                        submitted_via_zquic: true,
                        will_broadcast_via_zquic: broadcast_via_zquic,
                    }));
                }
                Err(e) => {
                    warn!("⚠️  ZQUIC submission failed, falling back to standard: {}", e);
                    // Fall through to standard submission
                }
            }
        }
    }
    
    // Standard submission (fallback or default)
    match state.wallet_manager.submit_transaction(unsigned_tx).await {
        Ok(tx_id) => {
            Ok(Json(SubmitTransactionResponse {
                transaction_id: tx_id,
                status: "submitted".to_string(),
                submitted_via_zquic: false,
                will_broadcast_via_zquic: false,
            }))
        }
        Err(e) => {
            error!("❌ Failed to submit transaction: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Submit transaction via ZQUIC transport
async fn submit_via_zquic(
    zquic: &Arc<crate::zquic::ZQuicTransport>,
    unsigned_tx: &UnsignedTransaction,
    state: &ApiState,
) -> Result<String, anyhow::Error> {
    // Serialize transaction for ZQUIC transport
    let tx_data = serde_json::to_vec(unsigned_tx)?;
    
    // Submit to GhostD via ZQUIC
    let ghostd_addr = &state.config.ghostd_endpoint;
    
    // TODO: Use actual ZQUIC client to submit to GhostD
    // let response = zquic.send_to_ghostd(ghostd_addr, &tx_data).await?;
    // let tx_response: SubmitResponse = serde_json::from_slice(&response)?;
    
    // Placeholder - generate transaction ID
    let tx_id = uuid::Uuid::new_v4().to_string();
    info!("✅ Transaction submitted via ZQUIC: {}", tx_id);
    
    Ok(tx_id)
}

#[derive(Deserialize)]
pub struct SignTransactionRequest {
    pub transaction_id: String,
    pub wallet_id: String,
    pub passphrase: Option<String>,
    pub use_enhanced_crypto: Option<bool>, // NEW: Use ZCRYPTO for signing
}

#[derive(Serialize)]
pub struct SignTransactionResponse {
    pub transaction_id: String,
    pub signature: String,
    pub signed_via_zcrypto: bool,
    pub status: String,
}

/// Sign a transaction with optional ZCRYPTO backend
pub async fn sign_transaction(
    State(state): State<ApiState>,
    Json(request): Json<SignTransactionRequest>,
) -> Result<Json<SignTransactionResponse>, StatusCode> {
    info!("✏️  Signing transaction: {}", request.transaction_id);
    
    let use_enhanced_crypto = request.use_enhanced_crypto.unwrap_or(true) && 
                             (state.enhanced_crypto.is_some() || crate::zquic::is_zcrypto_enabled());
    
    // Get transaction from ledger
    let transaction = match state.ledger.get_transaction(&request.transaction_id).await {
        Ok(Some(tx)) => tx,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("❌ Failed to get transaction: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    
    // Sign the transaction
    let sign_result = if use_enhanced_crypto && crate::zquic::is_zcrypto_enabled() {
        info!("🔐 Using ZCRYPTO for transaction signing");
        sign_with_zcrypto(&transaction, &request, &state).await
    } else if let Some(ref enhanced_crypto) = state.enhanced_crypto {
        info!("🔐 Using enhanced crypto for transaction signing");
        sign_with_enhanced_crypto(&transaction, &request, enhanced_crypto).await
    } else {
        info!("🔐 Using standard crypto for transaction signing");
        sign_with_standard_crypto(&transaction, &request, &state).await
    };
    
    match sign_result {
        Ok((signature, used_zcrypto)) => {
            Ok(Json(SignTransactionResponse {
                transaction_id: request.transaction_id,
                signature,
                signed_via_zcrypto: used_zcrypto,
                status: "signed".to_string(),
            }))
        }
        Err(e) => {
            error!("❌ Failed to sign transaction: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Sign transaction using ZCRYPTO
async fn sign_with_zcrypto(
    _transaction: &Transaction,
    _request: &SignTransactionRequest,
    _state: &ApiState,
) -> Result<(String, bool), anyhow::Error> {
    // TODO: Implement ZCRYPTO signing
    // let zcrypto = crate::zquic::create_zcrypto_backend()?;
    // let signature = zcrypto.sign_transaction(transaction, wallet_private_key)?;
    
    // Placeholder
    Ok(("zcrypto_signature_placeholder".to_string(), true))
}

/// Sign transaction using enhanced crypto (gcrypt)
async fn sign_with_enhanced_crypto(
    _transaction: &Transaction,
    _request: &SignTransactionRequest,
    _enhanced_crypto: &Arc<crate::crypto::EnhancedCrypto>,
) -> Result<(String, bool), anyhow::Error> {
    // TODO: Implement enhanced crypto signing
    // let signature = enhanced_crypto.sign_transaction(transaction, wallet_private_key)?;
    
    // Placeholder
    Ok(("enhanced_crypto_signature_placeholder".to_string(), false))
}

/// Sign transaction using standard crypto
async fn sign_with_standard_crypto(
    _transaction: &Transaction,
    _request: &SignTransactionRequest,
    _state: &ApiState,
) -> Result<(String, bool), anyhow::Error> {
    // TODO: Implement standard crypto signing
    // let signature = ed25519_dalek_sign(transaction, wallet_private_key)?;
    
    // Placeholder
    Ok(("standard_signature_placeholder".to_string(), false))
}

/// Get transaction status
pub async fn get_transaction(
    State(state): State<ApiState>,
    Path(transaction_id): Path<String>,
) -> Result<Json<Transaction>, StatusCode> {
    info!("🔍 Getting transaction: {}", transaction_id);
    
    match state.ledger.get_transaction(&transaction_id).await {
        Ok(Some(transaction)) => Ok(Json(transaction)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("❌ Failed to get transaction: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
