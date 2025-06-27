use std::sync::Arc;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Config;
use crate::wallet::{WalletManager, CreateWalletRequest, SendTransactionRequest, WalletImportData};
use crate::ledger::{LedgerStore, TransactionStatus};
use crate::auth::{AuthManager};
use crate::error::WalletError;

#[derive(Clone)]
pub struct AppState {
    wallet_manager: Arc<WalletManager>,
    ledger: Arc<LedgerStore>,
    auth_manager: Arc<AuthManager>,
    config: Config,
}

pub struct ApiServer {
    state: AppState,
}

impl ApiServer {
    pub fn new(
        config: Config,
        wallet_manager: Arc<WalletManager>,
        ledger: Arc<LedgerStore>,
        auth_manager: Arc<AuthManager>,
    ) -> Self {
        let state = AppState {
            wallet_manager,
            ledger,
            auth_manager,
            config,
        };

        Self { state }
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        let app = self.create_router();
        let addr: std::net::SocketAddr = self.state.config.api_bind_address.parse()?;

        tracing::info!("🌐 REST API server starting on {}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }

    fn create_router(&self) -> Router {
        Router::new()
            // Wallet endpoints
            .route("/wallets", get(list_wallets).post(create_wallet))
            .route("/wallets/:id", get(get_wallet).delete(delete_wallet))
            .route("/wallets/:id/balances", get(get_wallet_balances))
            .route("/wallets/:id/transactions", get(get_wallet_transactions))
            .route("/wallets/import", post(import_wallet))
            
            // Transaction endpoints
            .route("/transactions", post(send_transaction))
            .route("/transactions/:id", get(get_transaction))
            .route("/transactions/:id/status", post(update_transaction_status))
            
            // Signing endpoints
            .route("/sign", post(sign_transaction))
            .route("/sign/verify", post(verify_signature))
            
            // Authentication endpoints
            .route("/auth/challenge", post(create_auth_challenge))
            .route("/auth/login", post(login))
            .route("/auth/logout", post(logout))
            .route("/auth/session", get(get_session))
            
            // Broadcasting (placeholder - would connect to ghostd)
            .route("/broadcast", post(broadcast_transaction))
            
            // Health check
            .route("/health", get(health_check))
            
            // Add state
            .with_state(self.state.clone())
    }
}

// Wallet handlers
async fn list_wallets(State(state): State<AppState>) -> Result<Json<ApiResponse<Vec<WalletResponse>>>, ApiError> {
    let wallets = state.wallet_manager.list_wallets().await?;
    let wallet_responses: Vec<WalletResponse> = wallets.into_iter().map(|w| WalletResponse {
        id: w.id,
        name: w.name,
        address: w.address,
        public_key: w.public_key,
        account_type: w.account_type,
        network: w.network,
        balance: w.balance,
        created_at: w.created_at,
    }).collect();

    Ok(Json(ApiResponse::success(wallet_responses)))
}

async fn create_wallet(
    State(state): State<AppState>,
    Json(request): Json<CreateWalletRequest>,
) -> Result<Json<ApiResponse<WalletResponse>>, ApiError> {
    let wallet = state.wallet_manager.create_wallet(request).await?;
    let response = WalletResponse {
        id: wallet.id,
        name: wallet.name,
        address: wallet.address,
        public_key: wallet.public_key,
        account_type: wallet.account_type,
        network: wallet.network,
        balance: wallet.balance,
        created_at: wallet.created_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn get_wallet(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<WalletResponse>>, ApiError> {
    let wallet = state.wallet_manager.get_wallet(&id).await?;
    let response = WalletResponse {
        id: wallet.id,
        name: wallet.name,
        address: wallet.address,
        public_key: wallet.public_key,
        account_type: wallet.account_type,
        network: wallet.network,
        balance: wallet.balance,
        created_at: wallet.created_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn delete_wallet(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    state.wallet_manager.delete_wallet(&id).await?;
    Ok(Json(ApiResponse::success(())))
}

async fn get_wallet_balances(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<BalanceResponse>>>, ApiError> {
    let balances = state.wallet_manager.get_wallet_balances(&id).await?;
    let responses: Vec<BalanceResponse> = balances.into_iter().map(|b| BalanceResponse {
        token_symbol: b.token_symbol,
        balance: b.balance,
        decimals: b.decimals,
        token_address: b.token_address,
    }).collect();

    Ok(Json(ApiResponse::success(responses)))
}

async fn get_wallet_transactions(
    Path(id): Path<String>,
    Query(params): Query<TransactionQueryParams>,
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<TransactionResponse>>>, ApiError> {
    let transactions = state.wallet_manager.get_transaction_history(&id, params.limit).await?;
    let responses: Vec<TransactionResponse> = transactions.into_iter().map(|t| TransactionResponse {
        id: t.id,
        wallet_id: t.wallet_id,
        tx_hash: t.tx_hash,
        from_address: t.from_address,
        to_address: t.to_address,
        amount: t.amount,
        token_address: t.token_address,
        token_symbol: t.token_symbol,
        status: format!("{:?}", t.status),
        block_number: t.block_number,
        created_at: t.created_at,
        updated_at: t.updated_at,
    }).collect();

    Ok(Json(ApiResponse::success(responses)))
}

async fn import_wallet(
    State(state): State<AppState>,
    Json(request): Json<ImportWalletRequest>,
) -> Result<Json<ApiResponse<WalletResponse>>, ApiError> {
    let import_data = match request.import_type.as_str() {
        "private_key" => WalletImportData::PrivateKey {
            private_key: request.private_key.ok_or(ApiError::BadRequest("private_key required".to_string()))?,
            account_type: request.account_type.unwrap_or_else(|| "ed25519".to_string()),
        },
        "mnemonic" => WalletImportData::Mnemonic {
            mnemonic: request.mnemonic.ok_or(ApiError::BadRequest("mnemonic required".to_string()))?,
            derivation_path: request.derivation_path,
            account_type: request.account_type.unwrap_or_else(|| "ed25519".to_string()),
        },
        "passphrase" => WalletImportData::Passphrase {
            passphrase: request.passphrase.ok_or(ApiError::BadRequest("passphrase required".to_string()))?,
        },
        _ => return Err(ApiError::BadRequest("Invalid import_type".to_string())),
    };

    let wallet = state.wallet_manager.import_wallet(request.name, import_data).await?;
    let response = WalletResponse {
        id: wallet.id,
        name: wallet.name,
        address: wallet.address,
        public_key: wallet.public_key,
        account_type: wallet.account_type,
        network: wallet.network,
        balance: wallet.balance,
        created_at: wallet.created_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

// Transaction handlers
async fn send_transaction(
    State(state): State<AppState>,
    Json(request): Json<SendTransactionRequest>,
) -> Result<Json<ApiResponse<SignedTransactionResponse>>, ApiError> {
    let signed_tx = state.wallet_manager.send_transaction(request).await?;
    let response = SignedTransactionResponse {
        transaction_id: signed_tx.unsigned_tx.id,
        transaction_hash: signed_tx.tx_hash,
        signed_data: signed_tx.signed_data,
        signature: signed_tx.signature,
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn get_transaction(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<TransactionResponse>>, ApiError> {
    let transaction = state.wallet_manager.get_transaction(&id).await?;
    let response = TransactionResponse {
        id: transaction.id,
        wallet_id: transaction.wallet_id,
        tx_hash: transaction.tx_hash,
        from_address: transaction.from_address,
        to_address: transaction.to_address,
        amount: transaction.amount,
        token_address: transaction.token_address,
        token_symbol: transaction.token_symbol,
        status: format!("{:?}", transaction.status),
        block_number: transaction.block_number,
        created_at: transaction.created_at,
        updated_at: transaction.updated_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn update_transaction_status(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(request): Json<UpdateTransactionStatusRequest>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let status = match request.status.as_str() {
        "pending" => TransactionStatus::Pending,
        "confirmed" => TransactionStatus::Confirmed,
        "failed" => TransactionStatus::Failed,
        "cancelled" => TransactionStatus::Cancelled,
        _ => return Err(ApiError::BadRequest("Invalid status".to_string())),
    };

    state.wallet_manager.update_transaction_status(&id, status, request.tx_hash.as_deref()).await?;
    Ok(Json(ApiResponse::success(())))
}

// Signing handlers
async fn sign_transaction(
    State(state): State<AppState>,
    Json(request): Json<SignTransactionRequest>,
) -> Result<Json<ApiResponse<SignTransactionResponse>>, ApiError> {
    // This would be similar to send_transaction but without broadcasting
    let signed_tx = state.wallet_manager.send_transaction(SendTransactionRequest {
        from_wallet_id: request.wallet_id,
        to_address: request.to_address,
        amount: request.amount,
        token_address: request.token_address,
        gas_limit: request.gas_limit,
        gas_price: request.gas_price,
        data: request.data,
        passphrase: request.passphrase,
    }).await?;

    let response = SignTransactionResponse {
        signed_data: signed_tx.signed_data,
        signature: signed_tx.signature,
        transaction_hash: signed_tx.tx_hash,
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn verify_signature(
    State(_state): State<AppState>,
    Json(request): Json<VerifySignatureRequest>,
) -> Result<Json<ApiResponse<VerifySignatureResponse>>, ApiError> {
    // Decode inputs
    let public_key = hex::decode(&request.public_key)
        .map_err(|_| ApiError::BadRequest("Invalid public key format".to_string()))?;
    let signature = hex::decode(&request.signature)
        .map_err(|_| ApiError::BadRequest("Invalid signature format".to_string()))?;
    let data = hex::decode(&request.data)
        .unwrap_or_else(|_| request.data.into_bytes());

    if public_key.len() != 32 || signature.len() != 64 {
        return Err(ApiError::BadRequest("Invalid key or signature length".to_string()));
    }

    let public_key_array: [u8; 32] = public_key.try_into().unwrap();
    let signature_array: [u8; 64] = signature.try_into().unwrap();

    let signer = crate::signer::TransactionSigner::new();
    let valid = signer.verify_signature(&data, &signature_array, &public_key_array)?;

    Ok(Json(ApiResponse::success(VerifySignatureResponse { valid })))
}

// Auth handlers
async fn create_auth_challenge(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<AuthChallengeResponse>>, ApiError> {
    let challenge = state.auth_manager.create_challenge().await?;
    let response = AuthChallengeResponse {
        challenge_id: challenge.challenge_id,
        challenge_data: hex::encode(challenge.challenge_data),
        expires_at: challenge.expires_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<ApiResponse<LoginResponse>>, ApiError> {
    // Generate identity from passphrase
    let identity = state.auth_manager.generate_identity(&request.passphrase).await?;
    
    // Decode signature
    let signature = hex::decode(&request.signature)
        .map_err(|_| ApiError::BadRequest("Invalid signature format".to_string()))?;
    
    if signature.len() != 64 {
        return Err(ApiError::BadRequest("Invalid signature length".to_string()));
    }
    
    let signature_array: [u8; 64] = signature.try_into().unwrap();
    
    // Verify challenge and create session
    let session = state.auth_manager.verify_challenge_and_login(
        request.challenge_id,
        &signature_array,
        &identity,
    ).await?;

    let response = LoginResponse {
        session_id: session.session_id,
        identity: IdentityResponse {
            public_key: hex::encode(identity.public_key),
            qid: hex::encode(identity.qid),
            domain: identity.domain,
        },
        expires_at: session.expires_at,
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn logout(
    State(state): State<AppState>,
    Json(request): Json<LogoutRequest>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    state.auth_manager.logout(request.session_id).await?;
    Ok(Json(ApiResponse::success(())))
}

async fn get_session(
    Query(params): Query<SessionQueryParams>,
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<SessionResponse>>, ApiError> {
    let session = state.auth_manager.validate_session(params.session_id).await?;
    let response = SessionResponse {
        session_id: session.session_id,
        identity: IdentityResponse {
            public_key: hex::encode(session.identity.public_key),
            qid: hex::encode(session.identity.qid),
            domain: session.identity.domain,
        },
        created_at: session.created_at,
        expires_at: session.expires_at,
        last_accessed: session.last_accessed,
    };

    Ok(Json(ApiResponse::success(response)))
}

// Broadcasting handler (placeholder)
async fn broadcast_transaction(
    State(_state): State<AppState>,
    Json(request): Json<BroadcastTransactionRequest>,
) -> Result<Json<ApiResponse<BroadcastTransactionResponse>>, ApiError> {
    // TODO: Implement actual broadcasting to ghostd
    // For now, return a mock response
    let response = BroadcastTransactionResponse {
        success: true,
        transaction_hash: request.signed_data[..64].to_string(), // Mock hash
        message: "Transaction broadcasted successfully (mock)".to_string(),
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn health_check() -> Json<ApiResponse<HealthResponse>> {
    Json(ApiResponse::success(HealthResponse {
        status: "healthy".to_string(),
        timestamp: chrono::Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

// Response types
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

#[derive(Serialize)]
struct WalletResponse {
    id: String,
    name: String,
    address: String,
    public_key: String,
    account_type: String,
    network: String,
    balance: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct BalanceResponse {
    token_symbol: String,
    balance: String,
    decimals: i32,
    token_address: Option<String>,
}

#[derive(Serialize)]
struct TransactionResponse {
    id: String,
    wallet_id: String,
    tx_hash: Option<String>,
    from_address: String,
    to_address: String,
    amount: String,
    token_address: Option<String>,
    token_symbol: Option<String>,
    status: String,
    block_number: Option<i64>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct SignedTransactionResponse {
    transaction_id: String,
    transaction_hash: String,
    signed_data: String,
    signature: String,
}

#[derive(Serialize)]
struct AuthChallengeResponse {
    challenge_id: Uuid,
    challenge_data: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct LoginResponse {
    session_id: Uuid,
    identity: IdentityResponse,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct IdentityResponse {
    public_key: String,
    qid: String,
    domain: Option<String>,
}

#[derive(Serialize)]
struct SessionResponse {
    session_id: Uuid,
    identity: IdentityResponse,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    last_accessed: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct SignTransactionResponse {
    signed_data: String,
    signature: String,
    transaction_hash: String,
}

#[derive(Serialize)]
struct VerifySignatureResponse {
    valid: bool,
}

#[derive(Serialize)]
struct BroadcastTransactionResponse {
    success: bool,
    transaction_hash: String,
    message: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    version: String,
}

// Request types
#[derive(Deserialize)]
struct ImportWalletRequest {
    name: String,
    import_type: String, // "private_key", "mnemonic", "passphrase"
    private_key: Option<String>,
    mnemonic: Option<String>,
    derivation_path: Option<String>,
    passphrase: Option<String>,
    account_type: Option<String>,
}

#[derive(Deserialize)]
struct UpdateTransactionStatusRequest {
    status: String,
    tx_hash: Option<String>,
}

#[derive(Deserialize)]
struct SignTransactionRequest {
    wallet_id: String,
    to_address: String,
    amount: String,
    token_address: Option<String>,
    gas_limit: Option<u64>,
    gas_price: Option<String>,
    data: Option<String>,
    passphrase: String,
}

#[derive(Deserialize)]
struct VerifySignatureRequest {
    public_key: String,
    data: String,
    signature: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    challenge_id: Uuid,
    passphrase: String,
    signature: String,
}

#[derive(Deserialize)]
struct LogoutRequest {
    session_id: Uuid,
}

#[derive(Deserialize)]
struct BroadcastTransactionRequest {
    signed_data: String,
}

// Query parameters
#[derive(Deserialize)]
struct TransactionQueryParams {
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct SessionQueryParams {
    session_id: Uuid,
}

// Error handling
#[derive(Debug)]
enum ApiError {
    WalletError(WalletError),
    BadRequest(String),
    InternalError(String),
}

impl From<WalletError> for ApiError {
    fn from(err: WalletError) -> Self {
        ApiError::WalletError(err)
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiError::WalletError(WalletError::NotFound(msg)) => (StatusCode::NOT_FOUND, msg),
            ApiError::WalletError(WalletError::AlreadyExists(msg)) => (StatusCode::CONFLICT, msg),
            ApiError::WalletError(WalletError::Auth(msg)) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::WalletError(WalletError::InvalidInput(msg)) => (StatusCode::BAD_REQUEST, msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::WalletError(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        };

        let body = Json(ApiResponse::<()>::error(message));
        (status, body).into_response()
    }
}
