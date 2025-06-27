use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Database migration error: {0}")]
    Migration(sqlx::migrate::MigrateError),
    
    #[error("Sled database error: {0}")]
    SledDatabase(#[from] sled::Error),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("Authentication failed: {0}")]
    Auth(String),
    
    #[error("Invalid wallet: {0}")]
    InvalidWallet(String),
    
    #[error("Transaction error: {0}")]
    Transaction(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("FFI error: {0}")]
    Ffi(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Already exists: {0}")]
    AlreadyExists(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<WalletError> for tonic::Status {
    fn from(err: WalletError) -> Self {
        match err {
            WalletError::NotFound(msg) => tonic::Status::not_found(msg),
            WalletError::AlreadyExists(msg) => tonic::Status::already_exists(msg),
            WalletError::InvalidInput(msg) => tonic::Status::invalid_argument(msg),
            WalletError::Auth(msg) => tonic::Status::unauthenticated(msg),
            _ => tonic::Status::internal(err.to_string()),
        }
    }
}

impl From<sqlx::migrate::MigrateError> for WalletError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        WalletError::Migration(err)
    }
}

pub type Result<T> = std::result::Result<T, WalletError>;
