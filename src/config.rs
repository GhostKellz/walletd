use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::error::{WalletError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub config_path: PathBuf,
    pub database_path: PathBuf,
    pub grpc_bind_address: String,
    pub api_bind_address: String,
    pub ghostd_endpoint: String,
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub features: FeatureConfig,
    pub crypto: CryptoConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub chain_id: u64,
    pub network_name: String,
    pub default_gas_limit: u64,
    pub default_gas_price: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub require_auth: bool,
    pub session_timeout_seconds: u64,
    pub max_concurrent_sessions: usize,
    pub enable_hardware_security: bool,
    pub enable_hmac_auth: bool,
    pub hmac_key_rotation_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureConfig {
    pub enable_evm: bool,
    pub enable_cli: bool,
    pub enable_json_rpc: bool,
    pub enable_metrics: bool,
    pub enable_multi_algorithm: bool,
    pub enable_batch_operations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub default_algorithm: String,
    pub supported_algorithms: Vec<String>,
    pub deterministic_salt: String,
    pub enable_zig_ffi: bool,
    pub key_derivation_iterations: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("walletd.toml"),
            database_path: PathBuf::from("walletd.db"),
            grpc_bind_address: "127.0.0.1:50051".to_string(),
            api_bind_address: "127.0.0.1:8080".to_string(),
            ghostd_endpoint: "http://127.0.0.1:50052".to_string(),
            network: NetworkConfig {
                chain_id: 1337,
                network_name: "ghostchain".to_string(),
                default_gas_limit: 21000,
                default_gas_price: 20_000_000_000, // 20 gwei
            },
            security: SecurityConfig {
                require_auth: true,
                session_timeout_seconds: 3600, // 1 hour
                max_concurrent_sessions: 100,
                enable_hardware_security: false,
                enable_hmac_auth: true,
                hmac_key_rotation_days: 30,
            },
            features: FeatureConfig {
                enable_evm: true,
                enable_cli: true,
                enable_json_rpc: true,
                enable_metrics: true,
                enable_multi_algorithm: true,
                enable_batch_operations: true,
            },
            crypto: CryptoConfig {
                default_algorithm: "ed25519".to_string(),
                supported_algorithms: vec!["ed25519".to_string(), "secp256k1".to_string(), "secp256r1".to_string()],
                deterministic_salt: "walletd-passphrase-salt".to_string(),
                enable_zig_ffi: cfg!(feature = "zig-ffi"),
                key_derivation_iterations: 100_000,
            },
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = std::env::var("WALLETD_CONFIG")
            .unwrap_or_else(|_| "walletd.toml".to_string());
        
        let config_path = PathBuf::from(config_path);
        
        if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)?;
            let mut config: Config = toml::from_str(&contents)
                .map_err(|e| WalletError::Config(format!("Failed to parse config: {}", e)))?;
            
            config.config_path = config_path;
            Ok(config)
        } else {
            let config = Config::default();
            // Create default config file
            let contents = toml::to_string_pretty(&config)
                .map_err(|e| WalletError::Config(format!("Failed to serialize config: {}", e)))?;
            
            std::fs::write(&config_path, contents)?;
            Ok(config)
        }
    }
}
