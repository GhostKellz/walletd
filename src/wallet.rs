use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{WalletError, Result};
use crate::auth::{AuthManager};
use crate::ffi::{Identity};
use crate::ledger::{LedgerStore, WalletRecord, Balance, Transaction, TransactionStatus};
use crate::signer::{TransactionSigner, UnsignedTransaction, SignedTransaction};
use crate::crypto::EnhancedCrypto; // NEW: Enhanced crypto support
use crate::ffi::{ZWallet, AccountType, zcrypto};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub id: String,
    pub name: String,
    pub address: String,
    pub public_key: String,
    pub account_type: String,
    pub network: String,
    pub balance: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalance {
    pub token_symbol: String,
    pub balance: String,
    pub decimals: i32,
    pub token_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWalletRequest {
    pub name: String,
    pub account_type: Option<String>,
    pub passphrase: Option<String>,
    pub network: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendTransactionRequest {
    pub from_wallet_id: String,
    pub to_address: String,
    pub amount: String,
    pub token_address: Option<String>,
    pub gas_limit: Option<u64>,
    pub gas_price: Option<String>,
    pub data: Option<String>,
    pub passphrase: String,
}

pub struct WalletManager {
    config: Config,
    ledger: Arc<LedgerStore>,
    auth_manager: Arc<AuthManager>,
    signer: TransactionSigner,
    zwallet: Option<Arc<ZWallet>>,
    enhanced_crypto: Option<Arc<EnhancedCrypto>>, // NEW: Enhanced crypto support
    nonce_cache: Arc<RwLock<HashMap<String, u64>>>,
}

impl WalletManager {
    pub async fn new(
        config: Config,
        ledger: Arc<LedgerStore>,
        auth_manager: Arc<AuthManager>,
        enhanced_crypto: Option<Arc<EnhancedCrypto>>, // NEW: Enhanced crypto support
    ) -> Result<Self> {
        let signer = TransactionSigner::new();
        
        // Try to initialize ZWallet (Zig FFI)
        let zwallet = match ZWallet::new() {
            Ok(zw) => Some(Arc::new(zw)),
            Err(e) => {
                tracing::warn!("Failed to initialize ZWallet: {}. Using native implementation.", e);
                None
            }
        };

        Ok(Self {
            config,
            ledger,
            auth_manager,
            signer,
            zwallet,
            enhanced_crypto, // NEW: Store enhanced crypto instance
            nonce_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a new wallet
    pub async fn create_wallet(&self, request: CreateWalletRequest) -> Result<Wallet> {
        let wallet_id = Uuid::new_v4().to_string();
        let network = request.network.unwrap_or_else(|| self.config.network.network_name.clone());
        let account_type = request.account_type.unwrap_or_else(|| "ed25519".to_string());

        // Generate account based on method
        let (address, public_key) = if let Some(passphrase) = &request.passphrase {
            // Use passphrase-based key derivation
            let identity = self.auth_manager.generate_identity(passphrase).await?;
            let address = hex::encode(identity.public_key);
            let public_key = hex::encode(identity.public_key);
            (address, public_key)
        } else if let Some(ref zwallet) = self.zwallet {
            // Use ZWallet for random key generation
            let seed = {
                use rand::RngCore;
                let mut seed = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut seed);
                seed
            };
            
            let account_type_enum = match account_type.as_str() {
                "secp256k1" => AccountType::Secp256k1,
                _ => AccountType::Ed25519,
            };
            
            let account = zwallet.create_account(&seed, account_type_enum)?;
            let address = hex::encode(account.address);
            let public_key = hex::encode(account.public_key);
            (address, public_key)
        } else {
            // Use native Rust crypto
            let (secret_key, public_key_obj) = zcrypto::generate_keypair()?;
            let public_key = hex::encode(public_key_obj.to_bytes());
            let address = public_key.clone(); // For simplicity, use public key as address
            (address, public_key)
        };

        // Create wallet record
        let wallet_record = WalletRecord {
            id: wallet_id.clone(),
            name: request.name.clone(),
            address: address.clone(),
            public_key: public_key.clone(),
            account_type: account_type.clone(),
            network: network.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Save to ledger
        self.ledger.create_wallet(&wallet_record).await?;

        // Initialize balance tracking
        let initial_balance = Balance {
            wallet_id: wallet_id.clone(),
            token_address: None, // Native token
            token_symbol: "GCC".to_string(), // GhostChain native token
            balance: "0".to_string(),
            decimals: 18,
            last_updated: Utc::now(),
        };
        
        self.ledger.update_balance(&initial_balance).await?;

        Ok(Wallet {
            id: wallet_id,
            name: request.name,
            address,
            public_key,
            account_type,
            network,
            balance: Some("0".to_string()),
            created_at: Utc::now(),
        })
    }

    /// List all wallets
    pub async fn list_wallets(&self) -> Result<Vec<Wallet>> {
        let wallet_records = self.ledger.list_wallets().await?;
        let mut wallets = Vec::new();

        for record in wallet_records {
            // Get balance for native token
            let balance = self.ledger.get_balance(&record.id, None).await?
                .map(|b| b.balance)
                .unwrap_or_else(|| "0".to_string());

            wallets.push(Wallet {
                id: record.id,
                name: record.name,
                address: record.address,
                public_key: record.public_key,
                account_type: record.account_type,
                network: record.network,
                balance: Some(balance),
                created_at: record.created_at,
            });
        }

        Ok(wallets)
    }

    /// Get wallet by ID
    pub async fn get_wallet(&self, wallet_id: &str) -> Result<Wallet> {
        let record = self.ledger.get_wallet(wallet_id).await?;
        let balance = self.ledger.get_balance(&record.id, None).await?
            .map(|b| b.balance)
            .unwrap_or_else(|| "0".to_string());

        Ok(Wallet {
            id: record.id,
            name: record.name,
            address: record.address,
            public_key: record.public_key,
            account_type: record.account_type,
            network: record.network,
            balance: Some(balance),
            created_at: record.created_at,
        })
    }

    /// Get wallet balances
    pub async fn get_wallet_balances(&self, wallet_id: &str) -> Result<Vec<WalletBalance>> {
        let balances = self.ledger.get_balances(wallet_id).await?;
        let wallet_balances = balances.into_iter().map(|b| WalletBalance {
            token_symbol: b.token_symbol,
            balance: b.balance,
            decimals: b.decimals as i32,
            token_address: b.token_address,
        }).collect();

        Ok(wallet_balances)
    }

    /// Update wallet balance (called by external balance tracking service)
    pub async fn update_wallet_balance(
        &self,
        wallet_id: &str,
        token_address: Option<&str>,
        balance: &str,
        token_symbol: &str,
        decimals: i32,
    ) -> Result<()> {
        let balance_record = Balance {
            wallet_id: wallet_id.to_string(),
            token_address: token_address.map(|s| s.to_string()),
            token_symbol: token_symbol.to_string(),
            balance: balance.to_string(),
            decimals: decimals as i64,
            last_updated: Utc::now(),
        };

        self.ledger.update_balance(&balance_record).await?;
        Ok(())
    }

    /// Create and sign a transaction
    pub async fn send_transaction(&self, request: SendTransactionRequest) -> Result<SignedTransaction> {
        // Get wallet
        let wallet = self.get_wallet(&request.from_wallet_id).await?;
        
        // Generate identity from passphrase for signing
        let identity = self.auth_manager.generate_identity(&request.passphrase).await?;
        
        // Verify that the identity matches the wallet
        if hex::encode(identity.public_key) != wallet.public_key {
            return Err(WalletError::Auth("Passphrase doesn't match wallet".to_string()));
        }

        // Get next nonce
        let nonce = self.get_next_nonce(&wallet.id).await?;

        // Create unsigned transaction
        let unsigned_tx = self.signer.create_ghostchain_transaction(
            &wallet.address,
            &request.to_address,
            &request.amount,
            request.token_address.as_deref(),
            nonce,
            request.gas_limit,
            request.gas_price.as_deref(),
            request.data.as_deref(),
        )?;

        // Sign transaction with passphrase
        let signed_tx = self.sign_transaction_with_passphrase(
            &unsigned_tx,
            &request.passphrase,
            &identity,
        ).await?;

        // Save transaction to ledger
        let tx_record = self.signer.create_transaction_record(&signed_tx, &wallet.id);
        self.ledger.save_transaction(&tx_record).await?;

        // Update nonce cache
        self.update_nonce_cache(&wallet.id, nonce + 1).await;

        Ok(signed_tx)
    }

    /// Sign transaction with passphrase
    async fn sign_transaction_with_passphrase(
        &self,
        unsigned_tx: &UnsignedTransaction,
        passphrase: &str,
        identity: &Identity,
    ) -> Result<SignedTransaction> {
        // Serialize transaction for signing
        let tx_data = serde_json::to_vec(unsigned_tx)?;
        
        // Sign with passphrase
        let signature = self.signer.sign_with_passphrase(&tx_data, passphrase, identity).await?;
        
        // Create signed transaction
        let signed_data = {
            let mut data = tx_data;
            data.extend_from_slice(&signature);
            data
        };
        
        let tx_hash = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&signed_data);
            hex::encode(hasher.finalize())
        };

        Ok(SignedTransaction {
            unsigned_tx: unsigned_tx.clone(),
            signature: hex::encode(signature),
            signed_data: hex::encode(signed_data),
            tx_hash,
        })
    }

    /// Get transaction history
    pub async fn get_transaction_history(&self, wallet_id: &str, limit: Option<i64>) -> Result<Vec<Transaction>> {
        self.ledger.get_transactions_by_wallet(wallet_id, limit).await
    }

    /// Get transaction by ID
    pub async fn get_transaction(&self, tx_id: &str) -> Result<Transaction> {
        self.ledger.get_transaction(tx_id).await
    }

    /// Update transaction status (called by blockchain monitor)
    pub async fn update_transaction_status(
        &self,
        tx_id: &str,
        status: TransactionStatus,
        tx_hash: Option<&str>,
    ) -> Result<()> {
        self.ledger.update_transaction_status(tx_id, status, tx_hash).await
    }

    /// Delete wallet
    pub async fn delete_wallet(&self, wallet_id: &str) -> Result<()> {
        self.ledger.delete_wallet(wallet_id).await
    }

    /// Get next nonce for wallet
    async fn get_next_nonce(&self, wallet_id: &str) -> Result<u64> {
        let nonce_cache = self.nonce_cache.read().await;
        if let Some(&cached_nonce) = nonce_cache.get(wallet_id) {
            return Ok(cached_nonce);
        }
        drop(nonce_cache);

        // Get nonce from ledger (highest nonce + 1)
        let transactions = self.ledger.get_transactions_by_wallet(wallet_id, Some(1)).await?;
        let nonce = if let Some(tx) = transactions.first() {
            tx.nonce.map(|n| n as u64 + 1).unwrap_or(0)
        } else {
            0
        };

        // Cache the nonce
        self.update_nonce_cache(wallet_id, nonce).await;
        Ok(nonce)
    }

    /// Update nonce cache
    async fn update_nonce_cache(&self, wallet_id: &str, nonce: u64) {
        let mut nonce_cache = self.nonce_cache.write().await;
        nonce_cache.insert(wallet_id.to_string(), nonce);
    }

    /// Import wallet from private key or mnemonic
    pub async fn import_wallet(
        &self,
        name: String,
        import_data: WalletImportData,
    ) -> Result<Wallet> {
        match import_data {
            WalletImportData::PrivateKey { private_key, account_type } => {
                self.import_from_private_key(name, private_key, account_type).await
            }
            WalletImportData::Mnemonic { mnemonic, derivation_path, account_type } => {
                self.import_from_mnemonic(name, mnemonic, derivation_path, account_type).await
            }
            WalletImportData::Passphrase { passphrase } => {
                self.import_from_passphrase(name, passphrase).await
            }
        }
    }

    async fn import_from_private_key(
        &self,
        name: String,
        private_key: String,
        account_type: String,
    ) -> Result<Wallet> {
        // Decode private key
        let private_key_bytes = hex::decode(private_key)
            .map_err(|_| WalletError::InvalidInput("Invalid private key format".to_string()))?;

        if private_key_bytes.len() != 32 {
            return Err(WalletError::InvalidInput("Private key must be 32 bytes".to_string()));
        }

        // Generate public key
        let private_key_array: [u8; 32] = private_key_bytes.try_into().unwrap();
        use ed25519_dalek::{SigningKey, VerifyingKey};
        let signing_key = SigningKey::from_bytes(&private_key_array);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        
        let address = hex::encode(verifying_key.to_bytes());
        let public_key_hex = hex::encode(verifying_key.to_bytes());

        // Create wallet
        let wallet_id = Uuid::new_v4().to_string();
        let wallet_record = WalletRecord {
            id: wallet_id.clone(),
            name: name.clone(),
            address: address.clone(),
            public_key: public_key_hex.clone(),
            account_type,
            network: self.config.network.network_name.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        self.ledger.create_wallet(&wallet_record).await?;

        Ok(Wallet {
            id: wallet_id,
            name,
            address,
            public_key: public_key_hex,
            account_type: wallet_record.account_type,
            network: wallet_record.network,
            balance: Some("0".to_string()),
            created_at: Utc::now(),
        })
    }

    async fn import_from_mnemonic(
        &self,
        _name: String,
        _mnemonic: String,
        _derivation_path: Option<String>,
        _account_type: String,
    ) -> Result<Wallet> {
        // TODO: Implement BIP39 mnemonic import
        Err(WalletError::InvalidInput("Mnemonic import not yet implemented".to_string()))
    }

    async fn import_from_passphrase(&self, name: String, passphrase: String) -> Result<Wallet> {
        // Use the same method as create_wallet with passphrase
        let request = CreateWalletRequest {
            name,
            account_type: Some("ed25519".to_string()),
            passphrase: Some(passphrase),
            network: Some(self.config.network.network_name.clone()),
        };

        self.create_wallet(request).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalletImportData {
    PrivateKey {
        private_key: String,
        account_type: String,
    },
    Mnemonic {
        mnemonic: String,
        derivation_path: Option<String>,
        account_type: String,
    },
    Passphrase {
        passphrase: String,
    },
}
