use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{WalletError, Result};
use crate::ffi::{Identity, Algorithm, ZCrypto, ZSig, zcrypto};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub session_id: Uuid,
    pub identity: Identity,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub challenge_id: Uuid,
    pub challenge_data: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacAuthRequest {
    pub wallet_id: String,
    pub timestamp: i64,
    pub nonce: String,
    pub hmac_tag: String,
}

#[derive(Debug, Clone)]
pub struct HmacKey {
    pub id: String,
    pub wallet_id: String,
    pub key_hash: String,
    pub purpose: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub struct AuthManager {
    config: Config,
    zsig: Option<Arc<ZSig>>,
    sessions: Arc<RwLock<HashMap<Uuid, AuthSession>>>,
    challenges: Arc<RwLock<HashMap<Uuid, AuthChallenge>>>,
    hmac_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>, // In-memory HMAC key cache
}

impl AuthManager {
    pub async fn new(config: Config) -> Result<Self> {
        let zsig = ZSig::new().ok().map(Arc::new);
        
        Ok(Self {
            config,
            zsig,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            hmac_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Generate a new identity from passphrase
    pub async fn generate_identity(&self, passphrase: &str) -> Result<Identity> {
        self.generate_identity_with_algorithm(passphrase, Algorithm::Ed25519).await
    }
    
    /// Generate identity with specific algorithm
    pub async fn generate_identity_with_algorithm(&self, passphrase: &str, algorithm: Algorithm) -> Result<Identity> {
        if let Some(ref zsig) = self.zsig {
            // Use zsig for multi-algorithm support
            let salt = b"walletd-passphrase-salt";
            let key_material = zcrypto::derive_key_from_passphrase(passphrase, salt)?;
            let keypair = zsig.generate_keypair_from_seed(algorithm, &key_material)?;
            
            let qid = zcrypto::generate_qid(&keypair.keypair.public_key);
            Ok(Identity {
                public_key: keypair.keypair.public_key,
                qid,
                domain: None,
            })
        } else {
            // Fallback to native implementation for Ed25519
            if algorithm != Algorithm::Ed25519 {
                return Err(WalletError::Crypto(format!("Algorithm {:?} not supported without zsig", algorithm)));
            }
            self.generate_identity_native(passphrase).await
        }
    }

    /// Native Rust implementation as fallback
    async fn generate_identity_native(&self, passphrase: &str) -> Result<Identity> {
        let salt = b"walletd-passphrase-salt"; // Consistent salt across implementations
        let key_material = zcrypto::derive_key_from_passphrase(passphrase, salt)?;
        
        // Generate Ed25519 keypair from derived key material
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_material);
        let verifying_key = signing_key.verifying_key();
        
        let public_key_bytes = verifying_key.to_bytes();
        let qid = zcrypto::generate_qid(&public_key_bytes);
        
        Ok(Identity {
            public_key: public_key_bytes,
            qid,
            domain: None, // Domain resolution would be handled separately
        })
    }

    /// Create an authentication challenge
    pub async fn create_challenge(&self) -> Result<AuthChallenge> {
        let challenge_id = Uuid::new_v4();
        let challenge_data = {
            let mut data = Vec::with_capacity(32);
            data.extend_from_slice(challenge_id.as_bytes());
            data.extend_from_slice(&Utc::now().timestamp().to_be_bytes());
            data
        };

        let challenge = AuthChallenge {
            challenge_id,
            challenge_data: challenge_data.clone(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5), // 5 minute expiry
        };

        self.challenges.write().await.insert(challenge_id, challenge.clone());
        
        // Clean up expired challenges
        self.cleanup_expired_challenges().await;
        
        Ok(challenge)
    }

    /// Verify challenge response and create session
    pub async fn verify_challenge_and_login(
        &self,
        challenge_id: Uuid,
        signature: &[u8; 64],
        identity: &Identity,
    ) -> Result<AuthSession> {
        // Get and remove challenge
        let challenge = {
            let mut challenges = self.challenges.write().await;
            challenges.remove(&challenge_id)
                .ok_or_else(|| WalletError::Auth("Challenge not found or expired".to_string()))?
        };

        // Check if challenge is expired
        if Utc::now() > challenge.expires_at {
            return Err(WalletError::Auth("Challenge expired".to_string()));
        }

        // Verify signature - always use native verification for now
        let signature_valid = zcrypto::verify_ed25519(&identity.public_key, &challenge.challenge_data, signature)?;

        if !signature_valid {
            return Err(WalletError::Auth("Invalid signature".to_string()));
        }

        // Create session
        let session_id = Uuid::new_v4();
        let session = AuthSession {
            session_id,
            identity: identity.clone(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(self.config.security.session_timeout_seconds as i64),
            last_accessed: Utc::now(),
        };

        // Check session limits
        let sessions_count = self.sessions.read().await.len();
        if sessions_count >= self.config.security.max_concurrent_sessions {
            return Err(WalletError::Auth("Maximum concurrent sessions reached".to_string()));
        }

        self.sessions.write().await.insert(session_id, session.clone());
        
        // Clean up expired sessions
        self.cleanup_expired_sessions().await;
        
        Ok(session)
    }

    /// Validate session and update last accessed time
    pub async fn validate_session(&self, session_id: Uuid) -> Result<AuthSession> {
        if !self.config.security.require_auth {
            // If auth is disabled, create a dummy session
            return Ok(AuthSession {
                session_id,
                identity: Identity {
                    public_key: [0; 32],
                    qid: [0; 16],
                    domain: Some("localhost".to_string()),
                },
                created_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(24),
                last_accessed: Utc::now(),
            });
        }

        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(&session_id)
            .ok_or_else(|| WalletError::Auth("Session not found".to_string()))?;

        // Check if session is expired
        if Utc::now() > session.expires_at {
            sessions.remove(&session_id);
            return Err(WalletError::Auth("Session expired".to_string()));
        }

        // Update last accessed
        session.last_accessed = Utc::now();
        Ok(session.clone())
    }

    /// Sign data using identity
    pub async fn sign_data(&self, identity: &Identity, data: &[u8]) -> Result<[u8; 64]> {
        // This is a limitation - we don't store private keys, so signing
        // would require the user to provide the passphrase again
        Err(WalletError::Auth("Cannot sign without passphrase - use sign_data_with_passphrase".to_string()))
    }
    
    /// Sign data with passphrase
    pub async fn sign_data_with_passphrase(&self, passphrase: &str, data: &[u8], algorithm: Algorithm) -> Result<[u8; 64]> {
        if let Some(ref zsig) = self.zsig {
            let salt = b"walletd-passphrase-salt";
            let key_material = zcrypto::derive_key_from_passphrase(passphrase, salt)?;
            let keypair = zsig.generate_keypair_from_seed(algorithm, &key_material)?;
            let auth_sig = zsig.sign(&keypair, data)?;
            Ok(auth_sig)
        } else if algorithm == Algorithm::Ed25519 {
            // Fallback for Ed25519
            let salt = b"walletd-passphrase-salt";
            let key_material = zcrypto::derive_key_from_passphrase(passphrase, salt)?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_material);
            zcrypto::sign_ed25519(&signing_key, data)
        } else {
            Err(WalletError::Crypto(format!("Algorithm {:?} not supported without zsig", algorithm)))
        }
    }
    
    // HMAC authentication methods
    
    /// Generate HMAC key for wallet
    pub async fn generate_hmac_key(&self, wallet_id: &str, purpose: &str) -> Result<String> {
        let key = {
            use rand::RngCore;
            let mut key = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            key
        };
        
        let key_id = Uuid::new_v4().to_string();
        let key_hash = self.hash_hmac_key(&key);
        
        // Store in cache
        self.hmac_keys.write().await.insert(key_id.clone(), key.clone());
        
        // Return key info (in practice, would also save to database)
        Ok(hex::encode(key))
    }
    
    /// Create HMAC authentication tag
    pub async fn create_hmac_auth(&self, wallet_id: &str, data: &[u8], hmac_key: &[u8]) -> Result<[u8; 32]> {
        if self.zsig.is_some() {
            // Use zcrypto HMAC if available
            let mut mac = [0u8; 32];
            // This would call zcrypto_hmac_sha256 through FFI
            // For now, use native implementation
            self.hmac_sha256_native(hmac_key, data)
        } else {
            self.hmac_sha256_native(hmac_key, data)
        }
    }
    
    /// Verify HMAC authentication
    pub async fn verify_hmac_auth(&self, wallet_id: &str, data: &[u8], hmac_key: &[u8], mac: &[u8; 32]) -> Result<bool> {
        let computed_mac = self.create_hmac_auth(wallet_id, data, hmac_key).await?;
        
        // Constant-time comparison
        use subtle::ConstantTimeEq;
        Ok(computed_mac.ct_eq(mac).into())
    }
    
    /// Native HMAC-SHA256 implementation
    fn hmac_sha256_native(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|_| WalletError::Crypto("Invalid HMAC key".to_string()))?;
        mac.update(data);
        
        let result = mac.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes());
        Ok(output)
    }
    
    /// Hash HMAC key for storage
    fn hash_hmac_key(&self, key: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"walletd-hmac-key:");
        hasher.update(key);
        hex::encode(hasher.finalize())
    }

    /// Logout and remove session
    pub async fn logout(&self, session_id: Uuid) -> Result<()> {
        self.sessions.write().await.remove(&session_id);
        Ok(())
    }

    /// List active sessions (admin function)
    pub async fn list_sessions(&self) -> Result<Vec<AuthSession>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.values().cloned().collect())
    }

    /// Clean up expired sessions
    async fn cleanup_expired_sessions(&self) {
        let now = Utc::now();
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| now <= session.expires_at);
    }

    /// Clean up expired challenges
    async fn cleanup_expired_challenges(&self) {
        let now = Utc::now();
        let mut challenges = self.challenges.write().await;
        challenges.retain(|_, challenge| now <= challenge.expires_at);
    }

    /// Get identity info (public data only)
    pub fn get_identity_info(&self, identity: &Identity) -> IdentityInfo {
        IdentityInfo {
            public_key: hex::encode(identity.public_key),
            qid: format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                identity.qid[0], identity.qid[1], identity.qid[2], identity.qid[3],
                identity.qid[4], identity.qid[5], identity.qid[6], identity.qid[7],
                identity.qid[8], identity.qid[9], identity.qid[10], identity.qid[11],
                identity.qid[12], identity.qid[13], identity.qid[14], identity.qid[15]
            ),
            domain: identity.domain.clone(),
        }
    }
    
    /// Create authenticated request
    pub async fn create_authenticated_request(&self, wallet_id: &str, hmac_key: &[u8]) -> Result<HmacAuthRequest> {
        let timestamp = Utc::now().timestamp();
        let nonce = Uuid::new_v4().to_string();
        
        // Create message to authenticate
        let message = format!("{}:{}:{}", wallet_id, timestamp, nonce);
        let mac = self.create_hmac_auth(wallet_id, message.as_bytes(), hmac_key).await?;
        
        Ok(HmacAuthRequest {
            wallet_id: wallet_id.to_string(),
            timestamp,
            nonce,
            hmac_tag: hex::encode(mac),
        })
    }
    
    /// Verify authenticated request
    pub async fn verify_authenticated_request(&self, request: &HmacAuthRequest, hmac_key: &[u8]) -> Result<bool> {
        // Check timestamp freshness (5 minute window)
        let now = Utc::now().timestamp();
        if (now - request.timestamp).abs() > 300 {
            return Ok(false);
        }
        
        // Recreate message and verify
        let message = format!("{}:{}:{}", request.wallet_id, request.timestamp, request.nonce);
        let expected_mac = hex::decode(&request.hmac_tag)
            .map_err(|_| WalletError::Auth("Invalid HMAC tag format".to_string()))?;
        
        if expected_mac.len() != 32 {
            return Ok(false);
        }
        
        let mut mac_array = [0u8; 32];
        mac_array.copy_from_slice(&expected_mac);
        
        self.verify_hmac_auth(&request.wallet_id, message.as_bytes(), hmac_key, &mac_array).await
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub public_key: String,
    pub qid: String,
    pub domain: Option<String>,
}
