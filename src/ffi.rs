use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use std::marker::PhantomData;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use crate::error::{WalletError, Result};

// Algorithm types matching zcrypto
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Algorithm {
    Ed25519 = 0,
    Secp256k1 = 1,
    Secp256r1 = 2,
}

// Error codes
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZCryptoError {
    Ok = 0,
    InvalidParam = -1,
    CryptoFailed = -2,
    Unsupported = -3,
    OutOfMemory = -4,
}

// FFI structures
#[repr(C)]
pub struct ZCryptoPublicKey {
    pub bytes: [u8; 32],
}

#[repr(C)]
pub struct ZCryptoPrivateKey {
    pub bytes: [u8; 64],
}

#[repr(C)]
pub struct ZCryptoSignature {
    pub bytes: [u8; 64],
}

#[repr(C)]
pub struct ZCryptoKeypair {
    pub private_key: ZCryptoPrivateKey,
    pub public_key: ZCryptoPublicKey,
    pub algorithm: Algorithm,
}

// zsig structures
#[repr(C)]
pub struct ZsigContext {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ZsigMultisigKeypair {
    pub keypair: ZCryptoKeypair,
    pub hmac_key: [u8; 32],
    pub has_hmac_key: bool,
}

#[repr(C)]
pub struct ZsigAuthenticatedSignature {
    pub signature: ZCryptoSignature,
    pub hmac_tag: [u8; 32],
    pub has_hmac: bool,
}

// zwallet structures
#[repr(C)]
pub struct ZWalletContext {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum ZWalletAccountType {
    Ed25519 = 0,
    Secp256k1 = 1,
}

// External functions - conditionally compiled
#[cfg(feature = "zig-ffi")]
extern "C" {
    // zcrypto functions
    fn zcrypto_generate_keypair(algorithm: Algorithm, out_keypair: *mut ZCryptoKeypair) -> ZCryptoError;
    fn zcrypto_generate_keypair_from_seed(algorithm: Algorithm, seed: *const u8, seed_len: usize, out_keypair: *mut ZCryptoKeypair) -> ZCryptoError;
    fn zcrypto_sign(keypair: *const ZCryptoKeypair, message: *const u8, message_len: usize, out_signature: *mut ZCryptoSignature) -> ZCryptoError;
    fn zcrypto_verify(algorithm: Algorithm, public_key: *const ZCryptoPublicKey, message: *const u8, message_len: usize, signature: *const ZCryptoSignature, out_valid: *mut bool) -> ZCryptoError;
    fn zcrypto_derive_key_from_passphrase(passphrase: *const c_char, salt: *const u8, salt_len: usize, out_key: *mut u8) -> ZCryptoError;
    fn zcrypto_secure_zero(ptr: *mut c_void, len: usize);
    
    // zsig functions
    fn zsig_context_new() -> *mut ZsigContext;
    fn zsig_context_free(ctx: *mut ZsigContext);
    fn zsig_multisig_generate_keypair(ctx: *mut ZsigContext, algorithm: Algorithm, out_keypair: *mut ZsigMultisigKeypair) -> ZCryptoError;
    fn zsig_multisig_generate_keypair_from_seed(ctx: *mut ZsigContext, algorithm: Algorithm, seed: *const u8, seed_len: usize, out_keypair: *mut ZsigMultisigKeypair) -> ZCryptoError;
    fn zsig_multisig_sign(ctx: *mut ZsigContext, keypair: *const ZsigMultisigKeypair, message: *const u8, message_len: usize, out_signature: *mut ZsigAuthenticatedSignature) -> ZCryptoError;
    fn zsig_multisig_verify(ctx: *mut ZsigContext, algorithm: Algorithm, public_key: *const ZCryptoPublicKey, message: *const u8, message_len: usize, signature: *const ZsigAuthenticatedSignature, out_valid: *mut bool) -> ZCryptoError;
    
    // zwallet functions
    fn zwallet_context_new() -> *mut ZWalletContext;
    fn zwallet_context_free(ctx: *mut ZWalletContext);
    fn zwallet_create_account_from_passphrase(ctx: *mut ZWalletContext, passphrase: *const c_char, account_type: ZWalletAccountType, out_account: *mut ZWalletAccount) -> ZCryptoError;
    fn zwallet_import_private_key(ctx: *mut ZWalletContext, private_key: *const u8, key_len: usize, account_type: ZWalletAccountType, out_account: *mut ZWalletAccount) -> ZCryptoError;
}

impl From<ZCryptoError> for WalletError {
    fn from(err: ZCryptoError) -> Self {
        match err {
            ZCryptoError::Ok => unreachable!("Ok is not an error"),
            ZCryptoError::InvalidParam => WalletError::Ffi("Invalid parameter".to_string()),
            ZCryptoError::CryptoFailed => WalletError::Crypto("Cryptographic operation failed".to_string()),
            ZCryptoError::Unsupported => WalletError::Ffi("Unsupported operation".to_string()),
            ZCryptoError::OutOfMemory => WalletError::Ffi("Out of memory".to_string()),
        }
    }
}

// Safe Rust wrappers for zcrypto
pub struct ZCrypto;

impl ZCrypto {
    #[cfg(feature = "zig-ffi")]
    pub fn generate_keypair(algorithm: Algorithm) -> Result<Keypair> {
        unsafe {
            let mut ffi_keypair = std::mem::zeroed::<ZCryptoKeypair>();
            let result = zcrypto_generate_keypair(algorithm, &mut ffi_keypair);
            
            if result != ZCryptoError::Ok {
                return Err(result.into());
            }
            
            Ok(Keypair::from_ffi(ffi_keypair))
        }
    }
    
    #[cfg(not(feature = "zig-ffi"))]
    pub fn generate_keypair(algorithm: Algorithm) -> Result<Keypair> {
        // Fallback to native Rust implementation
        match algorithm {
            Algorithm::Ed25519 => {
                let (signing_key, verifying_key) = zcrypto::generate_keypair()?;
                Ok(Keypair {
                    private_key: signing_key.to_bytes().to_vec(),
                    public_key: verifying_key.to_bytes(),
                    algorithm,
                })
            }
            _ => Err(WalletError::Ffi("Algorithm not supported without Zig FFI".to_string())),
        }
    }
    
    #[cfg(feature = "zig-ffi")]
    pub fn generate_keypair_from_seed(algorithm: Algorithm, seed: &[u8]) -> Result<Keypair> {
        unsafe {
            let mut ffi_keypair = std::mem::zeroed::<ZCryptoKeypair>();
            let result = zcrypto_generate_keypair_from_seed(algorithm, seed.as_ptr(), seed.len(), &mut ffi_keypair);
            
            if result != ZCryptoError::Ok {
                return Err(result.into());
            }
            
            Ok(Keypair::from_ffi(ffi_keypair))
        }
    }
    
    #[cfg(not(feature = "zig-ffi"))]
    pub fn generate_keypair_from_seed(algorithm: Algorithm, seed: &[u8]) -> Result<Keypair> {
        // Fallback implementation
        match algorithm {
            Algorithm::Ed25519 => {
                if seed.len() != 32 {
                    return Err(WalletError::Crypto("Ed25519 requires 32-byte seed".to_string()));
                }
                let mut seed_bytes = [0u8; 32];
                seed_bytes.copy_from_slice(seed);
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
                let verifying_key = signing_key.verifying_key();
                
                Ok(Keypair {
                    private_key: signing_key.to_bytes().to_vec(),
                    public_key: verifying_key.to_bytes(),
                    algorithm,
                })
            }
            _ => Err(WalletError::Ffi("Algorithm not supported without Zig FFI".to_string())),
        }
    }
}

// Safe wrapper for zsig
pub struct ZSig {
    #[cfg(feature = "zig-ffi")]
    ctx: *mut ZsigContext,
    #[cfg(not(feature = "zig-ffi"))]
    _phantom: PhantomData<()>,
}

impl ZSig {
    #[cfg(feature = "zig-ffi")]
    pub fn new() -> Result<Self> {
        unsafe {
            let ctx = zsig_context_new();
            if ctx.is_null() {
                return Err(WalletError::Ffi("Failed to create zsig context".to_string()));
            }
            Ok(Self { ctx })
        }
    }

    #[cfg(not(feature = "zig-ffi"))]
    pub fn new() -> Result<Self> {
        Ok(Self { _phantom: PhantomData })
    }

    pub fn generate_keypair_from_seed(&self, algorithm: Algorithm, seed: &[u8]) -> Result<KeypairResult> {
        // Use native Rust implementation
        match algorithm {
            Algorithm::Ed25519 => {
                if seed.len() < 32 {
                    return Err(WalletError::Crypto("Seed too short for Ed25519".to_string()));
                }
                let mut seed_bytes = [0u8; 32];
                seed_bytes.copy_from_slice(&seed[0..32]);
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
                let verifying_key = signing_key.verifying_key();
                
                Ok(KeypairResult {
                    keypair: Keypair {
                        private_key: signing_key.to_bytes().to_vec(),
                        public_key: verifying_key.to_bytes(),
                        algorithm,
                    }
                })
            }
            _ => Err(WalletError::Ffi("Algorithm not supported without Zig FFI".to_string())),
        }
    }

    pub fn sign(&self, keypair: &KeypairResult, data: &[u8]) -> Result<[u8; 64]> {
        // Use native Rust implementation for Ed25519
        match keypair.keypair.algorithm {
            Algorithm::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(
                    &keypair.keypair.private_key.as_slice().try_into()
                        .map_err(|_| WalletError::Crypto("Invalid private key length".to_string()))?
                );
                let signature = signing_key.sign(data);
                Ok(signature.to_bytes())
            }
            _ => Err(WalletError::Ffi("Algorithm not supported".to_string())),
        }
    }
    
    #[cfg(feature = "zig-ffi")]
    pub fn generate_keypair(&self, algorithm: Algorithm) -> Result<MultisigKeypair> {
        unsafe {
            let mut ffi_keypair = std::mem::zeroed::<ZsigMultisigKeypair>();
            let result = zsig_multisig_generate_keypair(self.ctx, algorithm, &mut ffi_keypair);
            
            if result != ZCryptoError::Ok {
                return Err(result.into());
            }
            
            Ok(MultisigKeypair::from_ffi(ffi_keypair))
        }
    }
}

#[cfg(feature = "zig-ffi")]
impl Drop for ZSig {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                zsig_context_free(self.ctx);
            }
        }
    }
}

unsafe impl Send for ZSig {}
unsafe impl Sync for ZSig {}

// Safe wrapper for zwallet
pub struct ZWallet {
    #[cfg(feature = "zig-ffi")]
    ctx: *mut ZWalletContext,
    #[cfg(not(feature = "zig-ffi"))]
    _phantom: PhantomData<()>,
}

impl ZWallet {
    #[cfg(feature = "zig-ffi")]
    pub fn new() -> Result<Self> {
        unsafe {
            let ctx = zwallet_context_new();
            if ctx.is_null() {
                return Err(WalletError::Ffi("Failed to create zwallet context".to_string()));
            }
            Ok(Self { ctx })
        }
    }
    
    #[cfg(not(feature = "zig-ffi"))]
    pub fn new() -> Result<Self> {
        Ok(Self { _phantom: PhantomData })
    }
    
    #[cfg(feature = "zig-ffi")]
    pub fn create_account_from_passphrase(&self, passphrase: &str, account_type: AccountType) -> Result<Account> {
        unsafe {
            let c_passphrase = CString::new(passphrase).map_err(|_| WalletError::Ffi("Invalid passphrase".to_string()))?;
            let mut ffi_account = std::mem::zeroed::<ZWalletAccount>();
            let ffi_account_type = match account_type {
                AccountType::Ed25519 => ZWalletAccountType::Ed25519,
                AccountType::Secp256k1 => ZWalletAccountType::Secp256k1,
            };
            
            let result = zwallet_create_account_from_passphrase(
                self.ctx,
                c_passphrase.as_ptr(),
                ffi_account_type,
                &mut ffi_account
            );
            
            if result != ZCryptoError::Ok {
                return Err(result.into());
            }
            
            Ok(Account::from_ffi(ffi_account))
        }
    }
    
    pub fn create_account(&self, seed: &[u8], account_type: AccountType) -> Result<Account> {
        #[cfg(feature = "zig-ffi")]
        {
            // Use FFI implementation if available
            unsafe {
                let mut ffi_account = std::mem::zeroed::<ZWalletAccount>();
                let ffi_account_type = match account_type {
                    AccountType::Ed25519 => ZWalletAccountType::Ed25519,
                    AccountType::Secp256k1 => ZWalletAccountType::Secp256k1,
                };
                
                let result = zwallet_create_account_from_seed(
                    self.ctx,
                    seed.as_ptr(),
                    seed.len(),
                    ffi_account_type,
                    &mut ffi_account
                );
                
                if result != 0 {
                    return Err(WalletError::Ffi("Failed to create account".to_string()));
                }
                
                Ok(Account {
                    address: ffi_account.address,
                    public_key: ffi_account.public_key,
                    account_type,
                })
            }
        }
        #[cfg(not(feature = "zig-ffi"))]
        {
            // Use native Rust implementation
            self.create_account_native(seed, account_type)
        }
    }

    #[cfg(not(feature = "zig-ffi"))]
    fn create_account_native(&self, seed: &[u8], account_type: AccountType) -> Result<Account> {
        match account_type {
            AccountType::Ed25519 => {
                if seed.len() < 32 {
                    return Err(WalletError::Crypto("Seed too short".to_string()));
                }
                let mut seed_bytes = [0u8; 32];
                seed_bytes.copy_from_slice(&seed[0..32]);
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
                let verifying_key = signing_key.verifying_key();
                
                // Generate address from public key (simplified)
                let mut address = [0u8; 32];
                address.copy_from_slice(&verifying_key.to_bytes());
                
                Ok(Account {
                    address,
                    public_key: verifying_key.to_bytes(),
                    account_type,
                    zns_domain: None,
                })
            }
            _ => Err(WalletError::Ffi("Account type not supported in native mode".to_string())),
        }
    }
}

#[cfg(feature = "zig-ffi")]
impl Drop for ZWallet {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                zwallet_context_free(self.ctx);
            }
        }
    }
}

unsafe impl Send for ZWallet {}
unsafe impl Sync for ZWallet {}

// Rust data structures
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Identity {
    pub public_key: [u8; 32],
    pub qid: [u8; 16], // IPv6 QID
    pub domain: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub address: [u8; 32],
    pub public_key: [u8; 32],
    pub account_type: AccountType,
    pub zns_domain: Option<String>,
}

impl Account {
    #[cfg(feature = "zig-ffi")]
    fn from_ffi(ffi: ZWalletAccount) -> Self {
        let domain = if ffi.has_zns_domain {
            let domain_bytes = &ffi.zns_domain[..ffi.zns_domain.iter().position(|&b| b == 0).unwrap_or(256)];
            String::from_utf8_lossy(domain_bytes).into_owned().into()
        } else {
            None
        };
        
        Self {
            address: ffi.address,
            public_key: ffi.public_key.bytes,
            account_type: match ffi.account_type {
                ZWalletAccountType::Ed25519 => AccountType::Ed25519,
                ZWalletAccountType::Secp256k1 => AccountType::Secp256k1,
                ZWalletAccountType::Secp256r1 => AccountType::Secp256r1,
            },
            zns_domain: domain,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AccountType {
    Ed25519,
    Secp256k1,
    Secp256r1,
}

#[derive(Debug, Clone)]
pub struct KeypairResult {
    pub keypair: Keypair,
}

#[derive(Debug, Clone)]
pub struct Keypair {
    pub private_key: Vec<u8>,
    pub public_key: [u8; 32],
    pub algorithm: Algorithm,
}

impl Keypair {
    #[cfg(feature = "zig-ffi")]
    fn from_ffi(ffi: ZCryptoKeypair) -> Self {
        Self {
            private_key: ffi.private_key.bytes.to_vec(),
            public_key: ffi.public_key.bytes,
            algorithm: ffi.algorithm,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MultisigKeypair {
    pub keypair: Keypair,
    pub hmac_key: Option<[u8; 32]>,
}

impl MultisigKeypair {
    #[cfg(feature = "zig-ffi")]
    fn from_ffi(ffi: ZsigMultisigKeypair) -> Self {
        Self {
            keypair: Keypair::from_ffi(ffi.keypair),
            hmac_key: if ffi.has_hmac_key { Some(ffi.hmac_key) } else { None },
        }
    }
    
    #[cfg(feature = "zig-ffi")]
    fn to_ffi(&self) -> ZsigMultisigKeypair {
        let mut private_key_bytes = [0u8; 64];
        let len = self.keypair.private_key.len().min(64);
        private_key_bytes[..len].copy_from_slice(&self.keypair.private_key[..len]);
        
        ZsigMultisigKeypair {
            keypair: ZCryptoKeypair {
                private_key: ZCryptoPrivateKey { bytes: private_key_bytes },
                public_key: ZCryptoPublicKey { bytes: self.keypair.public_key },
                algorithm: self.keypair.algorithm,
            },
            hmac_key: self.hmac_key.unwrap_or([0u8; 32]),
            has_hmac_key: self.hmac_key.is_some(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedSignature {
    pub signature: [u8; 64],
    pub hmac_tag: Option<[u8; 32]>,
}

impl AuthenticatedSignature {
    #[cfg(feature = "zig-ffi")]
    fn from_ffi(ffi: ZsigAuthenticatedSignature) -> Self {
        Self {
            signature: ffi.signature.bytes,
            hmac_tag: if ffi.has_hmac { Some(ffi.hmac_tag) } else { None },
        }
    }
}

// ZCrypto functions (pure Rust fallback)
pub mod zcrypto {
    use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
    use sha2::{Sha256, Digest};
    use crate::error::{WalletError, Result};

    pub fn generate_keypair() -> Result<(SigningKey, VerifyingKey)> {
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key = signing_key.verifying_key();
        Ok((signing_key, verifying_key))
    }

    pub fn sign_ed25519(signing_key: &SigningKey, message: &[u8]) -> Result<[u8; 64]> {
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes())
    }

    pub fn verify_ed25519(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| WalletError::Crypto(format!("Invalid public key: {}", e)))?;
        let signature = Signature::from_bytes(signature);
        
        Ok(verifying_key.verify(message, &signature).is_ok())
    }

    pub fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        Ok(result.into())
    }

    pub fn generate_qid(public_key: &[u8; 32]) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(b"QID:");
        hasher.update(public_key);
        let hash = hasher.finalize();
        
        // Convert to IPv6 QID format
        let mut qid = [0u8; 16];
        qid[0] = 0xfd; // Unique local address prefix
        qid[1] = 0x00;
        qid[2..18].copy_from_slice(&hash[0..16]);
        qid
    }
}
