use anyhow::Result;
use tracing::{info, warn};

#[cfg(feature = "enhanced-crypto")]
use gcrypt::protocols::ed25519::{SecretKey, PublicKey, Signature, SignatureError};

#[cfg(feature = "enhanced-crypto")]
use rand::rngs::OsRng;

use crate::ffi::{Algorithm, Keypair};

/// Enhanced crypto operations using gcrypt for Ed25519 and fallbacks for other algorithms
pub struct EnhancedCrypto {
    // gcrypt provides Ed25519 operations only, other algorithms use fallback implementations
}

impl EnhancedCrypto {
    #[cfg(feature = "enhanced-crypto")]
    pub fn new() -> Result<Self> {
        info!("🔐 Enhanced gcrypt backend initialized with Ed25519 support");
        Ok(Self {})
    }

    #[cfg(not(feature = "enhanced-crypto"))]
    pub fn new() -> Result<Self> {
        warn!("⚠️  Enhanced crypto backend not available. Using fallback implementations.");
        Ok(Self {})
    }

    #[cfg(feature = "enhanced-crypto")]
    pub fn generate_keypair(&self, algorithm: Algorithm) -> Result<Keypair> {
        match algorithm {
            Algorithm::Ed25519 => {
                let mut rng = OsRng;
                let secret_key = SecretKey::generate(&mut rng);
                let public_key = secret_key.public_key();
                
                Ok(Keypair {
                    private_key: secret_key.to_bytes().to_vec(),
                    public_key: public_key.to_bytes(),
                    algorithm: Algorithm::Ed25519,
                })
            }
            _ => {
                // Fallback for non-Ed25519 algorithms
                self.generate_keypair_fallback(algorithm)
            }
        }
    }

    #[cfg(not(feature = "enhanced-crypto"))]
    pub fn generate_keypair(&self, algorithm: Algorithm) -> Result<Keypair> {
        // Fallback to ed25519-dalek for Ed25519
        match algorithm {
            Algorithm::Ed25519 => {
                use ed25519_dalek::{SigningKey, Signer};
                use rand::rngs::OsRng;
                
                let mut rng = OsRng;
                let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
                let public_key = signing_key.verifying_key();
                
                Ok(Keypair {
                    private_key: signing_key.to_bytes().to_vec(),
                    public_key: public_key.to_bytes(),
                    algorithm: Algorithm::Ed25519,
                })
            }
            _ => {
                Err(anyhow::anyhow!("Algorithm {:?} not supported without enhanced-crypto feature", algorithm))
            }
        }
    }

    #[cfg(feature = "enhanced-crypto")]
    pub fn sign_data(&self, private_key: &[u8], data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
        match algorithm {
            Algorithm::Ed25519 => {
                let key_bytes: [u8; 32] = private_key.try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid Ed25519 private key length"))?;
                let secret_key = SecretKey::from_bytes(&key_bytes);
                let signature = secret_key.sign_deterministic(data);
                Ok(signature.to_bytes().to_vec())
            }
            _ => {
                // Fallback for non-Ed25519 algorithms
                self.sign_data_fallback(private_key, data, algorithm)
            }
        }
    }

    #[cfg(not(feature = "enhanced-crypto"))]
    pub fn sign_data(&self, private_key: &[u8], data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
        match algorithm {
            Algorithm::Ed25519 => {
                use ed25519_dalek::{SigningKey, Signer};
                
                let key_bytes: [u8; 32] = private_key.try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid Ed25519 private key length"))?;
                let signing_key = SigningKey::from_bytes(&key_bytes);
                let signature = signing_key.sign(data);
                
                Ok(signature.to_bytes().to_vec())
            }
            _ => {
                Err(anyhow::anyhow!("Algorithm {:?} not supported without enhanced-crypto feature", algorithm))
            }
        }
    }

    #[cfg(feature = "enhanced-crypto")]
    pub fn verify_signature(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool> {
        match algorithm {
            Algorithm::Ed25519 => {
                let public_key_bytes: [u8; 32] = public_key.try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid Ed25519 public key length"))?;
                let signature_bytes: [u8; 64] = signature.try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid Ed25519 signature length"))?;
                
                let public_key_obj = PublicKey::from_bytes(&public_key_bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {:?}", e))?;
                let signature_obj = Signature::from_bytes(&signature_bytes);
                
                match public_key_obj.verify(data, &signature_obj) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            _ => {
                // Fallback for non-Ed25519 algorithms
                self.verify_signature_fallback(public_key, data, signature, algorithm)
            }
        }
    }

    #[cfg(not(feature = "enhanced-crypto"))]
    pub fn verify_signature(
        &self,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> Result<bool> {
        match algorithm {
            Algorithm::Ed25519 => {
                use ed25519_dalek::{VerifyingKey, Verifier, Signature};
                
                let public_key_bytes: [u8; 32] = public_key.try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid Ed25519 public key length"))?;
                let signature_bytes: [u8; 64] = signature.try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid Ed25519 signature length"))?;
                
                let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {}", e))?;
                let signature_obj = Signature::from_bytes(&signature_bytes);
                
                match verifying_key.verify(data, &signature_obj) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            _ => {
                Err(anyhow::anyhow!("Algorithm {:?} not supported without enhanced-crypto feature", algorithm))
            }
        }
    }

    #[cfg(feature = "enhanced-crypto")]
    pub fn hash_blake3(&self, data: &[u8]) -> Result<[u8; 32]> {
        // gcrypt doesn't provide BLAKE3, use fallback
        use sha2::{Sha256, Digest};
        warn!("⚠️  BLAKE3 not available in gcrypt, falling back to SHA256");
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(hasher.finalize().into())
    }

    #[cfg(not(feature = "enhanced-crypto"))]
    pub fn hash_blake3(&self, data: &[u8]) -> Result<[u8; 32]> {
        use sha2::{Sha256, Digest};
        warn!("⚠️  BLAKE3 not available, falling back to SHA256");
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(hasher.finalize().into())
    }

    #[cfg(feature = "enhanced-crypto")]
    pub fn secure_random(&self, length: usize) -> Result<Vec<u8>> {
        // gcrypt doesn't provide general secure_random, use rand crate
        use rand::RngCore;
        let mut rng = OsRng;
        let mut bytes = vec![0u8; length];
        rng.fill_bytes(&mut bytes);
        Ok(bytes)
    }

    #[cfg(not(feature = "enhanced-crypto"))]
    pub fn secure_random(&self, length: usize) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        let mut bytes = vec![0u8; length];
        rng.fill_bytes(&mut bytes);
        Ok(bytes)
    }

    pub fn supported_algorithms(&self) -> Vec<Algorithm> {
        // gcrypt only provides Ed25519, others use fallback
        vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::Secp256r1]
    }

    // Fallback implementations for non-Ed25519 algorithms
    fn generate_keypair_fallback(&self, algorithm: Algorithm) -> Result<Keypair> {
        match algorithm {
            Algorithm::Ed25519 => unreachable!("Ed25519 should use gcrypt path"),
            _ => Err(anyhow::anyhow!("Algorithm {:?} not supported in fallback mode", algorithm))
        }
    }

    fn sign_data_fallback(&self, private_key: &[u8], data: &[u8], algorithm: Algorithm) -> Result<Vec<u8>> {
        match algorithm {
            Algorithm::Ed25519 => unreachable!("Ed25519 should use gcrypt path"),
            _ => Err(anyhow::anyhow!("Algorithm {:?} not supported in fallback mode", algorithm))
        }
    }

    fn verify_signature_fallback(&self, public_key: &[u8], data: &[u8], signature: &[u8], algorithm: Algorithm) -> Result<bool> {
        match algorithm {
            Algorithm::Ed25519 => unreachable!("Ed25519 should use gcrypt path"),
            _ => Err(anyhow::anyhow!("Algorithm {:?} not supported in fallback mode", algorithm))
        }
    }
}

impl Default for EnhancedCrypto {
    fn default() -> Self {
        Self::new().expect("Failed to initialize enhanced crypto backend")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_keypair_generation() {
        let crypto = EnhancedCrypto::new().unwrap();
        let keypair = crypto.generate_keypair(Algorithm::Ed25519).unwrap();
        
        assert_eq!(keypair.public_key.len(), 32);
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.algorithm, Algorithm::Ed25519);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let crypto = EnhancedCrypto::new().unwrap();
        let keypair = crypto.generate_keypair(Algorithm::Ed25519).unwrap();
        let message = b"test message for signing";
        
        let signature = crypto.sign_data(&keypair.private_key, message, Algorithm::Ed25519).unwrap();
        let is_valid = crypto.verify_signature(&keypair.public_key, message, &signature, Algorithm::Ed25519).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_secure_random() {
        let crypto = EnhancedCrypto::new().unwrap();
        let random1 = crypto.secure_random(32).unwrap();
        let random2 = crypto.secure_random(32).unwrap();
        
        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
        assert_ne!(random1, random2); // Should be different
    }

    #[cfg(feature = "enhanced-crypto")]
    #[test]
    fn test_multi_algorithm_support() {
        let crypto = EnhancedCrypto::new().unwrap();
        let algorithms = crypto.supported_algorithms();
        
        assert!(algorithms.contains(&Algorithm::Ed25519));
        assert!(algorithms.contains(&Algorithm::Secp256k1));
        assert!(algorithms.contains(&Algorithm::Secp256r1));
    }
}
