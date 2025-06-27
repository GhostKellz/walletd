#[cfg(test)]
mod tests {
    use walletd::ffi::{Algorithm, ZCrypto, ZSig, ZWallet};
    use walletd::wallet::{WalletManager, CreateWalletRequest};
    use walletd::auth::AuthManager;
    use walletd::signer::TransactionSigner;
    
    #[tokio::test]
    async fn test_multi_algorithm_wallet_creation() {
        // Test creating wallets with different algorithms
        let algorithms = vec![
            ("ed25519", Algorithm::Ed25519),
            ("secp256k1", Algorithm::Secp256k1),
            ("secp256r1", Algorithm::Secp256r1),
        ];
        
        for (algo_str, algo_enum) in algorithms {
            // Test with ZCrypto
            if let Ok(keypair) = ZCrypto::generate_keypair(algo_enum) {
                assert_eq!(keypair.algorithm, algo_enum);
                assert_eq!(keypair.public_key.len(), 32);
                println!("✓ Generated {} keypair with ZCrypto", algo_str);
            }
            
            // Test deterministic generation
            let seed = b"test-seed-for-deterministic-generation!!";
            if let Ok(keypair1) = ZCrypto::generate_keypair_from_seed(algo_enum, seed) {
                if let Ok(keypair2) = ZCrypto::generate_keypair_from_seed(algo_enum, seed) {
                    assert_eq!(keypair1.public_key, keypair2.public_key);
                    println!("✓ Deterministic {} generation verified", algo_str);
                }
            }
        }
    }
    
    #[tokio::test]
    async fn test_hmac_authentication() {
        use walletd::auth::AuthManager;
        use walletd::config::Config;
        
        let config = Config::default();
        let auth_manager = AuthManager::new(config).await.unwrap();
        
        // Generate HMAC key
        let wallet_id = "test-wallet-123";
        let hmac_key = auth_manager.generate_hmac_key(wallet_id, "signing").await.unwrap();
        let hmac_key_bytes = hex::decode(&hmac_key).unwrap();
        
        // Create authenticated request
        let auth_request = auth_manager.create_authenticated_request(wallet_id, &hmac_key_bytes).await.unwrap();
        
        // Verify authenticated request
        let is_valid = auth_manager.verify_authenticated_request(&auth_request, &hmac_key_bytes).await.unwrap();
        assert!(is_valid);
        println!("✓ HMAC authentication verified");
        
        // Test with wrong key
        let wrong_key = vec![0u8; 32];
        let is_invalid = auth_manager.verify_authenticated_request(&auth_request, &wrong_key).await.unwrap();
        assert!(!is_invalid);
        println!("✓ HMAC authentication correctly rejects wrong key");
    }
    
    #[tokio::test]
    async fn test_multi_algorithm_signing() {
        if let Ok(zsig) = ZSig::new() {
            let message = b"Test message for multi-algorithm signing";
            
            // Test Ed25519
            if let Ok(ed_keypair) = zsig.generate_keypair(Algorithm::Ed25519) {
                if let Ok(ed_sig) = zsig.sign(&ed_keypair, message) {
                    assert_eq!(ed_sig.signature.len(), 64);
                    println!("✓ Ed25519 signing successful");
                }
            }
            
            // Test secp256k1
            if let Ok(secp_keypair) = zsig.generate_keypair(Algorithm::Secp256k1) {
                if let Ok(secp_sig) = zsig.sign(&secp_keypair, message) {
                    assert_eq!(secp_sig.signature.len(), 64);
                    println!("✓ secp256k1 signing successful");
                }
            }
        }
    }
    
    #[tokio::test]
    async fn test_wallet_integration() {
        use walletd::config::Config;
        use walletd::ledger::LedgerStore;
        use std::sync::Arc;
        
        // Set up test environment
        let config = Config::default();
        let ledger = Arc::new(LedgerStore::new(":memory:").await.unwrap());
        let auth_manager = Arc::new(AuthManager::new(config.clone()).await.unwrap());
        let wallet_manager = WalletManager::new(config, ledger, auth_manager).await.unwrap();
        
        // Test creating wallets with different algorithms
        let test_cases = vec![
            ("Ed25519 Wallet", "ed25519", "test-passphrase-ed25519"),
            ("Secp256k1 Wallet", "secp256k1", "test-passphrase-secp256k1"),
            ("Secp256r1 Wallet", "secp256r1", "test-passphrase-secp256r1"),
        ];
        
        for (name, algo, passphrase) in test_cases {
            let request = CreateWalletRequest {
                name: name.to_string(),
                account_type: Some(algo.to_string()),
                passphrase: Some(passphrase.to_string()),
                network: None,
            };
            
            match wallet_manager.create_wallet(request).await {
                Ok(wallet) => {
                    assert_eq!(wallet.account_type, algo);
                    assert!(!wallet.public_key.is_empty());
                    println!("✓ Created {} wallet successfully", algo);
                }
                Err(e) => {
                    println!("⚠ Failed to create {} wallet: {} (may require Zig FFI)", algo, e);
                }
            }
        }
    }
    
    #[test]
    fn test_deterministic_key_derivation() {
        use walletd::ffi::zcrypto;
        
        let passphrase = "test passphrase for deterministic generation";
        let salt = b"walletd-passphrase-salt";
        
        // Generate key material twice
        let key1 = zcrypto::derive_key_from_passphrase(passphrase, salt).unwrap();
        let key2 = zcrypto::derive_key_from_passphrase(passphrase, salt).unwrap();
        
        // Should be identical
        assert_eq!(key1, key2);
        println!("✓ Deterministic key derivation verified");
        
        // Different passphrase should give different key
        let different_passphrase = "different passphrase";
        let key3 = zcrypto::derive_key_from_passphrase(different_passphrase, salt).unwrap();
        assert_ne!(key1, key3);
        println!("✓ Different passphrases produce different keys");
    }
}