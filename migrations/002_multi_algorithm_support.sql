-- Migration to add multi-algorithm support and enhanced security features

-- Add algorithm column to wallets table
-- Note: We're keeping account_type for backward compatibility
ALTER TABLE wallets ADD COLUMN algorithm TEXT DEFAULT 'ed25519';

-- Update existing wallets to have explicit algorithm
UPDATE wallets SET algorithm = 
    CASE 
        WHEN account_type = 'secp256k1' THEN 'secp256k1'
        WHEN account_type = 'secp256r1' THEN 'secp256r1'
        ELSE 'ed25519'
    END;

-- Create table for HMAC keys (for authenticated operations)
CREATE TABLE IF NOT EXISTS hmac_keys (
    id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL,
    key_hash TEXT NOT NULL, -- Store hashed HMAC key for security
    purpose TEXT NOT NULL, -- 'signing', 'authentication', etc.
    created_at DATETIME NOT NULL,
    expires_at DATETIME,
    last_used DATETIME,
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE CASCADE
);

-- Create table for key derivation metadata
CREATE TABLE IF NOT EXISTS key_derivation_info (
    wallet_id TEXT PRIMARY KEY,
    derivation_method TEXT NOT NULL, -- 'passphrase', 'mnemonic', 'hardware'
    derivation_path TEXT, -- For HD wallets (e.g., "m/44'/1337'/0'/0/0")
    salt TEXT, -- For passphrase derivation (stored securely)
    metadata TEXT, -- JSON for additional info
    created_at DATETIME NOT NULL,
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE CASCADE
);

-- Add columns to transactions table for multi-algorithm support
ALTER TABLE transactions ADD COLUMN algorithm TEXT DEFAULT 'ed25519';
ALTER TABLE transactions ADD COLUMN signature_type TEXT DEFAULT 'standard'; -- 'standard', 'authenticated', 'multisig'

-- Create indexes for new columns
CREATE INDEX IF NOT EXISTS idx_wallets_algorithm ON wallets (algorithm);
CREATE INDEX IF NOT EXISTS idx_hmac_keys_wallet_id ON hmac_keys (wallet_id);
CREATE INDEX IF NOT EXISTS idx_hmac_keys_purpose ON hmac_keys (purpose);
CREATE INDEX IF NOT EXISTS idx_transactions_algorithm ON transactions (algorithm);

-- Add session management for authenticated operations
CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL,
    session_token_hash TEXT NOT NULL,
    challenge TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    last_activity DATETIME NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_wallet_id ON auth_sessions (wallet_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions (expires_at);