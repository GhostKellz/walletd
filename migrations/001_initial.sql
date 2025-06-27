-- Create wallets table
CREATE TABLE IF NOT EXISTS wallets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    account_type TEXT NOT NULL,
    network TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- Create transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL,
    tx_hash TEXT,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    amount TEXT NOT NULL,
    token_address TEXT,
    token_symbol TEXT,
    gas_limit INTEGER,
    gas_price TEXT,
    gas_used INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    block_number INTEGER,
    block_hash TEXT,
    transaction_index INTEGER,
    nonce INTEGER,
    data TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE CASCADE
);

-- Create balances table
CREATE TABLE IF NOT EXISTS balances (
    wallet_id TEXT NOT NULL,
    token_address TEXT,
    token_symbol TEXT NOT NULL,
    balance TEXT NOT NULL,
    decimals INTEGER NOT NULL DEFAULT 18,
    last_updated DATETIME NOT NULL,
    PRIMARY KEY (wallet_id, token_address),
    FOREIGN KEY (wallet_id) REFERENCES wallets (id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_transactions_wallet_id ON transactions (wallet_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions (status);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions (created_at);
CREATE INDEX IF NOT EXISTS idx_transactions_tx_hash ON transactions (tx_hash);
CREATE INDEX IF NOT EXISTS idx_balances_wallet_id ON balances (wallet_id);
