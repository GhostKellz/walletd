use std::path::Path;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use sqlx::{SqlitePool, Row};

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Transaction {
    pub id: String,
    pub wallet_id: String,
    pub tx_hash: Option<String>,
    pub from_address: String,
    pub to_address: String,
    pub amount: String, // Using string to handle large numbers
    pub token_address: Option<String>,
    pub token_symbol: Option<String>,
    pub gas_limit: Option<i64>,
    pub gas_price: Option<String>,
    pub gas_used: Option<i64>,
    pub status: TransactionStatus,
    pub block_number: Option<i64>,
    pub block_hash: Option<String>,
    pub transaction_index: Option<i64>,
    pub nonce: Option<i64>,
    pub data: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "transaction_status", rename_all = "lowercase")]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WalletRecord {
    pub id: String,
    pub name: String,
    pub address: String,
    pub public_key: String,
    pub account_type: String,
    pub network: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Balance {
    pub wallet_id: String,
    pub token_address: Option<String>,
    pub token_symbol: String,
    pub balance: String,
    pub decimals: i64,
    pub last_updated: DateTime<Utc>,
}

pub struct LedgerStore {
    pool: SqlitePool,
}

impl LedgerStore {
    pub async fn new<P: AsRef<Path>>(database_path: P) -> Result<Self> {
        let database_url = format!("sqlite:{}", database_path.as_ref().display());
        
        let pool = SqlitePool::connect(&database_url).await?;
        
        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await?;
        
        Ok(Self { pool })
    }

    // Wallet management
    pub async fn create_wallet(&self, wallet: &WalletRecord) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO wallets (id, name, address, public_key, account_type, network, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&wallet.id)
        .bind(&wallet.name)
        .bind(&wallet.address)
        .bind(&wallet.public_key)
        .bind(&wallet.account_type)
        .bind(&wallet.network)
        .bind(wallet.created_at)
        .bind(wallet.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_wallet(&self, wallet_id: &str) -> Result<WalletRecord> {
        let row = sqlx::query_as::<_, WalletRecord>(
            "SELECT * FROM wallets WHERE id = ?"
        )
        .bind(wallet_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn list_wallets(&self) -> Result<Vec<WalletRecord>> {
        let rows = sqlx::query_as::<_, WalletRecord>(
            "SELECT * FROM wallets ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn delete_wallet(&self, wallet_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM wallets WHERE id = ?")
            .bind(wallet_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // Transaction management
    pub async fn save_transaction(&self, tx: &Transaction) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO transactions 
            (id, wallet_id, tx_hash, from_address, to_address, amount, token_address, token_symbol,
             gas_limit, gas_price, gas_used, status, block_number, block_hash, transaction_index,
             nonce, data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&tx.id)
        .bind(&tx.wallet_id)
        .bind(&tx.tx_hash)
        .bind(&tx.from_address)
        .bind(&tx.to_address)
        .bind(&tx.amount)
        .bind(&tx.token_address)
        .bind(&tx.token_symbol)
        .bind(tx.gas_limit)
        .bind(&tx.gas_price)
        .bind(tx.gas_used)
        .bind(&tx.status)
        .bind(tx.block_number)
        .bind(&tx.block_hash)
        .bind(tx.transaction_index)
        .bind(tx.nonce)
        .bind(&tx.data)
        .bind(tx.created_at)
        .bind(tx.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_transaction(&self, tx_id: &str) -> Result<Transaction> {
        let row = sqlx::query_as::<_, Transaction>(
            "SELECT * FROM transactions WHERE id = ?"
        )
        .bind(tx_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_transactions_by_wallet(&self, wallet_id: &str, limit: Option<i64>) -> Result<Vec<Transaction>> {
        let limit = limit.unwrap_or(100);
        
        let rows = sqlx::query_as::<_, Transaction>(
            "SELECT * FROM transactions WHERE wallet_id = ? ORDER BY created_at DESC LIMIT ?"
        )
        .bind(wallet_id)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn update_transaction_status(&self, tx_id: &str, status: TransactionStatus, tx_hash: Option<&str>) -> Result<()> {
        sqlx::query(
            "UPDATE transactions SET status = ?, tx_hash = ?, updated_at = ? WHERE id = ?"
        )
        .bind(&status)
        .bind(tx_hash)
        .bind(Utc::now())
        .bind(tx_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Balance management
    pub async fn update_balance(&self, balance: &Balance) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO balances 
            (wallet_id, token_address, token_symbol, balance, decimals, last_updated)
            VALUES (?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&balance.wallet_id)
        .bind(&balance.token_address)
        .bind(&balance.token_symbol)
        .bind(&balance.balance)
        .bind(balance.decimals)
        .bind(balance.last_updated)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_balances(&self, wallet_id: &str) -> Result<Vec<Balance>> {
        let rows = sqlx::query_as::<_, Balance>(
            "SELECT * FROM balances WHERE wallet_id = ? ORDER BY token_symbol"
        )
        .bind(wallet_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn get_balance(&self, wallet_id: &str, token_address: Option<&str>) -> Result<Option<Balance>> {
        let row = sqlx::query_as::<_, Balance>(
            r#"
            SELECT * FROM balances 
            WHERE wallet_id = ? AND 
                  (token_address = ? OR (token_address IS NULL AND ? IS NULL))
            "#
        )
        .bind(wallet_id)
        .bind(token_address)
        .bind(token_address)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    // Analytics and reporting
    pub async fn get_transaction_stats(&self, wallet_id: &str) -> Result<TransactionStats> {
        let row = sqlx::query(
            r#"
            SELECT 
                CAST(COUNT(*) AS INTEGER) as total_transactions,
                CAST(COUNT(CASE WHEN status = 'confirmed' THEN 1 END) AS INTEGER) as confirmed_transactions,
                CAST(COUNT(CASE WHEN status = 'pending' THEN 1 END) AS INTEGER) as pending_transactions,
                CAST(COUNT(CASE WHEN status = 'failed' THEN 1 END) AS INTEGER) as failed_transactions,
                CAST(SUM(CASE WHEN gas_used IS NOT NULL THEN gas_used ELSE 0 END) AS INTEGER) as total_gas_used
            FROM transactions 
            WHERE wallet_id = ?
            "#
        )
        .bind(wallet_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(TransactionStats {
            total_transactions: row.get::<i64, _>("total_transactions"),
            confirmed_transactions: row.get::<i64, _>("confirmed_transactions"),
            pending_transactions: row.get::<i64, _>("pending_transactions"),
            failed_transactions: row.get::<i64, _>("failed_transactions"),
            total_gas_used: row.get::<i64, _>("total_gas_used"),
        })
    }

    // Search and filtering
    pub async fn search_transactions(
        &self,
        wallet_id: Option<&str>,
        status: Option<TransactionStatus>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<Transaction>> {
        let mut query = "SELECT * FROM transactions WHERE 1=1".to_string();
        let mut params: Vec<Box<dyn sqlx::Encode<'_, sqlx::Sqlite> + Send>> = Vec::new();

        if let Some(wallet_id) = wallet_id {
            query.push_str(" AND wallet_id = ?");
            params.push(Box::new(wallet_id.to_string()));
        }

        if let Some(status) = status {
            query.push_str(" AND status = ?");
            params.push(Box::new(status));
        }

        query.push_str(" ORDER BY created_at DESC");

        if let Some(limit) = limit {
            query.push_str(" LIMIT ?");
            params.push(Box::new(limit));
        }

        if let Some(offset) = offset {
            query.push_str(" OFFSET ?");
            params.push(Box::new(offset));
        }

        // Note: This is a simplified version. For a production system,
        // you'd want to use a query builder or more sophisticated parameter binding
        let rows = sqlx::query_as::<_, Transaction>(&query)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionStats {
    pub total_transactions: i64,
    pub confirmed_transactions: i64,
    pub pending_transactions: i64,
    pub failed_transactions: i64,
    pub total_gas_used: i64,
}
