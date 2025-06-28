use std::sync::Arc;
use std::net::SocketAddr;
use anyhow::Result;
use gquic::prelude::*;
use tracing::{info, debug};

pub struct QuicClient {
    client: gquic::client::QuicClient,
    pool: ConnectionPool,
}

impl QuicClient {
    pub fn new(server_name: String) -> Result<Self> {
        let config = QuicClientConfig::builder()
            .server_name(server_name)
            .with_alpn("ghostchain-v1")
            .with_alpn("grpc")
            .max_idle_timeout(30_000)
            .enable_0rtt(true)
            .build();

        let client = gquic::client::QuicClient::new(config)?;
        
        let pool_config = PoolConfig::builder()
            .max_connections_per_endpoint(10)
            .max_connection_age(std::time::Duration::from_secs(3600))
            .max_idle_time(std::time::Duration::from_secs(300))
            .enable_multiplexing(true)
            .max_concurrent_streams(100)
            .build();
            
        let pool = ConnectionPool::new(pool_config);

        Ok(Self { client, pool })
    }

    pub async fn send_transaction(
        &self,
        addr: SocketAddr,
        tx_data: &[u8],
    ) -> Result<Vec<u8>> {
        let conn = match self.pool.get_connection(addr).await {
            Some(conn) => conn,
            None => {
                info!("Creating new QUIC connection to {}", addr);
                let conn = self.client.connect(addr).await?;
                self.pool.return_connection(addr, conn.clone()).await;
                conn
            }
        };

        debug!("Sending transaction over QUIC, size: {} bytes", tx_data.len());
        
        let mut stream = self.client.open_bi_stream(&conn).await?;
        
        // Write transaction type marker
        stream.write_all(&[1u8]).await?; // 1 = transaction
        stream.write_all(tx_data).await?;
        stream.finish().await?;
        
        let response = stream.read_to_end(64 * 1024).await?;
        debug!("Received response, size: {} bytes", response.len());
        
        Ok(response)
    }

    pub async fn query_balance(
        &self,
        addr: SocketAddr,
        wallet_address: &str,
    ) -> Result<Vec<u8>> {
        let conn = match self.pool.get_connection(addr).await {
            Some(conn) => conn,
            None => {
                let conn = self.client.connect(addr).await?;
                self.pool.return_connection(addr, conn.clone()).await;
                conn
            }
        };

        let mut stream = self.client.open_bi_stream(&conn).await?;
        
        // Write query type marker
        stream.write_all(&[2u8]).await?; // 2 = balance query
        stream.write_all(wallet_address.as_bytes()).await?;
        stream.finish().await?;
        
        let response = stream.read_to_end(64 * 1024).await?;
        Ok(response)
    }

    pub async fn subscribe_events(
        &self,
        addr: SocketAddr,
        wallet_id: &str,
    ) -> Result<RecvStream> {
        let conn = self.client.connect(addr).await?;
        
        let mut stream = self.client.open_bi_stream(&conn).await?;
        
        // Write subscription type
        stream.write_all(&[3u8]).await?; // 3 = event subscription
        stream.write_all(wallet_id.as_bytes()).await?;
        stream.finish().await?;
        
        // Return the receive stream for reading events
        Ok(stream)
    }

    pub async fn close(&self) {
        self.pool.close_all().await;
    }
}