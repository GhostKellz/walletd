use std::sync::Arc;
use anyhow::Result;
use tracing::{info, warn, error};

#[cfg(feature = "quic")]
use gquic::prelude::*;

use crate::config::{Config, QuicConfig};
use crate::wallet::WalletManager;
use crate::ledger::LedgerStore;
use crate::auth::AuthManager;
use crate::grpc::walletd::{wallet_service_server::WalletServiceServer, wallet_service_server::WalletService};

/// QUIC-based transport server for walletd
pub struct QuicServer {
    config: Config,
    wallet_manager: Arc<WalletManager>,
    ledger: Arc<LedgerStore>,
    auth_manager: Arc<AuthManager>,
}

impl QuicServer {
    pub fn new(
        config: Config,
        wallet_manager: Arc<WalletManager>,
        ledger: Arc<LedgerStore>,
        auth_manager: Arc<AuthManager>,
    ) -> Self {
        Self {
            config,
            wallet_manager,
            ledger,
            auth_manager,
        }
    }

    #[cfg(feature = "quic")]
    pub async fn serve(self) -> Result<()> {
        info!("🚀 Starting QUIC server with gquic");
        
        let quic_config = &self.config.quic;
        let bind_addr = quic_config.bind_address.parse()?;

        // Create QUIC server configuration
        let server_config = gquic::server::QuicServerConfig::builder()
            .max_concurrent_bidi_streams(quic_config.max_concurrent_streams)
            .max_idle_timeout(std::time::Duration::from_millis(quic_config.max_idle_timeout))
            .enable_0rtt(quic_config.enable_0rtt)
            .build()?;

        // Create gRPC handler for QUIC
        let grpc_handler = QuicGrpcHandler::new(
            self.wallet_manager.clone(),
            self.ledger.clone(),
            self.auth_manager.clone(),
        );

        // Build QUIC server
        let server = if quic_config.tls.use_self_signed {
            info!("🔒 Using self-signed certificates for development");
            gquic::server::QuicServer::builder()
                .bind(bind_addr)
                .with_self_signed_cert()?
                .with_config(server_config)
        } else {
            info!("🔒 Using provided TLS certificates");
            gquic::server::QuicServer::builder()
                .bind(bind_addr)
                .with_tls_files(&quic_config.tls.cert_path, &quic_config.tls.key_path)?
                .with_config(server_config)
        };

        // Add ALPN protocols
        let mut server_builder = server;
        for alpn in &quic_config.alpn_protocols {
            server_builder = server_builder.with_alpn(alpn);
        }

        let server = server_builder
            .with_handler(Arc::new(grpc_handler))
            .build()?;

        info!("📡 QUIC server listening on {}", bind_addr);
        info!("🔌 ALPN protocols: {:?}", quic_config.alpn_protocols);

        server.run().await
    }

    #[cfg(not(feature = "quic"))]
    pub async fn serve(self) -> Result<()> {
        warn!("⚠️  QUIC support not enabled. Compile with --features quic to enable QUIC transport.");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok(())
    }
}

#[cfg(feature = "quic")]
struct QuicGrpcHandler {
    wallet_manager: Arc<WalletManager>,
    ledger: Arc<LedgerStore>,
    auth_manager: Arc<AuthManager>,
}

#[cfg(feature = "quic")]
impl QuicGrpcHandler {
    fn new(
        wallet_manager: Arc<WalletManager>,
        ledger: Arc<LedgerStore>,
        auth_manager: Arc<AuthManager>,
    ) -> Self {
        Self {
            wallet_manager,
            ledger,
            auth_manager,
        }
    }
}

#[cfg(feature = "quic")]
#[async_trait::async_trait]
impl gquic::server::handler::ConnectionHandler for QuicGrpcHandler {
    async fn handle_connection(
        &self,
        connection: gquic::server::NewConnection,
        _config: Arc<gquic::server::QuicServerConfig>,
    ) -> Result<()> {
        let remote_addr = connection.connection.remote_address();
        info!("🔗 New QUIC connection from {}", remote_addr);

        // Handle incoming bidirectional streams (gRPC requests)
        while let Ok((mut send, mut recv)) = connection.bi_streams.accept().await {
            let wallet_manager = self.wallet_manager.clone();
            let ledger = self.ledger.clone();
            let auth_manager = self.auth_manager.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_grpc_stream(send, recv, wallet_manager, ledger, auth_manager).await {
                    error!("Error handling gRPC stream: {}", e);
                }
            });
        }

        info!("🔌 QUIC connection from {} closed", remote_addr);
        Ok(())
    }
}

#[cfg(feature = "quic")]
async fn handle_grpc_stream(
    mut send: gquic::SendStream,
    mut recv: gquic::RecvStream,
    wallet_manager: Arc<WalletManager>,
    ledger: Arc<LedgerStore>,
    auth_manager: Arc<AuthManager>,
) -> Result<()> {
    // Read gRPC request from QUIC stream
    let request_data = recv.read_to_end(10 * 1024 * 1024).await?; // 10MB max

    // Parse gRPC request (simplified - would need proper gRPC frame parsing)
    let response_data = process_grpc_request(
        &request_data,
        wallet_manager,
        ledger,
        auth_manager,
    ).await?;

    // Send gRPC response back over QUIC
    send.write_all(&response_data).await?;
    send.finish().await?;

    Ok(())
}

#[cfg(feature = "quic")]
async fn process_grpc_request(
    _request_data: &[u8],
    _wallet_manager: Arc<WalletManager>,
    _ledger: Arc<LedgerStore>,
    _auth_manager: Arc<AuthManager>,
) -> Result<Vec<u8>> {
    // TODO: Implement proper gRPC-over-QUIC message parsing
    // This would involve:
    // 1. Parsing gRPC frame headers
    // 2. Deserializing protobuf messages
    // 3. Calling appropriate wallet service methods
    // 4. Serializing responses back to gRPC format
    
    // For now, return a simple success response
    Ok(b"QUIC gRPC response".to_vec())
}

/// High-level QUIC client for walletd-to-walletd and walletd-to-ghostd communication
pub struct WalletdQuicClient {
    #[cfg(feature = "quic")]
    client: QuicClient,
    #[cfg(feature = "quic")]
    pool: gquic::ConnectionPool,
    server_name: String,
}

impl WalletdQuicClient {
    #[cfg(feature = "quic")]
    pub fn new(server_name: String) -> Result<Self> {
        let config = gquic::client::QuicClientConfig::builder()
            .server_name(server_name.clone())
            .with_alpn("ghostchain-v1")
            .with_alpn("grpc")
            .with_alpn("walletd")
            .max_idle_timeout(30_000)
            .enable_0rtt(true)
            .build();

        let client = gquic::client::QuicClient::new(config)?;
        let pool = gquic::ConnectionPool::new(gquic::PoolConfig::default());

        Ok(Self { 
            client, 
            pool,
            server_name,
        })
    }

    #[cfg(not(feature = "quic"))]
    pub fn new(server_name: String) -> Result<Self> {
        warn!("⚠️  QUIC client not available. Compile with --features quic");
        Ok(Self { server_name })
    }

    /// Send a gRPC request to another walletd instance
    #[cfg(feature = "quic")]
    pub async fn send_grpc_request(
        &self,
        addr: std::net::SocketAddr,
        request_data: &[u8],
    ) -> Result<Vec<u8>> {
        // Get or create connection
        let conn = match self.pool.get_connection(addr).await {
            Some(conn) => conn,
            None => {
                let conn = self.client.connect(addr).await?;
                self.pool.return_connection(addr, conn.clone()).await;
                conn
            }
        };

        // Open bidirectional stream
        let mut stream = self.client.open_bi_stream(&conn).await?;
        
        // Send gRPC request (with proper framing in production)
        stream.write_all(request_data).await?;
        stream.finish().await?;
        
        // Read gRPC response
        let response = stream.read_to_end(10 * 1024 * 1024).await?; // 10MB max
        Ok(response)
    }

    #[cfg(not(feature = "quic"))]
    pub async fn send_grpc_request(
        &self,
        _addr: std::net::SocketAddr,
        _request_data: &[u8],
    ) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("QUIC not enabled - compile with --features quic"))
    }

    /// Connect to GhostD for blockchain operations
    pub async fn connect_to_ghostd(&self, ghostd_addr: std::net::SocketAddr) -> Result<()> {
        #[cfg(feature = "quic")]
        {
            info!("🔗 Connecting to GhostD via QUIC at {}", ghostd_addr);
            let _conn = self.client.connect(ghostd_addr).await?;
            info!("✅ Connected to GhostD via QUIC");
            Ok(())
        }
        #[cfg(not(feature = "quic"))]
        {
            warn!("⚠️  QUIC not enabled, cannot connect to GhostD via QUIC");
            Err(anyhow::anyhow!("QUIC not enabled"))
        }
    }
}

/// Create a QUIC client for communicating with other walletd instances
pub fn create_walletd_client(server_name: String) -> Result<WalletdQuicClient> {
    WalletdQuicClient::new(server_name)
}

/// Check if QUIC support is available in this build
pub fn is_quic_enabled() -> bool {
    cfg!(feature = "quic")
}

/// Check if enhanced crypto support is available in this build
pub fn is_enhanced_crypto_enabled() -> bool {
    cfg!(feature = "enhanced-crypto")
}


