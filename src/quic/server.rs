use std::sync::Arc;
use anyhow::Result;
use gquic::prelude::*;
use tracing::{info, error};

use crate::config::Config;
use crate::wallet::WalletManager;
use crate::ledger::LedgerStore;
use crate::auth::AuthManager;
use crate::quic::handler::WalletQuicHandler;

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

    pub async fn serve(self) -> Result<()> {
        let bind_addr = self.config.quic.bind_address.parse()?;
        
        // Create handler
        let handler = WalletQuicHandler::new(
            self.wallet_manager,
            self.ledger,
            self.auth_manager,
        );

        // Build QUIC server configuration
        let mut server_builder = gquic::server::QuicServer::builder()
            .bind(bind_addr);

        // Configure TLS
        if self.config.quic.tls.use_self_signed {
            server_builder = server_builder.with_self_signed_cert()?;
        } else {
            server_builder = server_builder.with_tls_files(
                &self.config.quic.tls.cert_path,
                &self.config.quic.tls.key_path,
            )?;
        }

        // Configure ALPN protocols
        for protocol in &self.config.quic.alpn_protocols {
            server_builder = server_builder.with_alpn(protocol);
        }

        // Configure stream limits and timeouts
        let server = server_builder
            .max_concurrent_bidi_streams(self.config.quic.max_concurrent_streams)
            .max_concurrent_uni_streams(self.config.quic.max_concurrent_streams)
            .max_idle_timeout(self.config.quic.max_idle_timeout)
            .with_handler(Arc::new(handler))
            .build()?;

        info!("🚀 QUIC server starting on {}", bind_addr);
        info!("   ALPN protocols: {:?}", self.config.quic.alpn_protocols);
        info!("   0-RTT: {}", if self.config.quic.enable_0rtt { "enabled" } else { "disabled" });

        // Run the server
        server.run().await.map_err(|e| {
            error!("QUIC server error: {}", e);
            e
        })
    }
}