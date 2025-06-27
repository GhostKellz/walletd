use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};
use tracing::info;

use crate::config::Config;
use crate::wallet::WalletManager;
use crate::ledger::LedgerStore;

// Generated protobuf code will go here
pub mod walletd {
    tonic::include_proto!("walletd");
}

use walletd::{
    wallet_service_server::{WalletService, WalletServiceServer},
    GenerateZidRequest, GenerateZidResponse,
    SignTransactionRequest, SignTransactionResponse,
    GetAddressRequest, GetAddressResponse,
    GetBalanceRequest, GetBalanceResponse,
    RecoverWalletRequest, RecoverWalletResponse,
    VerifySignatureRequest, VerifySignatureResponse,
    ListWalletsRequest, ListWalletsResponse,
    CreateWalletRequest as GrpcCreateWalletRequest,
    CreateWalletResponse,
    SendTransactionRequest as GrpcSendTransactionRequest,
    SendTransactionResponse,
    GetTransactionRequest, GetTransactionResponse,
    WalletInfo, TransactionInfo, BalanceInfo,
};

pub struct GrpcServer {
    config: Config,
    wallet_manager: Arc<WalletManager>,
    ledger: Arc<LedgerStore>,
}

impl GrpcServer {
    pub fn new(
        config: Config,
        wallet_manager: Arc<WalletManager>,
        ledger: Arc<LedgerStore>,
    ) -> Self {
        Self {
            config,
            wallet_manager,
            ledger,
        }
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = self.config.grpc_bind_address.parse()?;
        let service = WalletServiceServer::new(WalletServiceImpl {
            wallet_manager: self.wallet_manager,
            ledger: self.ledger,
        });

        info!("🔌 gRPC server starting on {}", addr);

        Server::builder()
            .add_service(service)
            .serve(addr)
            .await?;

        Ok(())
    }
}

struct WalletServiceImpl {
    wallet_manager: Arc<WalletManager>,
    ledger: Arc<LedgerStore>,
}

#[tonic::async_trait]
impl WalletService for WalletServiceImpl {
    async fn generate_zid(
        &self,
        request: Request<GenerateZidRequest>,
    ) -> Result<Response<GenerateZidResponse>, Status> {
        let req = request.into_inner();
        
        // Create wallet using passphrase
        let create_request = crate::wallet::CreateWalletRequest {
            name: req.name.unwrap_or_else(|| "Generated Wallet".to_string()),
            account_type: Some("ed25519".to_string()),
            passphrase: Some(req.passphrase),
            network: None,
        };

        match self.wallet_manager.create_wallet(create_request).await {
            Ok(wallet) => {
                let response = GenerateZidResponse {
                    success: true,
                    wallet_id: wallet.id,
                    address: wallet.address,
                    public_key: wallet.public_key,
                    qid: "".to_string(), // TODO: Calculate QID
                    domain: None,
                    error_message: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = GenerateZidResponse {
                    success: false,
                    wallet_id: String::new(),
                    address: String::new(),
                    public_key: String::new(),
                    qid: String::new(),
                    domain: None,
                    error_message: Some(e.to_string()),
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn sign_transaction(
        &self,
        request: Request<SignTransactionRequest>,
    ) -> Result<Response<SignTransactionResponse>, Status> {
        let req = request.into_inner();
        
        let send_request = crate::wallet::SendTransactionRequest {
            from_wallet_id: req.wallet_id,
            to_address: req.to_address,
            amount: req.amount,
            token_address: req.token_address,
            gas_limit: req.gas_limit.map(|g| g as u64),
            gas_price: req.gas_price,
            data: req.data,
            passphrase: req.passphrase,
        };

        match self.wallet_manager.send_transaction(send_request).await {
            Ok(signed_tx) => {
                let response = SignTransactionResponse {
                    success: true,
                    transaction_id: signed_tx.unsigned_tx.id,
                    signed_data: signed_tx.signed_data,
                    transaction_hash: signed_tx.tx_hash,
                    error_message: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = SignTransactionResponse {
                    success: false,
                    transaction_id: String::new(),
                    signed_data: String::new(),
                    transaction_hash: String::new(),
                    error_message: Some(e.to_string()),
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn get_address(
        &self,
        request: Request<GetAddressRequest>,
    ) -> Result<Response<GetAddressResponse>, Status> {
        let req = request.into_inner();
        
        match self.wallet_manager.get_wallet(&req.wallet_id).await {
            Ok(wallet) => {
                let response = GetAddressResponse {
                    success: true,
                    address: wallet.address,
                    public_key: wallet.public_key,
                    qid: "".to_string(), // TODO: Calculate QID
                    domain: None,
                    error_message: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = GetAddressResponse {
                    success: false,
                    address: String::new(),
                    public_key: String::new(),
                    qid: String::new(),
                    domain: None,
                    error_message: Some(e.to_string()),
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn get_balance(
        &self,
        request: Request<GetBalanceRequest>,
    ) -> Result<Response<GetBalanceResponse>, Status> {
        let req = request.into_inner();
        
        match self.wallet_manager.get_wallet_balances(&req.wallet_id).await {
            Ok(balances) => {
                let balance_infos: Vec<BalanceInfo> = balances.into_iter().map(|b| BalanceInfo {
                    token_symbol: b.token_symbol,
                    balance: b.balance,
                    decimals: b.decimals,
                    token_address: b.token_address.unwrap_or_default(),
                }).collect();

                let response = GetBalanceResponse {
                    success: true,
                    balances: balance_infos,
                    error_message: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = GetBalanceResponse {
                    success: false,
                    balances: vec![],
                    error_message: Some(e.to_string()),
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn recover_wallet(
        &self,
        request: Request<RecoverWalletRequest>,
    ) -> Result<Response<RecoverWalletResponse>, Status> {
        let req = request.into_inner();
        
        let import_data = if let Some(mnemonic) = req.mnemonic {
            crate::wallet::WalletImportData::Mnemonic {
                mnemonic,
                derivation_path: req.derivation_path,
                account_type: req.account_type.unwrap_or_else(|| "ed25519".to_string()),
            }
        } else if let Some(private_key) = req.private_key {
            crate::wallet::WalletImportData::PrivateKey {
                private_key,
                account_type: req.account_type.unwrap_or_else(|| "ed25519".to_string()),
            }
        } else if let Some(passphrase) = req.passphrase {
            crate::wallet::WalletImportData::Passphrase { passphrase }
        } else {
            return Ok(Response::new(RecoverWalletResponse {
                success: false,
                wallet_id: String::new(),
                address: String::new(),
                error_message: Some("No recovery method provided".to_string()),
            }));
        };

        match self.wallet_manager.import_wallet(req.name, import_data).await {
            Ok(wallet) => {
                let response = RecoverWalletResponse {
                    success: true,
                    wallet_id: wallet.id,
                    address: wallet.address,
                    error_message: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = RecoverWalletResponse {
                    success: false,
                    wallet_id: String::new(),
                    address: String::new(),
                    error_message: Some(e.to_string()),
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn verify_signature(
        &self,
        request: Request<VerifySignatureRequest>,
    ) -> Result<Response<VerifySignatureResponse>, Status> {
        let req = request.into_inner();
        
        // Decode hex strings
        let public_key = match hex::decode(&req.public_key) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut array = [0u8; 32];
                array.copy_from_slice(&bytes);
                array
            }
            _ => {
                return Ok(Response::new(VerifySignatureResponse {
                    success: false,
                    valid: false,
                    error_message: Some("Invalid public key format".to_string()),
                }));
            }
        };

        let signature = match hex::decode(&req.signature) {
            Ok(bytes) if bytes.len() == 64 => {
                let mut array = [0u8; 64];
                array.copy_from_slice(&bytes);
                array
            }
            _ => {
                return Ok(Response::new(VerifySignatureResponse {
                    success: false,
                    valid: false,
                    error_message: Some("Invalid signature format".to_string()),
                }));
            }
        };

        let data = match hex::decode(&req.data) {
            Ok(bytes) => bytes,
            Err(_) => req.data.into_bytes(), // Try as raw bytes if not hex
        };

        // Verify signature
        let signer = crate::signer::TransactionSigner::new();
        match signer.verify_signature(&data, &signature, &public_key) {
            Ok(valid) => {
                let response = VerifySignatureResponse {
                    success: true,
                    valid,
                    error_message: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = VerifySignatureResponse {
                    success: false,
                    valid: false,
                    error_message: Some(e.to_string()),
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn list_wallets(
        &self,
        _request: Request<ListWalletsRequest>,
    ) -> Result<Response<ListWalletsResponse>, Status> {
        match self.wallet_manager.list_wallets().await {
            Ok(wallets) => {
                let wallet_infos: Vec<WalletInfo> = wallets.into_iter().map(|w| WalletInfo {
                    id: w.id,
                    name: w.name,
                    address: w.address,
                    public_key: w.public_key,
                    account_type: w.account_type,
                    network: w.network,
                    balance: w.balance.unwrap_or_else(|| "0".to_string()),
                    created_at: w.created_at.timestamp(),
                }).collect();

                let response = ListWalletsResponse {
                    success: true,
                    wallets: wallet_infos,
                    error_message: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = ListWalletsResponse {
                    success: false,
                    wallets: vec![],
                    error_message: Some(e.to_string()),
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn create_wallet(
        &self,
        request: Request<GrpcCreateWalletRequest>,
    ) -> Result<Response<CreateWalletResponse>, Status> {
        let req = request.into_inner();
        
        let create_request = crate::wallet::CreateWalletRequest {
            name: req.name,
            account_type: req.account_type,
            passphrase: req.passphrase,
            network: req.network,
        };

        match self.wallet_manager.create_wallet(create_request).await {
            Ok(wallet) => {
                let response = CreateWalletResponse {
                    success: true,
                    wallet: Some(WalletInfo {
                        id: wallet.id,
                        name: wallet.name,
                        address: wallet.address,
                        public_key: wallet.public_key,
                        account_type: wallet.account_type,
                        network: wallet.network,
                        balance: wallet.balance.unwrap_or_else(|| "0".to_string()),
                        created_at: wallet.created_at.timestamp(),
                    }),
                    error_message: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = CreateWalletResponse {
                    success: false,
                    wallet: None,
                    error_message: Some(e.to_string()),
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn send_transaction(
        &self,
        request: Request<GrpcSendTransactionRequest>,
    ) -> Result<Response<SendTransactionResponse>, Status> {
        let req = request.into_inner();
        
        let send_request = crate::wallet::SendTransactionRequest {
            from_wallet_id: req.from_wallet_id,
            to_address: req.to_address,
            amount: req.amount,
            token_address: req.token_address,
            gas_limit: req.gas_limit.map(|g| g as u64),
            gas_price: req.gas_price,
            data: req.data,
            passphrase: req.passphrase,
        };

        match self.wallet_manager.send_transaction(send_request).await {
            Ok(signed_tx) => {
                let response = SendTransactionResponse {
                    success: true,
                    transaction_id: signed_tx.unsigned_tx.id,
                    transaction_hash: signed_tx.tx_hash,
                    error_message: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = SendTransactionResponse {
                    success: false,
                    transaction_id: String::new(),
                    transaction_hash: String::new(),
                    error_message: Some(e.to_string()),
                };
                Ok(Response::new(response))
            }
        }
    }

    async fn get_transaction(
        &self,
        request: Request<GetTransactionRequest>,
    ) -> Result<Response<GetTransactionResponse>, Status> {
        let req = request.into_inner();
        
        match self.wallet_manager.get_transaction(&req.transaction_id).await {
            Ok(tx) => {
                let response = GetTransactionResponse {
                    success: true,
                    transaction: Some(TransactionInfo {
                        id: tx.id,
                        wallet_id: tx.wallet_id,
                        tx_hash: tx.tx_hash.unwrap_or_default(),
                        from_address: tx.from_address,
                        to_address: tx.to_address,
                        amount: tx.amount,
                        token_address: tx.token_address.unwrap_or_default(),
                        status: format!("{:?}", tx.status),
                        block_number: tx.block_number.unwrap_or(0),
                        created_at: tx.created_at.timestamp(),
                    }),
                    error_message: None,
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                let response = GetTransactionResponse {
                    success: false,
                    transaction: None,
                    error_message: Some(e.to_string()),
                };
                Ok(Response::new(response))
            }
        }
    }
}
