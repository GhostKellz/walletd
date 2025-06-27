# 🔐 walletd: GhostChain Secure Wallet Daemon

`walletd` is a secure, non-custodial wallet backend for the GhostChain ecosystem. Designed## 💻 CLI Usage

### Cargo Aliases (Convenience Commands)

For easier development and usage, the following cargo aliases are available:

```bash
# Quick daemon commands
cargo walletd --help                    # Show walletd help
cargo daemon                            # Start daemon (basic)
cargo start                             # Start with config file
cargo dev                               # Start in debug mode with config
cargo bg                                # Start in background

# Development
cargo check-all                         # Run check, clippy, and test
```

### Start the Daemon

```bash
# Start in foreground
walletd start
# OR using alias
cargo daemon

# Start in background
walletd start --background
# OR using alias
cargo bg

# With custom config
walletd --config ./custom-config.toml start
# OR using alias (uses walletd.toml by default)
cargo startust principles, ZID-based authentication, and multi-chain support, it enables users, apps, and agents to securely generate identities, sign transactions, and interface with smart contracts — without ever exposing private keys.

## 🚀 Quick Start

### Prerequisites

- Rust `1.75+`
- SQLite3
- (Optional) Zig `0.12+` for FFI features

### Installation

```bash
# Clone the repository
git clone https://github.com/ghostkellz/walletd
cd walletd

# Build the project
cargo build --release

# Run the daemon
./target/release/walletd start
```

### Configuration

Create a `walletd.toml` configuration file:

```toml
# Network settings
[network]
chain_id = 1337
network_name = "ghostchain"
default_gas_limit = 21000
default_gas_price = 20000000000

# Security settings
[security]
require_auth = true
session_timeout_seconds = 3600
max_concurrent_sessions = 100

# Feature flags
[features]
enable_evm = true
enable_cli = true

# Server endpoints
grpc_bind_address = "127.0.0.1:50051"
api_bind_address = "127.0.0.1:8080"
ghostd_endpoint = "http://127.0.0.1:50052" 

# Database
database_path = "walletd.db"
```

---

## 🎯 Core Responsibilities

* 🔑 Securely generate and manage ZID-based identities
* ✍️ Sign GhostChain and EVM transactions via `zsig`
* 🔐 Handle passphrase-based key derivation (no seed phrases required)
* 🔁 Expose gRPC and REST API for secure wallet operations
* 🌐 Integrate with ZNS, ENS, CNS for domain-based signing
* 📦 Interface with `zledger` for transaction history and audit

---

## 🧠 Architecture

```
walletd/
├── src/
│   ├── main.rs          # Daemon entrypoint + CLI
│   ├── api.rs           # REST API endpoints
│   ├── grpc.rs          # gRPC service implementation
│   ├── auth.rs          # ZID authentication manager
│   ├── wallet.rs        # Wallet management + operations
│   ├── signer.rs        # Transaction signing via zsig
│   ├── ledger.rs        # SQLite-based transaction ledger
│   ├── ffi.rs           # Zig FFI interfaces (RealID, ZWallet)
│   ├── config.rs        # Configuration management
│   ├── cli.rs           # Command-line interface
│   └── error.rs         # Centralized error handling
├── proto/walletd.proto  # gRPC schema definitions
├── migrations/          # Database migrations
├── build.rs             # Build script for protobuf
└── walletd.toml         # Example configuration
```

---

## 📡 API Endpoints

### REST API (Port 8080)

#### Wallets
- `GET /wallets` - List all wallets
- `POST /wallets` - Create new wallet
- `GET /wallets/{id}` - Get wallet details
- `DELETE /wallets/{id}` - Delete wallet
- `GET /wallets/{id}/balances` - Get wallet balances
- `GET /wallets/{id}/transactions` - Get transaction history
- `POST /wallets/import` - Import wallet

#### Transactions
- `POST /transactions` - Send transaction
- `GET /transactions/{id}` - Get transaction details
- `POST /transactions/{id}/status` - Update transaction status

#### Signing & Broadcasting  
- `POST /sign` - Sign transaction
- `POST /sign/verify` - Verify signature
- `POST /broadcast` - Broadcast signed transaction

#### Authentication
- `POST /auth/challenge` - Create authentication challenge
- `POST /auth/login` - Login with challenge response
- `POST /auth/logout` - Logout session
- `GET /auth/session` - Get session info

### gRPC API (Port 50051)

* `GenerateZID` – Create identity from passphrase
* `SignTransaction` – Sign GhostChain or EVM tx
* `GetAddress` – Return public key, QID, and ZNS domain (if exists)
* `RecoverWallet` – Restore from mnemonic/passphrase
* `VerifySignature` – Stateless signature validation
* `GetBalance` – View ZLedger-based asset balances

> Can be accessed locally or over QUIC via Wraith + GhostBridge.

---

## � CLI Usage

### Start the Daemon

```bash
# Start in foreground
walletd start

# Start in background
walletd start --background

# With custom config
walletd start --config ./custom-config.toml
```

### Wallet Management

```bash
# Create new wallet
walletd wallet create "My Wallet" --account-type ed25519

# Create wallet with passphrase
walletd wallet create "Secure Wallet" --passphrase

# List all wallets
walletd wallet list

# Show wallet details
walletd wallet show <wallet-id>

# Import wallet from private key
walletd wallet import "Imported Wallet" --private-key <hex-key>

# Import from passphrase
walletd wallet import "Passphrase Wallet" --passphrase <passphrase>

# Check balance
walletd wallet balance <wallet-id>

# Check token balance
walletd wallet balance <wallet-id> --token <token-address>

# Delete wallet
walletd wallet delete <wallet-id> --confirm
```

### Transaction Operations

```bash
# Send transaction
walletd transaction send \
  --from <wallet-id> \
  --to <recipient-address> \
  --amount 100.5 \
  --passphrase <passphrase>

# Send token transaction
walletd transaction send \
  --from <wallet-id> \
  --to <recipient-address> \
  --amount 50.0 \
  --token <token-address> \
  --passphrase <passphrase>

# Sign transaction (without broadcasting)
walletd transaction sign \
  --from <wallet-id> \
  --to <recipient-address> \
  --amount 25.0 \
  --passphrase <passphrase>

# Show transaction details
walletd transaction show <tx-id>

# List transactions for wallet
walletd transaction list <wallet-id> --limit 20

# Broadcast signed transaction
walletd transaction broadcast <signed-data>
```

### Authentication

```bash
# Generate identity from passphrase
walletd auth identity "my-secret-passphrase"

# Create authentication challenge
walletd auth challenge

# Login with challenge
walletd auth login <challenge-id> "my-secret-passphrase"

# Logout
walletd auth logout <session-id>

# Verify signature
walletd auth verify \
  --public-key <hex-pubkey> \
  --data <hex-data> \
  --signature <hex-signature>
```

---

## 🔐 Security Model

* **No private key storage**: Keys are derived from passphrases on-demand
* **ZID-based identities**: Deterministic Ed25519 keypairs from passphrases
* **Memory-only keys**: Private keys never touch disk
* **Session-based auth**: Time-limited authentication sessions
* **Challenge-response**: Secure login without password transmission
* **Hardware security**: Optional FIDO2/WebAuthn and TPM support (future)
* **Signature verification**: Stateless Ed25519 signature validation

---

## 💡 Integration Examples

### Web Application

```javascript
// Create wallet
const response = await fetch('http://localhost:8080/wallets', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'Web Wallet',
    account_type: 'ed25519',
    passphrase: 'user-provided-passphrase'
  })
});

const wallet = await response.json();
console.log('Wallet created:', wallet.data);

// Send transaction
const txResponse = await fetch('http://localhost:8080/transactions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    from_wallet_id: wallet.data.id,
    to_address: '0x742d35Cc6634C0532925a3b8D0A9e4d1b6b5c9e0',
    amount: '1.5',
    passphrase: 'user-provided-passphrase'
  })
});
```

### gRPC Client (Rust)

```rust
use tonic::Request;
use walletd::walletd::{wallet_service_client::WalletServiceClient, CreateWalletRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = WalletServiceClient::connect("http://127.0.0.1:50051").await?;
    
    let request = Request::new(CreateWalletRequest {
        name: "gRPC Wallet".to_string(),
        account_type: Some("ed25519".to_string()),
        passphrase: Some("secure-passphrase".to_string()),
        network: None,
    });
    
    let response = client.create_wallet(request).await?;
    println!("Wallet created: {:?}", response.into_inner());
    
    Ok(())
}
```

### Python Client

```python
import requests
import json

# Create wallet
wallet_data = {
    "name": "Python Wallet",
    "account_type": "ed25519",
    "passphrase": "my-secure-passphrase"
}

response = requests.post("http://localhost:8080/wallets", json=wallet_data)
wallet = response.json()
print(f"Wallet created: {wallet['data']['id']}")

# Send transaction  
tx_data = {
    "from_wallet_id": wallet['data']['id'],
    "to_address": "0x742d35Cc6634C0532925a3b8D0A9e4d1b6b5c9e0",
    "amount": "2.5",
    "passphrase": "my-secure-passphrase"
}

tx_response = requests.post("http://localhost:8080/transactions", json=tx_data)
transaction = tx_response.json()
print(f"Transaction sent: {transaction['data']['transaction_hash']}")
```

---

## 🌐 Used In

* **`ghostd`** → Receives signed txs via RPC
* **`ghostsite`** → Web5 profile and domain wallet auth  
* **`znsd` / `cns`** → Verifies ZID identity and domain ownership
* **`Jarvis`** → AI agent integration for txs, contract automation
* **Mobile Apps** → Secure wallet backend for mobile wallets
* **Web Browsers** → Extension or PWA wallet functionality

---

## 🧩 Identity System (ZID)

* **Passphrase → Private Key** (Ed25519)
* **Public Key → QID** (stateless IPv6)
* **Domain → Wallet mapping** (via ZNS/CNS/ENS)
* **Supports signing, challenge-response, and OIDC login flows**

### ZID Generation Example

```bash
# Generate identity
walletd auth identity "my-unique-passphrase"

# Output:
# Public Key: ed25519:A1B2C3D4E5F6...
# QID: fd00:a1b2:c3d4:e5f6::1
# Address: ghostchain:A1B2C3D4E5F6...
```

---

## ✅ Features

* 🔐 **ZID identity lifecycle** - Passphrase-based deterministic keys
* 🧾 **gRPC + REST APIs** - Multiple integration options  
* ⚙️ **Rust async runtime** - High-performance tokio-based architecture
* 📦 **FFI integration** - Optional Zig modules (RealID, ZWallet, ZCrypto)
* 🗄️ **SQLite ledger** - Local transaction history and audit trail
* 🌍 **Multi-chain support** - GhostChain native + EVM compatibility
* 🔒 **Session management** - Secure authentication with time-limited sessions
* 🧠 **AI agent ready** - Clean APIs for AI integration and orchestration

---

## 🔧 Development

### Build from Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/ghostkellz/walletd
cd walletd
cargo build --release

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- start
```

### Docker

```bash
# Build Docker image  
docker build -t walletd .

# Run with Docker
docker run -p 8080:8080 -p 50051:50051 -v $(pwd)/data:/data walletd

# With custom config
docker run -p 8080:8080 -p 50051:50051 -v $(pwd)/config:/config -v $(pwd)/data:/data walletd --config /config/walletd.toml
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`cargo test`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

---

## 📚 Documentation

- [API Documentation](./docs/api.md)
- [Configuration Guide](./docs/configuration.md)
- [Security Model](./docs/security.md)
- [Integration Examples](./docs/integration.md)
- [FFI Interface](./docs/ffi.md)

---

## 🤝 Ecosystem Integration

### GhostChain Components

- **GhostBridge** - gRPC interoperability layer
- **ZNS/CNS** - Domain name resolution
- **GhostD** - Blockchain node and validator
- **GhostSite** - Web5 application platform
- **Jarvis** - AI agent system

### External Integration

- **Ethereum** - EVM-compatible transaction signing
- **ENS** - Ethereum domain resolution  
- **Unstoppable Domains** - Web3 domain mapping
- **IPFS** - Decentralized storage
- **Wraith** - Privacy networking layer

---

## � License

MIT © GhostKellz

---

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/ghostkellz/walletd/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ghostkellz/walletd/discussions)
- **Documentation**: [docs.ghostchain.io](https://docs.ghostchain.io)
- **Community**: [Discord](https://discord.gg/ghostchain)

---

**walletd** — Your secure gateway to the GhostChain ecosystem 👻

