# Fix gquic and gcrypt Repository Dependencies

## Problem

Both `gquic` and `gcrypt` repositories have relative path dependencies that prevent them from being used as git dependencies in other projects like `walletd` and `ghostd`.

## Required Fixes

### 1. Fix gquic Repository

**Repository**: https://github.com/ghostkellz/gquic

**File**: `Cargo.toml`

**Change**:
```toml
# BEFORE:
gcrypt = { path = "../gcrypt", optional = true }

# AFTER:
gcrypt = { git = "https://github.com/ghostkellz/gcrypt", features = ["std", "rand_core"], optional = true }
```

### 2. Add Missing Features to gcrypt

**Repository**: https://github.com/ghostkellz/gcrypt

**File**: `Cargo.toml`

**Add to `[features]` section**:
```toml
# Cryptographic algorithm features needed by gquic and walletd
ed25519 = []
secp256k1 = []
blake3 = []
```

### 3. Create or Remove gquicd

**Option A**: Create the missing repository at `https://github.com/ghostkellz/gquicd`

**Option B**: Remove gquicd references from:
- gquic repository
- walletd Cargo.toml
- Any other dependent projects

## After Fixes

Once these changes are made, update walletd and ghostd to re-enable the dependencies:

**walletd/Cargo.toml**:
```toml
# Re-enable these lines:
gquic = { git = "https://github.com/ghostkellz/gquic", features = ["gcrypt-integration", "metrics"], optional = true }
gcrypt = { git = "https://github.com/ghostkellz/gcrypt", features = ["std", "rand_core", "ed25519", "secp256k1", "blake3"], optional = true }

# Re-enable features:
quic = ["gquic"]
enhanced-crypto = ["gcrypt"]
full-quic = ["quic", "enhanced-crypto"]
```

## Test Commands

After making the fixes:
```bash
# In walletd directory:
cargo check --features enhanced-crypto
cargo check --features quic  
cargo check --features full-quic
cargo build --release --features full-quic
```
