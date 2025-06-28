# QUIC Transport Integration for WalletD

This document describes the QUIC transport implementation in WalletD using the GQUIC library.

## Overview

WalletD now supports QUIC transport alongside traditional HTTP and gRPC protocols. QUIC provides:
- 0-RTT connection establishment
- Multiplexed streams without head-of-line blocking
- Built-in encryption with TLS 1.3
- Connection migration
- Better performance on lossy networks

## Architecture

### Transport Layers
1. **gRPC-over-QUIC**: Compatible with existing gRPC clients using ALPN "grpc"
2. **Custom Protocol**: Optimized walletd protocol using ALPN "walletd-v1"

### Stream Multiplexing
The custom protocol uses dedicated stream types:
- **Stream Type 0**: Control/Authentication
- **Stream Type 1**: Transaction operations
- **Stream Type 2**: Query operations
- **Stream Type 3**: Event notifications (server-push)

## Configuration

Add QUIC settings to your `walletd.toml`:

```toml
[quic]
enabled = true
bind_address = "0.0.0.0:9090"
alpn_protocols = ["grpc", "walletd-v1"]
max_concurrent_streams = 1000
max_idle_timeout = 30000
enable_0rtt = true

[quic.tls]
cert_path = "certs/walletd.crt"
key_path = "certs/walletd.key"
use_self_signed = true  # For development only
```

## Building with QUIC Support

QUIC is enabled by default. To build without QUIC:

```bash
cargo build --no-default-features --features evm
```

## Client Usage

### Using gRPC-over-QUIC
Existing gRPC clients can connect using QUIC by:
1. Specifying the QUIC endpoint (port 9090)
2. Using ALPN protocol "grpc"

### Using Custom Protocol
For optimal performance, use the custom "walletd-v1" protocol:

```rust
use walletd::quic::QuicClient;

let client = QuicClient::new("walletd.local".to_string())?;
let response = client.send_transaction(addr, &tx_data).await?;
```

## RealID Authentication

QUIC connections support RealID authentication through:
1. Client certificate verification (mTLS)
2. Custom authentication headers
3. Session token resumption with 0-RTT

## Performance Benefits

1. **Latency**: 0-RTT reduces connection setup time
2. **Throughput**: No head-of-line blocking improves parallel operations
3. **Reliability**: Automatic retransmission and congestion control
4. **Security**: Always encrypted with TLS 1.3

## Monitoring

Enable metrics to monitor QUIC performance:

```toml
[features]
enable_metrics = true
```

Metrics include:
- Active connections
- Stream utilization
- Latency measurements
- Error rates

## Migration Guide

To migrate from HTTP/gRPC to QUIC:

1. Update client configuration to use QUIC endpoint
2. Enable QUIC in walletd.toml
3. Test with both protocols running in parallel
4. Gradually migrate clients
5. Disable legacy protocols when ready

## Troubleshooting

### Common Issues

1. **Connection failures**: Check firewall allows UDP on port 9090
2. **Certificate errors**: Ensure proper TLS certificates are configured
3. **Performance issues**: Monitor stream concurrency and adjust limits

### Debug Logging

Enable debug logging for QUIC:

```bash
RUST_LOG=walletd::quic=debug,gquic=debug walletd
```

## Future Enhancements

- [ ] HTTP/3 support for web clients
- [ ] Advanced stream prioritization
- [ ] Multipath QUIC for redundancy
- [ ] Integration with hardware security modules