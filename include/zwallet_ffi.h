#ifndef ZWALLET_FFI_H
#define ZWALLET_FFI_H

#include <stdint.h>
#include <stdbool.h>
#include "zcrypto_ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

// zwallet context
typedef struct zwallet_context zwallet_context_t;

// Account types
typedef enum {
    ZWALLET_ACCOUNT_ED25519 = 0,
    ZWALLET_ACCOUNT_SECP256K1 = 1,
    ZWALLET_ACCOUNT_SECP256R1 = 2,
} zwallet_account_type_t;

// Wallet account structure
typedef struct {
    uint8_t address[32];
    zcrypto_public_key_t public_key;
    zwallet_account_type_t account_type;
    char zns_domain[256];  // Optional ZNS domain
    bool has_zns_domain;
} zwallet_account_t;

// HD wallet support
typedef struct {
    uint8_t chain_code[32];
    uint32_t index;
    uint32_t depth;
    char path[128];  // e.g., "m/44'/1337'/0'/0/0"
} zwallet_hd_info_t;

// Balance information
typedef struct {
    char token_symbol[32];
    char balance[64];  // String representation to handle large numbers
    uint8_t decimals;
    uint8_t token_address[32];
    bool is_native_token;
} zwallet_balance_t;

// Context management
zwallet_context_t* zwallet_context_new(void);
void zwallet_context_free(zwallet_context_t* ctx);

// Account creation
zcrypto_error_t zwallet_create_account(zwallet_context_t* ctx, const uint8_t* seed, size_t seed_len, zwallet_account_type_t account_type, zwallet_account_t* out_account);
zcrypto_error_t zwallet_create_account_from_passphrase(zwallet_context_t* ctx, const char* passphrase, zwallet_account_type_t account_type, zwallet_account_t* out_account);
zcrypto_error_t zwallet_derive_account_hd(zwallet_context_t* ctx, const uint8_t* seed, size_t seed_len, const char* derivation_path, zwallet_account_type_t account_type, zwallet_account_t* out_account, zwallet_hd_info_t* out_hd_info);

// Account import
zcrypto_error_t zwallet_import_private_key(zwallet_context_t* ctx, const uint8_t* private_key, size_t key_len, zwallet_account_type_t account_type, zwallet_account_t* out_account);
zcrypto_error_t zwallet_import_mnemonic(zwallet_context_t* ctx, const char* mnemonic, const char* passphrase, zwallet_account_type_t account_type, zwallet_account_t* out_account);

// Balance operations
zcrypto_error_t zwallet_get_balance(zwallet_context_t* ctx, const zwallet_account_t* account, const char* rpc_endpoint, zwallet_balance_t* out_balance);
zcrypto_error_t zwallet_get_token_balance(zwallet_context_t* ctx, const zwallet_account_t* account, const uint8_t* token_address, const char* rpc_endpoint, zwallet_balance_t* out_balance);

// Transaction building
typedef struct {
    uint8_t from[32];
    uint8_t to[32];
    char amount[64];
    uint8_t token_address[32];
    bool is_token_transfer;
    uint64_t gas_limit;
    char gas_price[32];
    uint64_t nonce;
    uint8_t* data;
    size_t data_len;
    uint64_t chain_id;
} zwallet_transaction_t;

zcrypto_error_t zwallet_build_transaction(zwallet_context_t* ctx, const zwallet_transaction_t* tx_params, uint8_t** out_tx_data, size_t* out_tx_len);
zcrypto_error_t zwallet_estimate_gas(zwallet_context_t* ctx, const zwallet_transaction_t* tx_params, const char* rpc_endpoint, uint64_t* out_gas_limit);

// ZNS/ENS integration
zcrypto_error_t zwallet_resolve_domain(zwallet_context_t* ctx, const char* domain, const char* resolver_endpoint, uint8_t* out_address);
zcrypto_error_t zwallet_register_domain(zwallet_context_t* ctx, const zwallet_account_t* account, const char* domain, const char* registrar_endpoint);

#ifdef __cplusplus
}
#endif

#endif // ZWALLET_FFI_H