#ifndef ZCRYPTO_FFI_H
#define ZCRYPTO_FFI_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Algorithm types
typedef enum {
    ZCRYPTO_ALG_ED25519 = 0,
    ZCRYPTO_ALG_SECP256K1 = 1,
    ZCRYPTO_ALG_SECP256R1 = 2,
} zcrypto_algorithm_t;

// Error codes
typedef enum {
    ZCRYPTO_OK = 0,
    ZCRYPTO_ERR_INVALID_PARAM = -1,
    ZCRYPTO_ERR_CRYPTO_FAILED = -2,
    ZCRYPTO_ERR_UNSUPPORTED = -3,
    ZCRYPTO_ERR_OUT_OF_MEMORY = -4,
} zcrypto_error_t;

// Key structures
typedef struct {
    uint8_t bytes[32];
} zcrypto_public_key_t;

typedef struct {
    uint8_t bytes[64];  // Ed25519 uses 64-byte private keys
} zcrypto_private_key_t;

typedef struct {
    uint8_t bytes[64];
} zcrypto_signature_t;

typedef struct {
    zcrypto_private_key_t private_key;
    zcrypto_public_key_t public_key;
    zcrypto_algorithm_t algorithm;
} zcrypto_keypair_t;

// Core functions
zcrypto_error_t zcrypto_generate_keypair(zcrypto_algorithm_t algorithm, zcrypto_keypair_t* out_keypair);
zcrypto_error_t zcrypto_generate_keypair_from_seed(zcrypto_algorithm_t algorithm, const uint8_t* seed, size_t seed_len, zcrypto_keypair_t* out_keypair);
zcrypto_error_t zcrypto_sign(const zcrypto_keypair_t* keypair, const uint8_t* message, size_t message_len, zcrypto_signature_t* out_signature);
zcrypto_error_t zcrypto_verify(zcrypto_algorithm_t algorithm, const zcrypto_public_key_t* public_key, const uint8_t* message, size_t message_len, const zcrypto_signature_t* signature, bool* out_valid);

// HMAC functions
zcrypto_error_t zcrypto_hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t* out_mac);
zcrypto_error_t zcrypto_hmac_verify_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, const uint8_t* mac, bool* out_valid);

// Key derivation
zcrypto_error_t zcrypto_derive_key_from_passphrase(const char* passphrase, const uint8_t* salt, size_t salt_len, uint8_t* out_key);

// Utility functions
void zcrypto_secure_zero(void* ptr, size_t len);
zcrypto_error_t zcrypto_random_bytes(uint8_t* out_bytes, size_t len);

#ifdef __cplusplus
}
#endif

#endif // ZCRYPTO_FFI_H