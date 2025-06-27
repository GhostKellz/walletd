#ifndef ZSIG_FFI_H
#define ZSIG_FFI_H

#include <stdint.h>
#include <stdbool.h>
#include "zcrypto_ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

// zsig context for maintaining state
typedef struct zsig_context zsig_context_t;

// MultiSig support
typedef struct {
    zcrypto_keypair_t keypair;
    uint8_t hmac_key[32];
    bool has_hmac_key;
} zsig_multisig_keypair_t;

// Authenticated signature (signature + HMAC)
typedef struct {
    zcrypto_signature_t signature;
    uint8_t hmac_tag[32];
    bool has_hmac;
} zsig_authenticated_signature_t;

// Context management
zsig_context_t* zsig_context_new(void);
void zsig_context_free(zsig_context_t* ctx);

// Multi-algorithm signing
zcrypto_error_t zsig_multisig_generate_keypair(zsig_context_t* ctx, zcrypto_algorithm_t algorithm, zsig_multisig_keypair_t* out_keypair);
zcrypto_error_t zsig_multisig_generate_keypair_from_seed(zsig_context_t* ctx, zcrypto_algorithm_t algorithm, const uint8_t* seed, size_t seed_len, zsig_multisig_keypair_t* out_keypair);
zcrypto_error_t zsig_multisig_sign(zsig_context_t* ctx, const zsig_multisig_keypair_t* keypair, const uint8_t* message, size_t message_len, zsig_authenticated_signature_t* out_signature);
zcrypto_error_t zsig_multisig_verify(zsig_context_t* ctx, zcrypto_algorithm_t algorithm, const zcrypto_public_key_t* public_key, const uint8_t* message, size_t message_len, const zsig_authenticated_signature_t* signature, bool* out_valid);

// HMAC authenticated signing
zcrypto_error_t zsig_sign_with_hmac(zsig_context_t* ctx, const zsig_multisig_keypair_t* keypair, const uint8_t* message, size_t message_len, const uint8_t* hmac_key, zsig_authenticated_signature_t* out_signature);
zcrypto_error_t zsig_verify_with_hmac(zsig_context_t* ctx, zcrypto_algorithm_t algorithm, const zcrypto_public_key_t* public_key, const uint8_t* message, size_t message_len, const zsig_authenticated_signature_t* signature, const uint8_t* hmac_key, bool* out_valid);

// Batch operations
zcrypto_error_t zsig_batch_sign(zsig_context_t* ctx, const zsig_multisig_keypair_t* keypair, const uint8_t** messages, const size_t* message_lens, size_t count, zsig_authenticated_signature_t* out_signatures);
zcrypto_error_t zsig_batch_verify(zsig_context_t* ctx, zcrypto_algorithm_t algorithm, const zcrypto_public_key_t* public_key, const uint8_t** messages, const size_t* message_lens, const zsig_authenticated_signature_t* signatures, size_t count, bool* out_results);

#ifdef __cplusplus
}
#endif

#endif // ZSIG_FFI_H