#ifndef EM_FILTER_CRYPTO_H
#define EM_FILTER_CRYPTO_H

#include <stddef.h>
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ed25519 identity + canonical byte forms, byte-identical to em_pop_crypto.erl.
 *
 * Key file layout: pub(32) || seed(32), raw bytes. libsodium's ed25519
 * "secret key" is 64 bytes = seed(32) || pub(32); it is derived on demand
 * with crypto_sign_seed_keypair(), never persisted directly.
 */

#define EM_PUBKEY_LEN 32
#define EM_SEED_LEN   32
#define EM_ID_LEN     16
#define EM_SIG_LEN    64

/* id = SHA-256(pubkey)[0:16]. out_id must have room for EM_ID_LEN bytes. */
void em_id_of(const unsigned char pub[EM_PUBKEY_LEN], unsigned char out_id[EM_ID_LEN]);

/*
 * Load pub/seed from "<key_dir>/node_ed25519.key" (created if absent).
 * Returns 0 on success, -1 on failure (I/O error).
 */
int em_crypto_load_or_create(const char *key_dir,
                              unsigned char out_pub[EM_PUBKEY_LEN],
                              unsigned char out_seed[EM_SEED_LEN]);

/*
 * canonical_identity = id || 0x00 || name (UTF-8).
 * Writes into out (caller-owned buffer of at least EM_ID_LEN + 1 + strlen(name)
 * bytes) and returns the byte length written.
 */
size_t em_canonical_identity(const unsigned char id[EM_ID_LEN], const char *name,
                              unsigned char *out, size_t out_cap);

/*
 * canonical_response(items): concatenation of one line per item:
 *   U(url) || 0x00 || T(title|label) || 0x00 || R(resume|value|description) || 0x0A
 * `items` must be a cJSON value (array, or anything else -> empty bytes).
 * Returns a heap-allocated buffer (caller must free()) and sets *out_len.
 * Returns NULL (and *out_len = 0) only on allocation failure.
 */
unsigned char *em_canonical_response(const cJSON *items, size_t *out_len);

/* sig must have room for EM_SIG_LEN bytes. */
void em_sign(unsigned char sig[EM_SIG_LEN], const unsigned char *msg, size_t mlen,
             const unsigned char seed[EM_SEED_LEN]);

/* Returns 1 if valid, 0 otherwise. */
int em_verify(const unsigned char *msg, size_t mlen,
              const unsigned char sig[EM_SIG_LEN], const unsigned char pub[EM_PUBKEY_LEN]);

/*
 * sign_response: signs canonical_response(items) with (pub, seed).
 * Writes base64 (standard, padded) signer_id and signature into caller-owned
 * buffers (out_signer_id_b64 needs >= 25 bytes, out_sig_b64 needs >= 89 bytes,
 * both NUL-terminated).
 */
void em_sign_response(const cJSON *items,
                       const unsigned char pub[EM_PUBKEY_LEN],
                       const unsigned char seed[EM_SEED_LEN],
                       char *out_signer_id_b64, size_t signer_id_cap,
                       char *out_sig_b64, size_t sig_cap);

/* base64 (standard, padded) encode/decode helpers, thin wrappers over libsodium. */
size_t em_b64_encode(const unsigned char *data, size_t len, char *out, size_t out_cap);
/* Returns decoded length, or (size_t)-1 on error. out must be large enough (3*strlen(in)/4+3 is safe). */
size_t em_b64_decode(const char *in, unsigned char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* EM_FILTER_CRYPTO_H */
