#ifndef EM_FILTER_IDENTITY_H
#define EM_FILTER_IDENTITY_H

#include "cJSON.h"
#include "em_filter/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * em_identity_t: holds the loaded/created keypair, agent name and declared
 * capabilities, and builds the wire payloads shared by both transports
 * (Model A gossip push, Model B WS hello) plus the response-signing helper
 * used by both the HTTP server and the relay WS client.
 */
typedef struct em_identity {
    unsigned char pub[EM_PUBKEY_LEN];
    unsigned char seed[EM_SEED_LEN];
    unsigned char id[EM_ID_LEN];
    char         *name;           /* owned, UTF-8, NUL-terminated */
    char        **capabilities;   /* owned array of owned strings */
    int           capabilities_len;
} em_identity_t;

/*
 * Load-or-create the keypair from key_dir and capture name/capabilities.
 * capabilities may be NULL if capabilities_len == 0. Strings are copied.
 * Returns NULL on key I/O failure.
 */
em_identity_t *em_identity_create(const char *name, const char *key_dir,
                                   const char *const *capabilities, int capabilities_len);

void em_identity_destroy(em_identity_t *ident);

/* {"action":"hello","name":...,"pubkey":b64,"sig":b64(selfsig),"capabilities":[...]} */
cJSON *em_identity_hello_payload(const em_identity_t *ident);

/*
 * {"id":b64,"name":...,"host":...,"query_port":N,"pubkey":b64,"sig":b64(selfsig),
 *  "capabilities":[...],"role":"filter"}
 */
cJSON *em_identity_gossip_payload(const em_identity_t *ident, const char *host, int query_port);

/* Signs canonical_response(items); writes base64 signer_id/signature (NUL-terminated). */
void em_identity_sign_results(const em_identity_t *ident, const cJSON *items,
                               char *out_signer_id_b64, size_t signer_id_cap,
                               char *out_sig_b64, size_t sig_cap);

#ifdef __cplusplus
}
#endif

#endif /* EM_FILTER_IDENTITY_H */
