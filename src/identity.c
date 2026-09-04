#include "em_filter/identity.h"

#include <stdlib.h>
#include <string.h>

em_identity_t *em_identity_create(const char *name, const char *key_dir,
                                   const char *const *capabilities, int capabilities_len) {
    em_identity_t *ident = calloc(1, sizeof(*ident));
    if (!ident) return NULL;

    if (em_crypto_load_or_create(key_dir, ident->pub, ident->seed) != 0) {
        free(ident);
        return NULL;
    }
    em_id_of(ident->pub, ident->id);

    ident->name = strdup(name);

    ident->capabilities_len = capabilities_len > 0 ? capabilities_len : 0;
    if (ident->capabilities_len > 0) {
        ident->capabilities = calloc((size_t)ident->capabilities_len, sizeof(char *));
        for (int i = 0; i < ident->capabilities_len; i++)
            ident->capabilities[i] = strdup(capabilities[i]);
    }

    return ident;
}

void em_identity_destroy(em_identity_t *ident) {
    if (!ident) return;
    free(ident->name);
    for (int i = 0; i < ident->capabilities_len; i++)
        free(ident->capabilities[i]);
    free(ident->capabilities);
    free(ident);
}

static char *selfsig_b64(const em_identity_t *ident) {
    unsigned char ci[512];
    size_t ci_len = em_canonical_identity(ident->id, ident->name, ci, sizeof(ci));
    unsigned char sig[EM_SIG_LEN];
    em_sign(sig, ci, ci_len, ident->seed);
    char *out = malloc(96);
    em_b64_encode(sig, EM_SIG_LEN, out, 96);
    return out;
}

static cJSON *capabilities_array(const em_identity_t *ident) {
    cJSON *caps = cJSON_CreateArray();
    for (int i = 0; i < ident->capabilities_len; i++)
        cJSON_AddItemToArray(caps, cJSON_CreateString(ident->capabilities[i]));
    return caps;
}

cJSON *em_identity_hello_payload(const em_identity_t *ident) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "action", "hello");
    cJSON_AddStringToObject(obj, "name", ident->name);

    char pub_b64[64];
    em_b64_encode(ident->pub, EM_PUBKEY_LEN, pub_b64, sizeof(pub_b64));
    cJSON_AddStringToObject(obj, "pubkey", pub_b64);

    char *sig = selfsig_b64(ident);
    cJSON_AddStringToObject(obj, "sig", sig);
    free(sig);

    cJSON_AddItemToObject(obj, "capabilities", capabilities_array(ident));
    return obj;
}

cJSON *em_identity_gossip_payload(const em_identity_t *ident, const char *host, int query_port) {
    cJSON *obj = cJSON_CreateObject();

    char id_b64[32];
    em_b64_encode(ident->id, EM_ID_LEN, id_b64, sizeof(id_b64));
    cJSON_AddStringToObject(obj, "id", id_b64);
    cJSON_AddStringToObject(obj, "name", ident->name);
    cJSON_AddStringToObject(obj, "host", host ? host : "");
    cJSON_AddNumberToObject(obj, "query_port", query_port);

    char pub_b64[64];
    em_b64_encode(ident->pub, EM_PUBKEY_LEN, pub_b64, sizeof(pub_b64));
    cJSON_AddStringToObject(obj, "pubkey", pub_b64);

    char *sig = selfsig_b64(ident);
    cJSON_AddStringToObject(obj, "sig", sig);
    free(sig);

    cJSON_AddItemToObject(obj, "capabilities", capabilities_array(ident));
    cJSON_AddStringToObject(obj, "role", "filter");
    return obj;
}

void em_identity_sign_results(const em_identity_t *ident, const cJSON *items,
                               char *out_signer_id_b64, size_t signer_id_cap,
                               char *out_sig_b64, size_t sig_cap) {
    em_sign_response(items, ident->pub, ident->seed,
                      out_signer_id_b64, signer_id_cap, out_sig_b64, sig_cap);
}
