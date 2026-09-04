/* Identity payload tests: hello_payload / gossip_payload / sign_results. */
#include "em_filter/identity.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <direct.h>
#  define rmdir_recursive(p) /* best effort, skip on Windows */
#else
#  include <sys/stat.h>
#endif

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); failures++; } \
    else { printf("PASS: %s\n", (msg)); } \
} while (0)

int main(void) {
    const char *key_dir = "test_identity_keydir";
    const char *caps[] = {"search"};

    em_identity_t *ident = em_identity_create("t", key_dir, caps, 1);
    CHECK(ident != NULL, "em_identity_create succeeds");

    cJSON *h = em_identity_hello_payload(ident);
    cJSON *action = cJSON_GetObjectItemCaseSensitive(h, "action");
    cJSON *name = cJSON_GetObjectItemCaseSensitive(h, "name");
    CHECK(cJSON_IsString(action) && strcmp(action->valuestring, "hello") == 0,
          "hello_payload action == hello");
    CHECK(cJSON_IsString(name) && strcmp(name->valuestring, "t") == 0,
          "hello_payload name == t");

    cJSON *pubkey_j = cJSON_GetObjectItemCaseSensitive(h, "pubkey");
    unsigned char pub_decoded[EM_PUBKEY_LEN];
    size_t pub_len = em_b64_decode(pubkey_j->valuestring, pub_decoded, sizeof(pub_decoded));
    CHECK(pub_len == EM_PUBKEY_LEN && memcmp(pub_decoded, ident->pub, EM_PUBKEY_LEN) == 0,
          "hello_payload pubkey base64-decodes to ident->pub");

    cJSON *sig_j = cJSON_GetObjectItemCaseSensitive(h, "sig");
    unsigned char sig_decoded[EM_SIG_LEN];
    size_t sig_len = em_b64_decode(sig_j->valuestring, sig_decoded, sizeof(sig_decoded));
    unsigned char ci[512];
    size_t ci_len = em_canonical_identity(ident->id, "t", ci, sizeof(ci));
    CHECK(sig_len == EM_SIG_LEN && em_verify(ci, ci_len, sig_decoded, ident->pub),
          "hello_payload self-sig verifies");

    cJSON *caps_j = cJSON_GetObjectItemCaseSensitive(h, "capabilities");
    CHECK(cJSON_IsArray(caps_j) && cJSON_GetArraySize(caps_j) == 1,
          "hello_payload capabilities has 1 entry");

    cJSON *g = em_identity_gossip_payload(ident, "1.2.3.4", 9600);
    cJSON *qport = cJSON_GetObjectItemCaseSensitive(g, "query_port");
    cJSON *role = cJSON_GetObjectItemCaseSensitive(g, "role");
    CHECK(cJSON_IsNumber(qport) && qport->valueint == 9600, "gossip_payload query_port == 9600");
    CHECK(cJSON_IsString(role) && strcmp(role->valuestring, "filter") == 0,
          "gossip_payload role == filter");

    /* sign_results: build one item and verify the signature against canonical_response. */
    cJSON *items = cJSON_CreateArray();
    cJSON *item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "url", "https://x/1");
    cJSON_AddStringToObject(item, "title", "T");
    cJSON_AddStringToObject(item, "resume", "R");
    cJSON_AddItemToArray(items, item);

    char signer_id_b64[32], sig_b64[128];
    em_identity_sign_results(ident, items, signer_id_b64, sizeof(signer_id_b64), sig_b64, sizeof(sig_b64));

    unsigned char signer_id_decoded[EM_ID_LEN];
    em_b64_decode(signer_id_b64, signer_id_decoded, sizeof(signer_id_decoded));
    CHECK(memcmp(signer_id_decoded, ident->id, EM_ID_LEN) == 0, "sign_results signer_id == ident->id");

    size_t cr_len = 0;
    unsigned char *cr = em_canonical_response(items, &cr_len);
    unsigned char resp_sig_decoded[EM_SIG_LEN];
    em_b64_decode(sig_b64, resp_sig_decoded, sizeof(resp_sig_decoded));
    CHECK(em_verify(cr, cr_len, resp_sig_decoded, ident->pub), "sign_results signature verifies");
    free(cr);

    cJSON_Delete(items);
    cJSON_Delete(h);
    cJSON_Delete(g);
    em_identity_destroy(ident);

    if (failures) { fprintf(stderr, "\n%d check(s) FAILED\n", failures); return 1; }
    printf("\nAll identity checks PASSED\n");
    return 0;
}
