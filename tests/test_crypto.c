/* Cross-language crypto parity test: fixtures/crypto_vectors.json must be
 * reproduced byte-for-byte, proving parity with em_pop_crypto.erl. */
#include "em_filter/crypto.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef FIXTURE_PATH
#define FIXTURE_PATH "fixtures/crypto_vectors.json"
#endif

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
        failures++; \
    } else { \
        printf("PASS: %s\n", (msg)); \
    } \
} while (0)

static char *read_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)len + 1);
    size_t n = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[n] = '\0';
    if (out_len) *out_len = (long)n;
    return buf;
}

static size_t hex_decode(const char *hex, unsigned char *out, size_t out_cap) {
    size_t hlen = strlen(hex);
    size_t blen = hlen / 2;
    if (blen > out_cap) { fprintf(stderr, "hex_decode: buffer too small\n"); exit(2); }
    for (size_t i = 0; i < blen; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = (unsigned char)byte;
    }
    return blen;
}

static char *hex_encode(const unsigned char *data, size_t len) {
    char *out = malloc(2 * len + 1);
    for (size_t i = 0; i < len; i++) sprintf(out + 2 * i, "%02x", data[i]);
    out[2 * len] = '\0';
    return out;
}

int main(void) {
    long flen;
    char *raw = read_file(FIXTURE_PATH, &flen);
    cJSON *fx = cJSON_Parse(raw);
    if (!fx) { fprintf(stderr, "fixture parse error\n"); return 2; }

    const char *pubkey_hex = cJSON_GetObjectItemCaseSensitive(fx, "pubkey_hex")->valuestring;
    const char *privkey_hex = cJSON_GetObjectItemCaseSensitive(fx, "privkey_hex")->valuestring;
    const char *id_hex = cJSON_GetObjectItemCaseSensitive(fx, "id_hex")->valuestring;
    const char *signer_id_b64 = cJSON_GetObjectItemCaseSensitive(fx, "signer_id_b64")->valuestring;
    const char *name = cJSON_GetObjectItemCaseSensitive(fx, "name")->valuestring;
    const char *canonical_identity_hex = cJSON_GetObjectItemCaseSensitive(fx, "canonical_identity_hex")->valuestring;
    const char *selfsig_b64 = cJSON_GetObjectItemCaseSensitive(fx, "selfsig_b64")->valuestring;
    const cJSON *items = cJSON_GetObjectItemCaseSensitive(fx, "items");
    const char *canonical_response_hex = cJSON_GetObjectItemCaseSensitive(fx, "canonical_response_hex")->valuestring;
    const char *response_signature_b64 = cJSON_GetObjectItemCaseSensitive(fx, "response_signature_b64")->valuestring;

    unsigned char pub[EM_PUBKEY_LEN], seed[EM_SEED_LEN], id_expected[EM_ID_LEN];
    hex_decode(pubkey_hex, pub, sizeof(pub));
    hex_decode(privkey_hex, seed, sizeof(seed));
    hex_decode(id_hex, id_expected, sizeof(id_expected));

    /* 1. id_of */
    unsigned char id[EM_ID_LEN];
    em_id_of(pub, id);
    CHECK(memcmp(id, id_expected, EM_ID_LEN) == 0, "id_of matches id_hex");

    char id_b64[32];
    em_b64_encode(id, EM_ID_LEN, id_b64, sizeof(id_b64));
    CHECK(strcmp(id_b64, signer_id_b64) == 0, "base64(id) matches signer_id_b64");

    /* 2. canonical_identity */
    unsigned char ci[256];
    size_t ci_len = em_canonical_identity(id, name, ci, sizeof(ci));
    unsigned char ci_expected[256];
    size_t ci_expected_len = hex_decode(canonical_identity_hex, ci_expected, sizeof(ci_expected));
    CHECK(ci_len == ci_expected_len && memcmp(ci, ci_expected, ci_len) == 0,
          "canonical_identity matches canonical_identity_hex");

    /* 3. selfsig */
    unsigned char selfsig[EM_SIG_LEN];
    em_sign(selfsig, ci, ci_len, seed);
    char selfsig_b64_got[128];
    em_b64_encode(selfsig, EM_SIG_LEN, selfsig_b64_got, sizeof(selfsig_b64_got));
    CHECK(strcmp(selfsig_b64_got, selfsig_b64) == 0, "selfsig matches selfsig_b64");
    CHECK(em_verify(ci, ci_len, selfsig, pub), "selfsig verifies against pubkey");

    /* 4. canonical_response */
    size_t cr_len = 0;
    unsigned char *cr = em_canonical_response(items, &cr_len);
    unsigned char cr_expected[4096];
    size_t cr_expected_len = hex_decode(canonical_response_hex, cr_expected, sizeof(cr_expected));
    CHECK(cr_len == cr_expected_len && memcmp(cr, cr_expected, cr_len) == 0,
          "canonical_response matches canonical_response_hex");

    /* 5. response signature */
    unsigned char resp_sig[EM_SIG_LEN];
    em_sign(resp_sig, cr, cr_len, seed);
    char resp_sig_b64_got[128];
    em_b64_encode(resp_sig, EM_SIG_LEN, resp_sig_b64_got, sizeof(resp_sig_b64_got));
    CHECK(strcmp(resp_sig_b64_got, response_signature_b64) == 0,
          "response signature matches response_signature_b64");
    CHECK(em_verify(cr, cr_len, resp_sig, pub), "response signature verifies against pubkey");

    /* 6. sign_response helper (round-trip through the exact wire-facing API) */
    char signer_id_got[32], sig_got[128];
    em_sign_response(items, pub, seed, signer_id_got, sizeof(signer_id_got), sig_got, sizeof(sig_got));
    CHECK(strcmp(signer_id_got, signer_id_b64) == 0, "sign_response signer_id matches");
    CHECK(strcmp(sig_got, response_signature_b64) == 0, "sign_response signature matches");

    /* 7. hex round-trip sanity (belt-and-braces on our own hex helpers) */
    char *ci_hex_roundtrip = hex_encode(ci, ci_len);
    CHECK(strcmp(ci_hex_roundtrip, canonical_identity_hex) == 0, "hex_encode round-trips canonical_identity");

    free(cr);
    free(ci_hex_roundtrip);
    free(raw);
    cJSON_Delete(fx);

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nAll crypto fixture checks PASSED\n");
    return 0;
}
