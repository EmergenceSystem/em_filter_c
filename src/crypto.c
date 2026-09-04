#include "em_filter/crypto.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <direct.h>
#  define em_mkdir(p) _mkdir(p)
#else
#  include <sys/stat.h>
#  define em_mkdir(p) mkdir((p), 0700)
#endif

void em_id_of(const unsigned char pub[EM_PUBKEY_LEN], unsigned char out_id[EM_ID_LEN]) {
    unsigned char h[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(h, pub, EM_PUBKEY_LEN);
    memcpy(out_id, h, EM_ID_LEN);
}

static void key_file_path(const char *key_dir, char *out, size_t out_cap) {
    size_t dlen = strlen(key_dir);
    int has_sep = dlen > 0 && (key_dir[dlen - 1] == '/' || key_dir[dlen - 1] == '\\');
    snprintf(out, out_cap, "%s%snode_ed25519.key", key_dir, has_sep ? "" : "/");
}

int em_crypto_load_or_create(const char *key_dir,
                              unsigned char out_pub[EM_PUBKEY_LEN],
                              unsigned char out_seed[EM_SEED_LEN]) {
    char path[1024];
    key_file_path(key_dir, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (f) {
        unsigned char buf[EM_PUBKEY_LEN + EM_SEED_LEN];
        size_t n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        if (n == sizeof(buf)) {
            memcpy(out_pub, buf, EM_PUBKEY_LEN);
            memcpy(out_seed, buf + EM_PUBKEY_LEN, EM_SEED_LEN);
            return 0;
        }
        /* Corrupt/short file: fall through and refuse to silently overwrite. */
        return -1;
    }

    /* Doesn't exist: create key_dir (best-effort) and generate a fresh keypair. */
    em_mkdir(key_dir);

    unsigned char seed[EM_SEED_LEN];
    unsigned char pub[EM_PUBKEY_LEN];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    randombytes_buf(seed, EM_SEED_LEN);
    if (crypto_sign_seed_keypair(pub, sk, seed) != 0) return -1;

    FILE *wf = fopen(path, "wb");
    if (!wf) return -1;
    unsigned char buf[EM_PUBKEY_LEN + EM_SEED_LEN];
    memcpy(buf, pub, EM_PUBKEY_LEN);
    memcpy(buf + EM_PUBKEY_LEN, seed, EM_SEED_LEN);
    size_t written = fwrite(buf, 1, sizeof(buf), wf);
    fclose(wf);
    if (written != sizeof(buf)) return -1;

    memcpy(out_pub, pub, EM_PUBKEY_LEN);
    memcpy(out_seed, seed, EM_SEED_LEN);
    return 0;
}

size_t em_canonical_identity(const unsigned char id[EM_ID_LEN], const char *name,
                              unsigned char *out, size_t out_cap) {
    size_t nlen = strlen(name);
    size_t total = EM_ID_LEN + 1 + nlen;
    if (out_cap < total) return 0;
    memcpy(out, id, EM_ID_LEN);
    out[EM_ID_LEN] = 0x00;
    memcpy(out + EM_ID_LEN + 1, name, nlen);
    return total;
}

/* Pick the first string field among `keys` (NULL-terminated list) in object `p`.
 * Returns a pointer to the string's UTF-8 bytes (not owned) and its length, or
 * NULL/0 if none matched or p is not an object. */
static const char *pick(const cJSON *p, const char *const *keys, size_t *out_len) {
    if (!p || !cJSON_IsObject(p)) { *out_len = 0; return NULL; }
    for (const char *const *k = keys; *k; k++) {
        cJSON *v = cJSON_GetObjectItemCaseSensitive(p, *k);
        if (cJSON_IsString(v) && v->valuestring) {
            *out_len = strlen(v->valuestring);
            return v->valuestring;
        }
    }
    *out_len = 0;
    return NULL;
}

/* Growable byte buffer. */
typedef struct { unsigned char *data; size_t len, cap; } buf_t;

static int buf_reserve(buf_t *b, size_t extra) {
    if (b->len + extra <= b->cap) return 1;
    size_t ncap = b->cap ? b->cap * 2 : 256;
    while (ncap < b->len + extra) ncap *= 2;
    unsigned char *nd = realloc(b->data, ncap);
    if (!nd) return 0;
    b->data = nd;
    b->cap = ncap;
    return 1;
}

static int buf_append(buf_t *b, const void *src, size_t n) {
    if (!buf_reserve(b, n)) return 0;
    if (n) memcpy(b->data + b->len, src, n);
    b->len += n;
    return 1;
}

static const char *const URL_KEYS[]   = {"url", NULL};
static const char *const TITLE_KEYS[] = {"title", "label", NULL};
static const char *const RESUME_KEYS[] = {"resume", "value", "description", NULL};

unsigned char *em_canonical_response(const cJSON *items, size_t *out_len) {
    buf_t b = {0};
    if (items && cJSON_IsArray(items)) {
        const cJSON *it;
        cJSON_ArrayForEach(it, items) {
            const cJSON *p = it;
            if (cJSON_IsObject(it)) {
                cJSON *props = cJSON_GetObjectItemCaseSensitive(it, "properties");
                if (props && cJSON_IsObject(props)) p = props;
            } else {
                p = NULL; /* non-object item -> empty U/T/R */
            }
            size_t ulen, tlen, rlen;
            const char *u = pick(p, URL_KEYS, &ulen);
            const char *t = pick(p, TITLE_KEYS, &tlen);
            const char *r = pick(p, RESUME_KEYS, &rlen);
            unsigned char zero = 0x00, nl = 0x0A;
            if (!buf_append(&b, u, ulen)) goto oom;
            if (!buf_append(&b, &zero, 1)) goto oom;
            if (!buf_append(&b, t, tlen)) goto oom;
            if (!buf_append(&b, &zero, 1)) goto oom;
            if (!buf_append(&b, r, rlen)) goto oom;
            if (!buf_append(&b, &nl, 1)) goto oom;
        }
    }
    /* Non-array items (or empty array): b stays empty, which is correct. */
    if (b.data == NULL) {
        /* Ensure a non-NULL, freeable pointer for the zero-length case. */
        b.data = malloc(1);
        if (!b.data) { *out_len = 0; return NULL; }
    }
    *out_len = b.len;
    return b.data;

oom:
    free(b.data);
    *out_len = 0;
    return NULL;
}

void em_sign(unsigned char sig[EM_SIG_LEN], const unsigned char *msg, size_t mlen,
             const unsigned char seed[EM_SEED_LEN]) {
    unsigned char pub[EM_PUBKEY_LEN];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pub, sk, seed);
    crypto_sign_detached(sig, NULL, msg, mlen, sk);
    sodium_memzero(sk, sizeof(sk));
}

int em_verify(const unsigned char *msg, size_t mlen,
              const unsigned char sig[EM_SIG_LEN], const unsigned char pub[EM_PUBKEY_LEN]) {
    return crypto_sign_verify_detached(sig, msg, mlen, pub) == 0;
}

size_t em_b64_encode(const unsigned char *data, size_t len, char *out, size_t out_cap) {
    if (sodium_bin2base64(out, out_cap, data, len, sodium_base64_VARIANT_ORIGINAL) == NULL)
        return 0;
    return strlen(out);
}

size_t em_b64_decode(const char *in, unsigned char *out, size_t out_cap) {
    size_t decoded_len = 0;
    if (sodium_base642bin(out, out_cap, in, strlen(in), NULL, &decoded_len, NULL,
                           sodium_base64_VARIANT_ORIGINAL) != 0)
        return (size_t)-1;
    return decoded_len;
}

void em_sign_response(const cJSON *items,
                       const unsigned char pub[EM_PUBKEY_LEN],
                       const unsigned char seed[EM_SEED_LEN],
                       char *out_signer_id_b64, size_t signer_id_cap,
                       char *out_sig_b64, size_t sig_cap) {
    unsigned char id[EM_ID_LEN];
    em_id_of(pub, id);

    size_t clen = 0;
    unsigned char *canon = em_canonical_response(items, &clen);

    unsigned char sig[EM_SIG_LEN];
    em_sign(sig, canon ? canon : (const unsigned char *)"", clen, seed);
    free(canon);

    em_b64_encode(id, EM_ID_LEN, out_signer_id_b64, signer_id_cap);
    em_b64_encode(sig, EM_SIG_LEN, out_sig_b64, sig_cap);
}
