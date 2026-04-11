#ifndef EM_FILTER_H
#define EM_FILTER_H

#include <stddef.h>
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Result type ─────────────────────────────────────────────────────────── */

/**
 * Result returned by a handler callback.
 *
 * Mirrors the Erlang {Result, NewMemory} tuple.
 *
 * - result:     cJSON* to serialise and send as the "data" field.
 *               SDK frees it after sending. Must not be NULL (use cJSON_CreateNull()).
 * - new_memory: cJSON* object to use as the next memory state.
 *               If NULL, the current memory is kept unchanged.
 *               If non-NULL and different from the input memory, the SDK frees
 *               the old memory and stores new_memory.
 */
typedef struct em_result {
    cJSON *result;
    cJSON *new_memory;
} em_result_t;

/* ── Handler ─────────────────────────────────────────────────────────────── */

/**
 * Handler callback.
 *
 * @param body    null-terminated query string from em_disco
 * @param memory  current memory (cJSON object, SDK-owned — do not free)
 * @param ctx     user-defined context pointer
 * @return        em_result_t; SDK takes ownership of result and new_memory
 */
typedef em_result_t (*em_handle_fn)(const char *body, cJSON *memory, void *ctx);

/**
 * Handler descriptor passed to em_filter_create().
 */
typedef struct em_handler {
    em_handle_fn  handle;
    const char  **capabilities;    /* NULL-terminated array of UTF-8 strings */
    int           capabilities_len;
    void         *ctx;             /* opaque user context */
} em_handler_t;

/* ── Config ──────────────────────────────────────────────────────────────── */

typedef struct em_disco_node {
    char host[256];
    int  port;
    int  tls;   /* 1 = wss://, 0 = ws:// */
} em_disco_node_t;

typedef struct em_config {
    char             jwt_token[512]; /* empty = read EM_FILTER_JWT_TOKEN env var */
    em_disco_node_t *nodes;          /* explicit node list (NULL = auto-resolve) */
    int              nodes_len;
} em_config_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

typedef struct em_filter em_filter_t;

/**
 * Create a runner. Does not connect yet.
 * @return heap-allocated runner; caller must call em_filter_destroy() when done.
 */
em_filter_t *em_filter_create(const char *agent_name,
                               em_handler_t *handler,
                               em_config_t  *config);

/**
 * Connect to all resolved disco nodes and run forever.
 * Blocks until all connection threads exit (not expected in normal operation).
 */
void em_filter_run(em_filter_t *runner);

/** Free all resources. Call after em_filter_run() returns. */
void em_filter_destroy(em_filter_t *runner);

/* ── HTML utilities ──────────────────────────────────────────────────────── */

/** Remove <script>…</script> blocks. Returns heap string; caller must free(). */
char *em_strip_scripts(const char *html);

/** Remove all HTML tags. Returns heap string; caller must free(). */
char *em_get_text(const char *html);

/** Extract attribute value from an HTML element. Returns heap string or NULL; caller must free(). */
char *em_extract_attribute(const char *element, const char *attr);

/** Decode &#N;, &#xHH;, &name; entities. Returns heap string; caller must free(). */
char *em_decode_html_entities(const char *text);

/** Returns 1 if url should be skipped (not http, or matches any exclusion). */
int em_should_skip_link(const char *url, const char **excluded, int excluded_len);

#ifdef __cplusplus
}
#endif

#endif /* EM_FILTER_H */
