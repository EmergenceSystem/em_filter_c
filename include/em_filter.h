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

/*
 * A disco endpoint. Doubles as a Model B relay target
 * (wss://host:port/ws/filter) and a Model A gossip seed
 * (POST host:port/pop/gossip) — same mesh entry points, either transport.
 */
typedef struct em_disco_node {
    char host[256];
    int  port;
    int  tls;   /* 1 = wss:// / https://, 0 = ws:// / http:// */
} em_disco_node_t;

typedef struct em_config {
    em_disco_node_t *nodes;             /* explicit disco list (NULL = auto-resolve via env/emergence.conf) */
    int              nodes_len;

    /* §4.3 mode dispatch: "relay" (default) | "direct" | "both".
     * Empty = read EM_FILTER_MODE env var, else "relay". */
    char             mode[16];

    /* Key directory (pub(32)||seed(32), created on first run if absent).
     * Empty = read EM_FILTER_KEY_DIR env var, else "./empop_key_<name>/". */
    char             key_dir[256];

    /* Model A/both only: the host advertised in gossip payloads for inbound
     * /agent/query reachability. Empty = read EM_FILTER_HOST env var, else
     * "0.0.0.0" (rarely useful as an advertised address — set this or the
     * env var to a real reachable host/IP for direct mode to work). */
    char             advertise_host[256];

    /* Model A/both only: HTTP server port. 0 = read EM_FILTER_QUERY_PORT
     * env var, else 8090. */
    int              query_port;
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
 * Loads/creates the ed25519 identity, then starts the transport(s) selected
 * by mode dispatch (§4.3): "relay" opens outbound WS session(s) to each
 * resolved disco node; "direct" starts the Model A HTTP server plus the
 * gossip push loop; "both" starts all of them. Blocks forever (not expected
 * to return in normal operation).
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
