#ifndef EM_WEBSOCKET_H
#define EM_WEBSOCKET_H

#include <stddef.h>
#include <openssl/ssl.h>

typedef struct em_ws {
    int   fd;        /* TCP socket */
    SSL  *ssl;       /* NULL if non-TLS */
    SSL_CTX *ssl_ctx;
} em_ws_t;

/* Connect and perform HTTP WebSocket upgrade.
 * path: e.g. "/ws" or "/ws?token=eyJ..."
 * Returns 0 on success, -1 on failure. */
int  em_ws_connect(em_ws_t *ws, const char *host, int port, int tls,
                   const char *path);

/* Send a UTF-8 text frame (masked, as required for clients). Returns 0/-1. */
int  em_ws_send_text(em_ws_t *ws, const char *text);

/* Receive the next text frame. Blocks until a frame arrives.
 * Returns heap-allocated string (caller must free()) or NULL on close/error.
 * Ignores ping/pong frames, returns NULL on close frame. */
char *em_ws_recv_text(em_ws_t *ws);

/* Close the connection and free SSL resources. */
void em_ws_close(em_ws_t *ws);

#endif /* EM_WEBSOCKET_H */
