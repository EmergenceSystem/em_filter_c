#ifndef EM_HTTP_CLIENT_H
#define EM_HTTP_CLIENT_H

#include <stddef.h>

/*
 * Minimal blocking HTTP/HTTPS POST client. Mirrors websocket.c's TCP(+TLS)
 * connect, without the WebSocket upgrade — used by the Model A gossip push
 * loop to POST to a seed disco's /pop/gossip.
 *
 * Sends "Content-Type: application/json", "Content-Length: <len>",
 * "Connection: close". Reads the status line + headers, then the body
 * (via Content-Length if present, else until the peer closes the socket).
 *
 * Returns 0 if the request/response round-trip completed at the transport
 * level (regardless of HTTP status — check *out_status), -1 on connect/I/O
 * failure. On success, *out_body is a heap string (caller must free()); it
 * may be NULL if the response had no body.
 */
int em_http_post(const char *host, int port, int tls, const char *path,
                  const char *body, size_t body_len,
                  int *out_status, char **out_body);

#endif /* EM_HTTP_CLIENT_H */
