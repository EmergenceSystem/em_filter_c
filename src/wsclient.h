#ifndef EM_WSCLIENT_H
#define EM_WSCLIENT_H

#include "em_filter.h"
#include "em_filter/identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Model B — WS relay client (spec §4.2): opens an outbound WebSocket to
 * wss://<disco>/ws/filter, sends hello, waits for hello_ok, then answers
 * query frames with signed result frames. Never needs inbound reachability.
 *
 *   hello  (filter → disco): identity.hello_payload()
 *   query  (disco → filter): {"action":"query","id":..,"body":..}
 *   result (filter → disco): {"action":"result","id":..,"results":..,
 *                             "signer_id":..,"signature":..}
 *
 * On disconnect (recv returns NULL — close frame, error, or the disco
 * dropping the socket), reconnects after reconnect_ms and retries hello.
 */
typedef struct em_relay_client em_relay_client_t;

em_relay_client_t *em_relay_client_create(em_identity_t *ident, em_handler_t *handler,
                                           const char *host, int port, int tls,
                                           int reconnect_ms);

/*
 * Runs one connect → hello → query/result loop → disconnect cycle.
 * Returns 0 if hello_ok was received and the session ran (even if it then
 * disconnected normally), -1 if the connection or handshake failed outright.
 * Exposed (not static) so tests can drive a single session against a stub
 * server without an infinite loop.
 */
int em_relay_client_session(em_relay_client_t *c);

/*
 * Runs em_relay_client_session() forever, sleeping reconnect_ms between
 * attempts. Signature matches the thread-start callback used by the SDK's
 * portable thread abstraction (em_thread_create's void *(*)(void*)).
 */
void *em_relay_client_run(void *arg);

void em_relay_client_destroy(em_relay_client_t *client);

#ifdef __cplusplus
}
#endif

#endif /* EM_WSCLIENT_H */
