#ifndef EM_SERVER_H
#define EM_SERVER_H

#include "em_filter.h"
#include "em_filter/identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Model A: a minimal HTTP server implementing
 *   GET  /health       -> 200 "ok"
 *   POST /agent/query  -> {"query":"..."} -> {"results":[...],"signer_id":b64,"signature":b64}
 *   POST /pop/gossip    -> accept a remote payload (ignored beyond parsing),
 *                          reply with this agent's own gossip payload.
 *
 * Single accept/serve loop (one connection at a time) — SDKs are meant to
 * stay a thin, minimal server per spec §4.1; concurrency is not required.
 */
typedef struct em_agent_server em_agent_server_t;

/* port == 0 lets the OS pick an ephemeral port; read it back with
 * em_agent_server_port() once the server is started. */
em_agent_server_t *em_agent_server_create(em_identity_t *ident, em_handler_t *handler,
                                           const char *host, int port);

/* Starts the accept loop on a background thread. Returns 0 on success, -1 on failure. */
int em_agent_server_start(em_agent_server_t *srv);

/* Signals the accept loop to stop and joins its thread. Safe to call once. */
void em_agent_server_stop(em_agent_server_t *srv);

void em_agent_server_destroy(em_agent_server_t *srv);

int em_agent_server_port(const em_agent_server_t *srv);
const char *em_agent_server_advertise_host(const em_agent_server_t *srv);

#ifdef __cplusplus
}
#endif

#endif /* EM_SERVER_H */
