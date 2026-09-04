#ifndef EM_GOSSIP_H
#define EM_GOSSIP_H

#include "em_filter.h"
#include "em_filter/identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Model A gossip push loop (spec §4.1): every interval_ms, POST this
 * agent's gossip_payload(advertise_host, query_port) to each seed disco's
 * /pop/gossip, on a background thread. The seed's reply (its own gossip
 * payload) is read and discarded — SDKs keep no peer table (spec §4.1).
 */
typedef struct em_gossip_pusher em_gossip_pusher_t;

/* Copies ident (not owned) and seeds[0..seeds_len) (copied). */
em_gossip_pusher_t *em_gossip_pusher_create(em_identity_t *ident,
                                             const em_disco_node_t *seeds, int seeds_len,
                                             const char *advertise_host, int query_port,
                                             int interval_ms);

/* Starts the push loop on a background thread. Pushes once immediately,
 * then every interval_ms. No-op (returns 0) if seeds_len == 0. Returns 0 on
 * success, -1 on thread-creation failure. */
int em_gossip_pusher_start(em_gossip_pusher_t *p);

/* Signals the loop to stop and joins its thread. Safe to call once. */
void em_gossip_pusher_stop(em_gossip_pusher_t *p);

void em_gossip_pusher_destroy(em_gossip_pusher_t *p);

#ifdef __cplusplus
}
#endif

#endif /* EM_GOSSIP_H */
