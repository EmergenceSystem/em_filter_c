#ifndef EM_CONFIG_INTERNAL_H
#define EM_CONFIG_INTERNAL_H

#include "em_filter.h"

/* Maximum nodes resolved from config/env */
#define EM_MAX_NODES 16

/* Resolve disco nodes into out_nodes[]. These double as Model B relay
 * targets (wss://<host>:<port>/ws/filter) and Model A gossip seeds
 * (POST <host>:<port>/pop/gossip). Returns node count. */
int em_resolve_nodes(const em_config_t *cfg,
                     em_disco_node_t out_nodes[EM_MAX_NODES]);

/* Reconnect delay in milliseconds (reads EM_FILTER_RECONNECT_MS, default 5000). */
int em_reconnect_ms(void);

/* TLS inference helpers */
int em_infer_tls(const char *host, int port);
void em_default_port_tls(const char *host, int *out_port, int *out_tls);

/* ── §4.3 mode dispatch + Model A/B knobs ─────────────────────────────── */

/* cfg->mode -> EM_FILTER_MODE env -> "relay" (default). out_mode needs >= 16 bytes. */
void em_resolve_mode(const em_config_t *cfg, char out_mode[16]);

/* cfg->key_dir -> EM_FILTER_KEY_DIR env -> "./empop_key_<name>/". */
void em_resolve_key_dir(const em_config_t *cfg, const char *name, char *out, size_t out_cap);

/* cfg->advertise_host -> EM_FILTER_HOST env -> "0.0.0.0" (direct/both only;
 * the address gossiped for inbound /agent/query reachability). */
void em_resolve_advertise_host(const em_config_t *cfg, char *out, size_t out_cap);

/* cfg->query_port -> EM_FILTER_QUERY_PORT env -> 8090 (direct/both only). */
int em_resolve_query_port(const em_config_t *cfg);

/* Gossip push interval in milliseconds (reads EM_FILTER_GOSSIP_INTERVAL_MS, default 5000). */
int em_gossip_interval_ms(void);

#endif /* EM_CONFIG_INTERNAL_H */
