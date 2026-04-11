#ifndef EM_CONFIG_INTERNAL_H
#define EM_CONFIG_INTERNAL_H

#include "em_filter.h"

/* Maximum nodes resolved from config/env */
#define EM_MAX_NODES 16

/* Resolve disco nodes into out_nodes[]. Returns node count. */
int em_resolve_nodes(const em_config_t *cfg,
                     em_disco_node_t out_nodes[EM_MAX_NODES]);

/* Resolve JWT token into out_jwt (buf of at least 512 bytes). */
void em_resolve_jwt(const em_config_t *cfg, char out_jwt[512]);

/* Reconnect delay in milliseconds (reads EM_FILTER_RECONNECT_MS, default 5000). */
int em_reconnect_ms(void);

/* TLS inference helpers */
int em_infer_tls(const char *host, int port);
void em_default_port_tls(const char *host, int *out_port, int *out_tls);

#endif /* EM_CONFIG_INTERNAL_H */
