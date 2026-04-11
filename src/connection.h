#ifndef EM_CONNECTION_H
#define EM_CONNECTION_H

#include "em_filter.h"
#include "config_internal.h"

typedef struct em_conn_args {
    char             agent_name[128];
    em_disco_node_t  node;
    em_handler_t    *handler;
    char             jwt_token[512];
    int              reconnect_ms;
} em_conn_args_t;

void *em_connection_thread(void *arg);

#endif /* EM_CONNECTION_H */
