#include "em_filter.h"
#include "config_internal.h"
#include "em_filter/identity.h"
#include "server.h"
#include "gossip.h"
#include "wsclient.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Portable thread abstraction ─────────────────────────────────────────── */
#ifdef _WIN32
#  include <windows.h>
typedef HANDLE em_thread_t;
static int em_thread_create(em_thread_t *t, void *(*fn)(void *), void *arg) {
    *t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fn, arg, 0, NULL);
    return (*t == NULL) ? -1 : 0;
}
static void em_thread_join(em_thread_t t) {
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}
#else
#  include <pthread.h>
#  include <unistd.h>
typedef pthread_t em_thread_t;
static int em_thread_create(em_thread_t *t, void *(*fn)(void *), void *arg) {
    return pthread_create(t, NULL, fn, arg);
}
static void em_thread_join(em_thread_t t) {
    pthread_join(t, NULL);
}
#endif

/* ── em_filter struct ────────────────────────────────────────────────────── */

struct em_filter {
    char             agent_name[128];
    em_handler_t    *handler;
    em_config_t     *config;

    em_identity_t      *ident;

    /* Model A (direct/both) */
    em_agent_server_t  *server;
    em_gossip_pusher_t *pusher;

    /* Model B (relay/both) — one relay session per resolved disco node */
    em_relay_client_t **relays;
    em_thread_t         relay_threads[EM_MAX_NODES];
    int                  relay_count;
};

em_filter_t *em_filter_create(const char *agent_name,
                               em_handler_t *handler,
                               em_config_t  *config) {
    em_filter_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    strncpy(r->agent_name, agent_name, sizeof(r->agent_name) - 1);
    r->handler = handler;
    r->config  = config;
    return r;
}

void em_filter_run(em_filter_t *runner) {
    char mode[16];
    em_resolve_mode(runner->config, mode);

    char key_dir[512];
    em_resolve_key_dir(runner->config, runner->agent_name, key_dir, sizeof(key_dir));

    runner->ident = em_identity_create(runner->agent_name, key_dir,
                                        runner->handler->capabilities,
                                        runner->handler->capabilities_len);
    if (!runner->ident) {
        fprintf(stderr, "[em_filter] failed to load/create identity in '%s'\n", key_dir);
        return;
    }

    em_disco_node_t nodes[EM_MAX_NODES];
    int n = em_resolve_nodes(runner->config, nodes);
    int reconnect_ms = em_reconnect_ms();

    /* §4.3: "relay" (default) | "direct" | "both". Anything unrecognized
     * falls back to relay, same as an unset mode. */
    int want_direct = (strcmp(mode, "direct") == 0 || strcmp(mode, "both") == 0);
    int want_relay  = !want_direct || strcmp(mode, "both") == 0;

    printf("[em_filter] starting agent '%s' mode=%s (%d disco node(s))\n",
           runner->agent_name, mode, n);

    if (want_direct) {
        char host[256];
        em_resolve_advertise_host(runner->config, host, sizeof(host));
        int qport = em_resolve_query_port(runner->config);

        /* server.c binds and advertises the same host string (its /pop/gossip
         * reply handler reads it back for the "host" field); pass the
         * resolved advertise_host to both so the push loop and the inbound
         * reply agree. Left at the "0.0.0.0" default, this binds all
         * interfaces but advertises an unreachable placeholder — set
         * EM_FILTER_HOST (or em_config_t.advertise_host) to a real address
         * for direct mode to be reachable, per spec §4.1. */
        runner->server = em_agent_server_create(runner->ident, runner->handler, host, qport);
        if (em_agent_server_start(runner->server) != 0) {
            fprintf(stderr, "[em_filter] Model A server failed to start on %s:%d\n", host, qport);
        } else {
            printf("[em_filter] Model A server listening/advertising %s:%d\n", host, qport);
        }

        runner->pusher = em_gossip_pusher_create(runner->ident, nodes, n, host, qport,
                                                  em_gossip_interval_ms());
        em_gossip_pusher_start(runner->pusher);
    }

    if (want_relay) {
        if (n == 0) {
            fprintf(stderr, "[em_filter] relay mode requested but no disco nodes resolved\n");
        } else {
            runner->relays = calloc((size_t)n, sizeof(em_relay_client_t *));
            runner->relay_count = n;
            for (int i = 0; i < n; i++) {
                runner->relays[i] = em_relay_client_create(runner->ident, runner->handler,
                                                            nodes[i].host, nodes[i].port, nodes[i].tls,
                                                            reconnect_ms);
                em_thread_create(&runner->relay_threads[i], em_relay_client_run, runner->relays[i]);
            }
        }
    }

    if (runner->relay_count > 0) {
        /* Relay sessions reconnect forever; block until they exit (they
         * normally don't — not expected in normal operation). */
        for (int i = 0; i < runner->relay_count; i++)
            em_thread_join(runner->relay_threads[i]);
    } else if (want_direct) {
        /* Direct-only: the server and the gossip pusher run on their own
         * background threads; keep the caller blocked the same way. */
        for (;;) {
#ifdef _WIN32
            Sleep(1000);
#else
            sleep(1);
#endif
        }
    }
}

void em_filter_destroy(em_filter_t *runner) {
    if (!runner) return;
    if (runner->pusher) em_gossip_pusher_destroy(runner->pusher);
    if (runner->server) em_agent_server_destroy(runner->server);
    for (int i = 0; i < runner->relay_count; i++)
        em_relay_client_destroy(runner->relays[i]);
    free(runner->relays);
    if (runner->ident) em_identity_destroy(runner->ident);
    free(runner);
}
