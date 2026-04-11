#include "em_filter.h"
#include "config_internal.h"
#include "connection.h"
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
    em_thread_t     *threads;
    em_conn_args_t **args;
    int              thread_count;
};

em_filter_t *em_filter_create(const char *agent_name,
                               em_handler_t *handler,
                               em_config_t  *config) {
    em_filter_t *r = calloc(1, sizeof(*r));
    strncpy(r->agent_name, agent_name, 127);
    r->handler = handler;
    r->config  = config;
    return r;
}

void em_filter_run(em_filter_t *runner) {
    em_disco_node_t nodes[EM_MAX_NODES];
    int n = em_resolve_nodes(runner->config, nodes);

    char jwt[512];
    em_resolve_jwt(runner->config, jwt);

    int delay = em_reconnect_ms();

    printf("[em_filter] Starting agent '%s' on %d node(s)\n",
           runner->agent_name, n);

    runner->threads = calloc((size_t)n, sizeof(em_thread_t));
    runner->args    = calloc((size_t)n, sizeof(em_conn_args_t *));
    runner->thread_count = n;

    for (int i = 0; i < n; i++) {
        em_conn_args_t *a = calloc(1, sizeof(*a));
        strncpy(a->agent_name,  runner->agent_name, 127);
        a->node         = nodes[i];
        a->handler      = runner->handler;
        a->reconnect_ms = delay;
        strncpy(a->jwt_token, jwt, 511);

        runner->args[i] = a;
        em_thread_create(&runner->threads[i], em_connection_thread, a);
    }

    /* Block until all threads exit (they normally run forever). */
    for (int i = 0; i < n; i++)
        em_thread_join(runner->threads[i]);
}

void em_filter_destroy(em_filter_t *runner) {
    if (!runner) return;
    free(runner->threads);
    free(runner->args);
    free(runner);
}
