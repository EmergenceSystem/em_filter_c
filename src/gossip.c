#include "gossip.h"
#include "http_client.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
   typedef HANDLE em_thread_t;
#  define sleep_ms(ms) Sleep((DWORD)(ms))
#else
#  include <pthread.h>
#  include <unistd.h>
   typedef pthread_t em_thread_t;
#  define sleep_ms(ms) usleep((useconds_t)(ms) * 1000)
#endif

struct em_gossip_pusher {
    em_identity_t   *ident;
    em_disco_node_t *seeds;
    int              seeds_len;
    char             advertise_host[256];
    int              query_port;
    int              interval_ms;

    volatile int     running;
    em_thread_t      thread;
    int              has_thread;
};

em_gossip_pusher_t *em_gossip_pusher_create(em_identity_t *ident,
                                             const em_disco_node_t *seeds, int seeds_len,
                                             const char *advertise_host, int query_port,
                                             int interval_ms) {
    em_gossip_pusher_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;

    p->ident = ident;
    p->seeds_len = seeds_len > 0 ? seeds_len : 0;
    if (p->seeds_len > 0) {
        p->seeds = calloc((size_t)p->seeds_len, sizeof(em_disco_node_t));
        if (!p->seeds) { free(p); return NULL; }
        memcpy(p->seeds, seeds, (size_t)p->seeds_len * sizeof(em_disco_node_t));
    }
    strncpy(p->advertise_host, advertise_host ? advertise_host : "", sizeof(p->advertise_host) - 1);
    p->query_port = query_port;
    p->interval_ms = interval_ms > 0 ? interval_ms : 5000;
    return p;
}

static void push_once(em_gossip_pusher_t *p) {
    cJSON *payload = em_identity_gossip_payload(p->ident, p->advertise_host, p->query_port);
    char *body = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);
    if (!body) return;

    for (int i = 0; i < p->seeds_len; i++) {
        int status = 0;
        char *resp_body = NULL;
        em_http_post(p->seeds[i].host, p->seeds[i].port, p->seeds[i].tls,
                     "/pop/gossip", body, strlen(body), &status, &resp_body);
        free(resp_body); /* the seed's own payload; SDKs keep no peer table (spec §4.1) */
    }
    free(body);
}

static void *pusher_loop(void *arg) {
    em_gossip_pusher_t *p = (em_gossip_pusher_t *)arg;
    while (p->running) {
        push_once(p);

        int waited = 0;
        while (waited < p->interval_ms && p->running) {
            int step = (p->interval_ms - waited) < 100 ? (p->interval_ms - waited) : 100;
            sleep_ms(step);
            waited += step;
        }
    }
    return NULL;
}

int em_gossip_pusher_start(em_gossip_pusher_t *p) {
    if (!p) return -1;
    if (p->seeds_len == 0) return 0; /* nothing to push to; not an error */

    p->running = 1;
#ifdef _WIN32
    p->thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pusher_loop, p, 0, NULL);
    p->has_thread = (p->thread != NULL);
#else
    p->has_thread = (pthread_create(&p->thread, NULL, pusher_loop, p) == 0);
#endif
    if (!p->has_thread) { p->running = 0; return -1; }
    return 0;
}

void em_gossip_pusher_stop(em_gossip_pusher_t *p) {
    if (!p || !p->has_thread) return;
    p->running = 0;
#ifdef _WIN32
    WaitForSingleObject(p->thread, INFINITE);
    CloseHandle(p->thread);
#else
    pthread_join(p->thread, NULL);
#endif
    p->has_thread = 0;
}

void em_gossip_pusher_destroy(em_gossip_pusher_t *p) {
    if (!p) return;
    em_gossip_pusher_stop(p);
    free(p->seeds);
    free(p);
}
