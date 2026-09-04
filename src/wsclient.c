#include "wsclient.h"
#include "websocket.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#  define sleep_ms(ms) Sleep((DWORD)(ms))
#else
#  include <unistd.h>
#  define sleep_ms(ms) usleep((useconds_t)(ms) * 1000)
#endif

struct em_relay_client {
    em_identity_t *ident;
    em_handler_t  *handler;
    char           host[256];
    int            port;
    int            tls;
    int            reconnect_ms;

    /* Persists across reconnects within this client's lifetime, like the
     * Erlang leaf's per-connection RAM memory and Python's RelayClient. */
    cJSON         *memory;
};

em_relay_client_t *em_relay_client_create(em_identity_t *ident, em_handler_t *handler,
                                           const char *host, int port, int tls,
                                           int reconnect_ms) {
    em_relay_client_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    c->ident = ident;
    c->handler = handler;
    strncpy(c->host, host ? host : "", sizeof(c->host) - 1);
    c->port = port;
    c->tls = tls;
    c->reconnect_ms = reconnect_ms > 0 ? reconnect_ms : 5000;
    c->memory = cJSON_CreateObject();
    return c;
}

static void send_json(em_ws_t *ws, cJSON *obj) {
    char *s = cJSON_PrintUnformatted(obj);
    if (s) {
        em_ws_send_text(ws, s);
        free(s);
    }
}

/* Runs the handler on one query frame's body, signs the results, and sends
 * back the "result" frame. */
static void handle_query(em_relay_client_t *c, em_ws_t *ws, const char *qid, const char *body) {
    em_result_t r;
    if (c->handler && c->handler->handle) {
        r = c->handler->handle(body, c->memory, c->handler->ctx);
    } else {
        r.result = cJSON_CreateArray();
        r.new_memory = c->memory;
    }

    if (r.new_memory && r.new_memory != c->memory) {
        cJSON_Delete(c->memory);
        c->memory = r.new_memory;
    }

    cJSON *items = r.result ? r.result : cJSON_CreateArray();

    char signer_id_b64[32], sig_b64[128];
    em_identity_sign_results(c->ident, items, signer_id_b64, sizeof(signer_id_b64),
                              sig_b64, sizeof(sig_b64));

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "result");
    cJSON_AddStringToObject(resp, "id", qid);
    cJSON_AddItemToObject(resp, "results", items); /* resp now owns items */
    cJSON_AddStringToObject(resp, "signer_id", signer_id_b64);
    cJSON_AddStringToObject(resp, "signature", sig_b64);

    send_json(ws, resp);
    cJSON_Delete(resp);
}

int em_relay_client_session(em_relay_client_t *c) {
    em_ws_t ws;
    if (em_ws_connect(&ws, c->host, c->port, c->tls, "/ws/filter") < 0) {
        fprintf(stderr, "[em_filter] relay connect failed (%s:%d)\n", c->host, c->port);
        return -1;
    }

    cJSON *hello = em_identity_hello_payload(c->ident);
    send_json(&ws, hello);
    cJSON_Delete(hello);

    char *ack_raw = em_ws_recv_text(&ws);
    if (!ack_raw) {
        fprintf(stderr, "[em_filter] relay disconnected before hello_ok (%s:%d)\n", c->host, c->port);
        em_ws_close(&ws);
        return -1;
    }
    cJSON *ack = cJSON_Parse(ack_raw);
    free(ack_raw);

    cJSON *action = ack ? cJSON_GetObjectItemCaseSensitive(ack, "action") : NULL;
    if (!cJSON_IsString(action) || strcmp(action->valuestring, "hello_ok") != 0) {
        fprintf(stderr, "[em_filter] relay hello rejected by %s:%d\n", c->host, c->port);
        if (ack) cJSON_Delete(ack);
        em_ws_close(&ws);
        return -1;
    }
    cJSON_Delete(ack);

    for (;;) {
        char *raw = em_ws_recv_text(&ws);
        if (!raw) break; /* connection closed or error */

        cJSON *msg = cJSON_Parse(raw);
        free(raw);
        if (!msg) continue;

        cJSON *a = cJSON_GetObjectItemCaseSensitive(msg, "action");
        if (!cJSON_IsString(a) || strcmp(a->valuestring, "query") != 0) {
            cJSON_Delete(msg);
            continue;
        }

        cJSON *jid = cJSON_GetObjectItemCaseSensitive(msg, "id");
        cJSON *jbody = cJSON_GetObjectItemCaseSensitive(msg, "body");
        if (!cJSON_IsString(jid)) {
            cJSON_Delete(msg);
            continue;
        }

        handle_query(c, &ws, jid->valuestring, cJSON_IsString(jbody) ? jbody->valuestring : "");
        cJSON_Delete(msg);
    }

    em_ws_close(&ws);
    return 0;
}

void *em_relay_client_run(void *arg) {
    em_relay_client_t *c = (em_relay_client_t *)arg;
    for (;;) {
        em_relay_client_session(c);
        sleep_ms(c->reconnect_ms);
    }
    return NULL; /* unreachable; run_forever like em_filter_run's other threads */
}

void em_relay_client_destroy(em_relay_client_t *c) {
    if (!c) return;
    if (c->memory) cJSON_Delete(c->memory);
    free(c);
}
