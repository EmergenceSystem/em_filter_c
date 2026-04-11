#include "connection.h"
#include "websocket.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#  define sleep_ms(ms) Sleep(ms)
#else
#  include <unistd.h>
#  define sleep_ms(ms) usleep((useconds_t)(ms) * 1000)
#endif

static void send_json(em_ws_t *ws, cJSON *obj) {
    char *s = cJSON_PrintUnformatted(obj);
    if (s) {
        em_ws_send_text(ws, s);
        free(s);
    }
}

static void handle_query(em_ws_t *ws, em_conn_args_t *args,
                          const char *id, const char *body,
                          cJSON **memory) {
    em_result_t r = args->handler->handle(body, *memory, args->handler->ctx);

    /* Update memory */
    if (r.new_memory && r.new_memory != *memory) {
        cJSON_Delete(*memory);
        *memory = r.new_memory;
    }

    /* Send result frame */
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "action", "result");
    cJSON_AddStringToObject(resp, "id",     id);
    if (r.result)
        cJSON_AddItemToObject(resp, "data", r.result);
    else
        cJSON_AddNullToObject(resp, "data");

    send_json(ws, resp);
    cJSON_Delete(resp);
}

static void connect_once(em_conn_args_t *args, cJSON **memory) {
    char path[600];
    if (args->jwt_token[0])
        snprintf(path, sizeof(path), "/ws?token=%s", args->jwt_token);
    else
        strcpy(path, "/ws");

    printf("[em_filter] %s connecting to %s://%s:%d/ws\n",
           args->agent_name,
           args->node.tls ? "wss" : "ws",
           args->node.host, args->node.port);

    em_ws_t ws;
    if (em_ws_connect(&ws, args->node.host, args->node.port,
                      args->node.tls, path) < 0) {
        fprintf(stderr, "[em_filter] %s connect failed (%s:%d)\n",
                args->agent_name, args->node.host, args->node.port);
        return;
    }

    /* Step 1: register */
    cJSON *reg = cJSON_CreateObject();
    cJSON_AddStringToObject(reg, "action", "register");
    cJSON_AddStringToObject(reg, "name",   args->agent_name);
    send_json(&ws, reg);
    cJSON_Delete(reg);

    /* Step 2: agent_hello */
    cJSON *hello = cJSON_CreateObject();
    cJSON_AddStringToObject(hello, "action", "agent_hello");
    cJSON *caps = cJSON_CreateArray();
    for (int i = 0; i < args->handler->capabilities_len; i++)
        cJSON_AddItemToArray(caps, cJSON_CreateString(args->handler->capabilities[i]));
    cJSON_AddItemToObject(hello, "capabilities", caps);
    send_json(&ws, hello);
    cJSON_Delete(hello);

    printf("[em_filter] %s registered — entering message loop\n", args->agent_name);

    for (;;) {
        char *raw = em_ws_recv_text(&ws);
        if (!raw) break;  /* connection closed or error */

        cJSON *msg = cJSON_Parse(raw);
        free(raw);
        if (!msg) continue;

        cJSON *action = cJSON_GetObjectItemCaseSensitive(msg, "action");
        if (!cJSON_IsString(action) || strcmp(action->valuestring, "query") != 0) {
            cJSON_Delete(msg);
            continue;
        }

        cJSON *jid   = cJSON_GetObjectItemCaseSensitive(msg, "id");
        cJSON *jbody = cJSON_GetObjectItemCaseSensitive(msg, "body");

        if (!cJSON_IsString(jid)) {
            fprintf(stderr, "[em_filter] %s query missing 'id', skipping\n",
                    args->agent_name);
            cJSON_Delete(msg);
            continue;
        }

        const char *id   = jid->valuestring;
        const char *body = cJSON_IsString(jbody) ? jbody->valuestring : "";

        printf("[em_filter] %s query %s: %s\n", args->agent_name, id, body);
        handle_query(&ws, args, id, body, memory);
        cJSON_Delete(msg);
    }

    em_ws_close(&ws);
    printf("[em_filter] %s disconnected\n", args->agent_name);
}

void *em_connection_thread(void *arg) {
    em_conn_args_t *args = (em_conn_args_t *)arg;
    cJSON *memory = cJSON_CreateObject();  /* starts as empty map, like Erlang #{} */
    int delay = args->reconnect_ms;

    for (;;) {
        connect_once(args, &memory);
        sleep_ms(delay);
    }

    cJSON_Delete(memory);
    free(args);
    return NULL;
}
