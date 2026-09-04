/**
 * echo_filter — minimal em_filter agent example.
 *
 * Build:
 *   cmake -B build && cmake --build build
 *   ./build/echo_filter
 *
 * Model B (default — outbound WS relay, NAT-friendly):
 *   EM_DISCO_HOST=disco.example.com EM_DISCO_PORT=443 ./build/echo_filter
 *
 * Model A (inbound HTTP server + gossip push; needs a reachable host:port):
 *   EM_FILTER_MODE=direct EM_FILTER_HOST=203.0.113.9 EM_FILTER_QUERY_PORT=9600 \
 *   EM_DISCO_HOST=disco.example.com EM_DISCO_PORT=443 ./build/echo_filter
 *
 * Both at once:
 *   EM_FILTER_MODE=both ... ./build/echo_filter
 */
#include "em_filter.h"
#include <stdio.h>
#include <string.h>

static const char *CAPS[] = {"search", "query", "echo"};

static em_result_t my_handle(const char *body, cJSON *memory, void *ctx) {
    (void)ctx;
    printf("[echo_filter] query: %s\n", body);

    /* Build result: [{url:"...", title:"...", resume:"..."}] — see
     * canonical_response (spec §3) for how these three fields get signed. */
    cJSON *arr  = cJSON_CreateArray();
    cJSON *item = cJSON_CreateObject();

    cJSON_AddStringToObject(item, "url", "https://example.com");

    char title[512];
    snprintf(title, sizeof(title), "Echo: %s", body);
    cJSON_AddStringToObject(item, "title", title);
    cJSON_AddStringToObject(item, "resume", "Echoes the query back as a result.");

    cJSON_AddItemToArray(arr, item);

    /* Memory unchanged: return the same pointer (SDK keeps it). */
    return (em_result_t){ .result = arr, .new_memory = memory };
}

int main(void) {
    em_handler_t handler = {
        .handle           = my_handle,
        .capabilities     = CAPS,
        .capabilities_len = 3,
        .ctx              = NULL,
    };

    em_config_t config = {0};  /* all defaults: EM_FILTER_MODE=relay, env-resolved disco nodes */

    em_filter_t *runner = em_filter_create("echo_filter", &handler, &config);
    em_filter_run(runner);       /* blocks forever */
    em_filter_destroy(runner);
    return 0;
}
