/**
 * echo_filter — exemple minimal d'un agent em_filter en C.
 *
 * Build:
 *   cmake -B build && cmake --build build
 *   ./build/echo_filter
 *
 * Avec un broker distant:
 *   EM_DISCO_HOST=disco.example.com EM_DISCO_PORT=443 \
 *   EM_FILTER_JWT_TOKEN=eyJ... ./build/echo_filter
 */
#include "em_filter.h"
#include <stdio.h>
#include <string.h>

static const char *CAPS[] = {"search", "query", "echo"};

static em_result_t my_handle(const char *body, cJSON *memory, void *ctx) {
    (void)ctx;
    printf("[echo_filter] query: %s\n", body);

    /* Build result: [{type:"url", properties:{url:"...", title:"Echo: <body>"}}] */
    cJSON *arr  = cJSON_CreateArray();
    cJSON *item = cJSON_CreateObject();
    cJSON *props = cJSON_CreateObject();

    cJSON_AddStringToObject(props, "url",   "https://example.com");

    char title[512];
    snprintf(title, sizeof(title), "Echo: %s", body);
    cJSON_AddStringToObject(props, "title", title);

    cJSON_AddStringToObject(item,  "type", "url");
    cJSON_AddItemToObject(item,    "properties", props);
    cJSON_AddItemToArray(arr, item);

    /* Memory unchanged: return same pointer (SDK keeps it) */
    return (em_result_t){ .result = arr, .new_memory = memory };
}

int main(void) {
    em_handler_t handler = {
        .handle           = my_handle,
        .capabilities     = CAPS,
        .capabilities_len = 3,
        .ctx              = NULL,
    };

    em_config_t config = {0};  /* all defaults: reads env vars + emergence.conf */

    em_filter_t *runner = em_filter_create("echo_filter", &handler, &config);
    em_filter_run(runner);
    em_filter_destroy(runner);
    return 0;
}
