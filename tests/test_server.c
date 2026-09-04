/* Model A HTTP server tests: /health, /agent/query (signed), /pop/gossip. */
#include "em_filter.h"
#include "em_filter/identity.h"
#include "em_filter/crypto.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
   typedef SOCKET sock_t;
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
   typedef int sock_t;
#endif

/* server.h is internal (src/), not installed — include it directly by
 * relative path since tests live alongside src/ in the same repo build. */
#include "../src/server.h"

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); failures++; } \
    else { printf("PASS: %s\n", (msg)); } \
} while (0)

static em_result_t echo_handle(const char *body, cJSON *memory, void *ctx) {
    (void)ctx;
    cJSON *items = cJSON_CreateArray();
    cJSON *item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "url", "https://x/1");
    cJSON_AddStringToObject(item, "title", "T");
    char resume[256];
    snprintf(resume, sizeof(resume), "echo:%s", body);
    cJSON_AddStringToObject(item, "resume", resume);
    cJSON_AddItemToArray(items, item);
    return (em_result_t){ .result = items, .new_memory = memory };
}

/* Tiny blocking HTTP/1.1 client sufficient for our own server's responses
 * (Content-Length framing, Connection: close). Returns 0 on success. */
static int http_request(int port, const char *method, const char *path,
                         const char *body, int *out_status, char *out_body, size_t out_cap) {
    sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) return -1;

    char req[4096];
    size_t body_len = body ? strlen(body) : 0;
    int n = snprintf(req, sizeof(req),
        "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: %zu\r\n\r\n%s",
        method, path, body_len, body ? body : "");
#ifdef _WIN32
    send(fd, req, n, 0);
#else
    write(fd, req, (size_t)n);
#endif

    char resp[65536];
    size_t total = 0;
    for (;;) {
#ifdef _WIN32
        int r = recv(fd, resp + total, (int)(sizeof(resp) - 1 - total), 0);
#else
        int r = (int)read(fd, resp + total, sizeof(resp) - 1 - total);
#endif
        if (r <= 0) break;
        total += (size_t)r;
        if (total >= sizeof(resp) - 1) break;
    }
    resp[total] = '\0';
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif

    sscanf(resp, "HTTP/1.1 %d", out_status);
    const char *sep = strstr(resp, "\r\n\r\n");
    if (sep) {
        strncpy(out_body, sep + 4, out_cap - 1);
        out_body[out_cap - 1] = '\0';
    } else {
        out_body[0] = '\0';
    }
    return 0;
}

int main(void) {
    const char *key_dir = "test_server_keydir";
    const char *caps[] = {"search"};
    em_identity_t *ident = em_identity_create("srv", key_dir, caps, 1);
    CHECK(ident != NULL, "identity created for server test");

    em_handler_t handler = { .handle = echo_handle, .capabilities = caps, .capabilities_len = 1, .ctx = NULL };

    em_agent_server_t *srv = em_agent_server_create(ident, &handler, "127.0.0.1", 0);
    CHECK(em_agent_server_start(srv) == 0, "server starts");
    int port = em_agent_server_port(srv);
    CHECK(port > 0, "server bound to a non-zero ephemeral port");

    int status;
    char body[8192];

    /* /health */
    CHECK(http_request(port, "GET", "/health", NULL, &status, body, sizeof(body)) == 0,
          "GET /health request succeeds");
    CHECK(status == 200 && strncmp(body, "ok", 2) == 0, "GET /health returns 200 ok");

    /* /agent/query — signed response verifies */
    CHECK(http_request(port, "POST", "/agent/query", "{\"query\":\"hi\"}", &status, body, sizeof(body)) == 0,
          "POST /agent/query request succeeds");
    CHECK(status == 200, "POST /agent/query returns 200");
    cJSON *resp = cJSON_Parse(body);
    CHECK(resp != NULL, "response body parses as JSON");
    cJSON *signer_id_j = cJSON_GetObjectItemCaseSensitive(resp, "signer_id");
    cJSON *sig_j = cJSON_GetObjectItemCaseSensitive(resp, "signature");
    cJSON *items = cJSON_GetObjectItemCaseSensitive(resp, "results");
    CHECK(cJSON_IsString(signer_id_j) && cJSON_IsString(sig_j) && cJSON_IsArray(items),
          "response has signer_id/signature/results");

    unsigned char signer_id_decoded[EM_ID_LEN], sig_decoded[EM_SIG_LEN];
    em_b64_decode(signer_id_j->valuestring, signer_id_decoded, sizeof(signer_id_decoded));
    em_b64_decode(sig_j->valuestring, sig_decoded, sizeof(sig_decoded));
    CHECK(memcmp(signer_id_decoded, ident->id, EM_ID_LEN) == 0, "signer_id matches ident->id");

    size_t cr_len = 0;
    unsigned char *cr = em_canonical_response(items, &cr_len);
    CHECK(em_verify(cr, cr_len, sig_decoded, ident->pub), "signature verifies against ident->pub");
    free(cr);
    cJSON_Delete(resp);

    /* malformed query -> 400 */
    CHECK(http_request(port, "POST", "/agent/query", "{}", &status, body, sizeof(body)) == 0,
          "POST /agent/query with missing query succeeds at transport level");
    CHECK(status == 400, "POST /agent/query with missing query returns 400");

    /* /pop/gossip -> replies with our own gossip payload */
    CHECK(http_request(port, "POST", "/pop/gossip", "{\"id\":\"anything\"}", &status, body, sizeof(body)) == 0,
          "POST /pop/gossip request succeeds");
    CHECK(status == 200, "POST /pop/gossip returns 200");
    cJSON *gresp = cJSON_Parse(body);
    cJSON *role = gresp ? cJSON_GetObjectItemCaseSensitive(gresp, "role") : NULL;
    CHECK(cJSON_IsString(role) && strcmp(role->valuestring, "filter") == 0,
          "POST /pop/gossip reply has role == filter");
    if (gresp) cJSON_Delete(gresp);

    em_agent_server_stop(srv);
    em_agent_server_destroy(srv);
    em_identity_destroy(ident);

    if (failures) { fprintf(stderr, "\n%d check(s) FAILED\n", failures); return 1; }
    printf("\nAll server checks PASSED\n");
    return 0;
}
