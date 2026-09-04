/* Model A gossip push loop: a stub HTTP server accepts one /pop/gossip POST
 * from em_gossip_pusher and verifies its shape + self-signature. */
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
#  define SOCK_INVALID INVALID_SOCKET
#  define closesocket_ closesocket
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
   typedef int sock_t;
#  define SOCK_INVALID (-1)
#  define closesocket_ close
#endif

#include "../src/gossip.h"

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); failures++; } \
    else { printf("PASS: %s\n", (msg)); } \
} while (0)

/* Bind a listening socket on 127.0.0.1:0, return fd and the bound port. */
static sock_t stub_listen(int *out_port) {
    sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(fd, 1);

    struct sockaddr_in bound;
    socklen_t bl = sizeof(bound);
    getsockname(fd, (struct sockaddr *)&bound, &bl);
    *out_port = ntohs(bound.sin_port);
    return fd;
}

/* Accept one connection, read the request (headers + Content-Length body),
 * reply 200 with a trivial JSON body, close. Returns the parsed request
 * body as a heap string (caller frees), or NULL on error. Also sets
 * *out_path to the request path (caller-owned buffer). */
static char *stub_accept_one(sock_t listen_fd, char *out_path, size_t path_cap) {
    struct sockaddr_in peer;
    socklen_t pl = sizeof(peer);
    sock_t fd = accept(listen_fd, (struct sockaddr *)&peer, &pl);
    if (fd == SOCK_INVALID) return NULL;

    char head[8192];
    size_t n = 0;
    while (n + 1 < sizeof(head)) {
        char c;
        int r = (int)read(fd, &c, 1);
        if (r <= 0) { closesocket_(fd); return NULL; }
        head[n++] = c;
        if (n >= 4 && head[n-4]=='\r' && head[n-3]=='\n' && head[n-2]=='\r' && head[n-1]=='\n') {
            head[n] = '\0';
            break;
        }
    }

    char method[8] = "";
    sscanf(head, "%7s %255s", method, out_path);
    (void)path_cap;

    long content_length = 0;
    const char *cl = strstr(head, "Content-Length:");
    if (cl) content_length = strtol(cl + strlen("Content-Length:"), NULL, 10);

    char *body = malloc((size_t)content_length + 1);
    long got = 0;
    while (got < content_length) {
        int r = (int)read(fd, body + got, (size_t)(content_length - got));
        if (r <= 0) break;
        got += r;
    }
    body[got] = '\0';

    const char *resp_body = "{\"ok\":true}";
    char resp[256];
    int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
        strlen(resp_body), resp_body);
    write(fd, resp, (size_t)rlen);
    closesocket_(fd);

    return body;
}

int main(void) {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    const char *key_dir = "test_gossip_keydir";
    const char *caps[] = {"search"};
    em_identity_t *ident = em_identity_create("gossiper", key_dir, caps, 1);
    CHECK(ident != NULL, "identity created for gossip test");

    int port;
    sock_t listen_fd = stub_listen(&port);
    CHECK(listen_fd != SOCK_INVALID, "stub /pop/gossip server bound");

    em_disco_node_t seeds[1];
    memset(seeds, 0, sizeof(seeds));
    strncpy(seeds[0].host, "127.0.0.1", sizeof(seeds[0].host) - 1);
    seeds[0].port = port;
    seeds[0].tls = 0;

    em_gossip_pusher_t *pusher = em_gossip_pusher_create(ident, seeds, 1, "1.2.3.4", 9600, 100);
    CHECK(pusher != NULL, "gossip pusher created");
    CHECK(em_gossip_pusher_start(pusher) == 0, "gossip pusher starts");

    char path[256] = "";
    char *body = stub_accept_one(listen_fd, path, sizeof(path));
    CHECK(body != NULL, "stub server received a request");
    CHECK(strcmp(path, "/pop/gossip") == 0, "request path is /pop/gossip");

    cJSON *payload = body ? cJSON_Parse(body) : NULL;
    CHECK(payload != NULL, "gossip push body parses as JSON");

    cJSON *id_j = payload ? cJSON_GetObjectItemCaseSensitive(payload, "id") : NULL;
    cJSON *host_j = payload ? cJSON_GetObjectItemCaseSensitive(payload, "host") : NULL;
    cJSON *qport_j = payload ? cJSON_GetObjectItemCaseSensitive(payload, "query_port") : NULL;
    cJSON *role_j = payload ? cJSON_GetObjectItemCaseSensitive(payload, "role") : NULL;
    cJSON *pub_j = payload ? cJSON_GetObjectItemCaseSensitive(payload, "pubkey") : NULL;
    cJSON *sig_j = payload ? cJSON_GetObjectItemCaseSensitive(payload, "sig") : NULL;

    CHECK(cJSON_IsString(host_j) && strcmp(host_j->valuestring, "1.2.3.4") == 0,
          "gossip payload host == advertise_host");
    CHECK(cJSON_IsNumber(qport_j) && qport_j->valueint == 9600,
          "gossip payload query_port == 9600");
    CHECK(cJSON_IsString(role_j) && strcmp(role_j->valuestring, "filter") == 0,
          "gossip payload role == filter");

    if (cJSON_IsString(id_j) && cJSON_IsString(pub_j) && cJSON_IsString(sig_j)) {
        unsigned char id_decoded[EM_ID_LEN], pub_decoded[EM_PUBKEY_LEN], sig_decoded[EM_SIG_LEN];
        em_b64_decode(id_j->valuestring, id_decoded, sizeof(id_decoded));
        em_b64_decode(pub_j->valuestring, pub_decoded, sizeof(pub_decoded));
        em_b64_decode(sig_j->valuestring, sig_decoded, sizeof(sig_decoded));

        CHECK(memcmp(id_decoded, ident->id, EM_ID_LEN) == 0, "gossip payload id == ident->id");
        CHECK(memcmp(pub_decoded, ident->pub, EM_PUBKEY_LEN) == 0, "gossip payload pubkey == ident->pub");

        unsigned char ci[512];
        size_t ci_len = em_canonical_identity(ident->id, ident->name, ci, sizeof(ci));
        CHECK(em_verify(ci, ci_len, sig_decoded, ident->pub), "gossip payload self-sig verifies");
    } else {
        CHECK(0, "gossip payload has id/pubkey/sig strings");
    }

    if (payload) cJSON_Delete(payload);
    free(body);
    closesocket_(listen_fd);

    em_gossip_pusher_destroy(pusher);
    em_identity_destroy(ident);

    if (failures) { fprintf(stderr, "\n%d check(s) FAILED\n", failures); return 1; }
    printf("\nAll gossip checks PASSED\n");
    return 0;
}
