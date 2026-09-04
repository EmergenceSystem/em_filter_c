/* Model B RelayClient: a stub WS server (hand-rolled RFC 6455 handshake +
 * unmasked/masked framing) plays the disco side — replies hello_ok to
 * hello, sends one query, and asserts the client answers with a verifiable
 * signed result. */
#include "em_filter/identity.h"
#include "em_filter/crypto.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
   typedef SOCKET sock_t;
   typedef HANDLE em_test_thread_t;
#  define SOCK_INVALID INVALID_SOCKET
#  define closesocket_ closesocket
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <pthread.h>
   typedef int sock_t;
   typedef pthread_t em_test_thread_t;
#  define SOCK_INVALID (-1)
#  define closesocket_ close
#endif

#include <openssl/sha.h>

#include "../src/wsclient.h"

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); failures++; } \
    else { printf("PASS: %s\n", (msg)); } \
} while (0)

/* ── echo handler under test: one embryo per query, memory unchanged ──── */
static em_result_t echo_handle(const char *body, cJSON *memory, void *ctx) {
    (void)ctx;
    cJSON *items = cJSON_CreateArray();
    cJSON *item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "url", "https://x/relay");
    cJSON_AddStringToObject(item, "title", "Relay");
    char resume[256];
    snprintf(resume, sizeof(resume), "relay-echo:%s", body);
    cJSON_AddStringToObject(item, "resume", resume);
    cJSON_AddItemToArray(items, item);
    return (em_result_t){ .result = items, .new_memory = memory };
}

/* ── tiny base64 (standard, padded) — mirrors websocket.c's private one ── */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void b64encode(const unsigned char *src, size_t len, char *dst) {
    size_t out = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned int b = (unsigned int)src[i] << 16;
        if (i+1 < len) b |= (unsigned int)src[i+1] << 8;
        if (i+2 < len) b |= (unsigned int)src[i+2];
        dst[out++] = B64[(b >> 18) & 0x3f];
        dst[out++] = B64[(b >> 12) & 0x3f];
        dst[out++] = (i+1 < len) ? B64[(b >>  6) & 0x3f] : '=';
        dst[out++] = (i+2 < len) ? B64[(b      ) & 0x3f] : '=';
    }
    dst[out] = '\0';
}

static int read_exact(sock_t fd, void *buf, size_t len) {
    char *p = (char *)buf;
    size_t got = 0;
    while (got < len) {
        int r = (int)read(fd, p + got, len - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* ── stub WS server side (RFC 6455 §4.2 handshake) ──────────────────────── */
static int ws_stub_handshake(sock_t fd) {
    char head[8192];
    size_t n = 0;
    while (n + 1 < sizeof(head)) {
        char c;
        int r = (int)read(fd, &c, 1);
        if (r <= 0) return -1;
        head[n++] = c;
        if (n >= 4 && head[n-4]=='\r' && head[n-3]=='\n' && head[n-2]=='\r' && head[n-1]=='\n') {
            head[n] = '\0';
            break;
        }
    }

    const char *key_hdr = strstr(head, "Sec-WebSocket-Key:");
    if (!key_hdr) return -1;
    key_hdr += strlen("Sec-WebSocket-Key:");
    while (*key_hdr == ' ') key_hdr++;
    char key[128];
    int ki = 0;
    while (*key_hdr && *key_hdr != '\r' && ki < 127) key[ki++] = *key_hdr++;
    key[ki] = '\0';

    char accept_input[256];
    snprintf(accept_input, sizeof(accept_input), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    unsigned char sha[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)accept_input, strlen(accept_input), sha);
    char accept_b64[64];
    b64encode(sha, SHA_DIGEST_LENGTH, accept_b64);

    char resp[512];
    int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
        accept_b64);
    return write(fd, resp, (size_t)rlen) == rlen ? 0 : -1;
}

/* server → client frames are sent unmasked (RFC 6455 §5.1). */
static void ws_stub_send_text(sock_t fd, const char *text) {
    size_t len = strlen(text);
    unsigned char header[4];
    int hlen;
    header[0] = 0x81; /* FIN + text opcode */
    if (len <= 125) {
        header[1] = (unsigned char)len;
        hlen = 2;
    } else {
        header[1] = 126;
        header[2] = (unsigned char)(len >> 8);
        header[3] = (unsigned char)(len & 0xff);
        hlen = 4;
    }
    write(fd, header, (size_t)hlen);
    write(fd, text, len);
}

/* client → server frames arrive masked; unmask and return heap string. */
static char *ws_stub_recv_text(sock_t fd) {
    unsigned char hdr[2];
    if (read_exact(fd, hdr, 2) < 0) return NULL;
    int opcode = hdr[0] & 0x0f;
    int masked = (hdr[1] & 0x80) >> 7;
    uint64_t plen = hdr[1] & 0x7f;

    if (plen == 126) {
        unsigned char ext[2];
        if (read_exact(fd, ext, 2) < 0) return NULL;
        plen = ((uint64_t)ext[0] << 8) | ext[1];
    }

    unsigned char mask[4] = {0};
    if (masked && read_exact(fd, mask, 4) < 0) return NULL;

    char *payload = malloc(plen + 1);
    if (!payload) return NULL;
    if (read_exact(fd, payload, (size_t)plen) < 0) { free(payload); return NULL; }
    payload[plen] = '\0';
    if (masked) {
        for (size_t i = 0; i < plen; i++) payload[i] ^= mask[i % 4];
    }
    if (opcode == 0x8) { free(payload); return NULL; }
    return payload;
}

/* ── the stub server run: one connection, hello -> hello_ok -> query -> result ── */
typedef struct {
    sock_t listen_fd;
    int    saw_hello;
    int    saw_valid_selfsig;
    int    saw_result;
    int    result_ok;
    unsigned char peer_pub[EM_PUBKEY_LEN];
} stub_state_t;

static void run_stub_server(stub_state_t *st) {
    struct sockaddr_in peer;
    socklen_t pl = sizeof(peer);
    sock_t fd = accept(st->listen_fd, (struct sockaddr *)&peer, &pl);
    if (fd == SOCK_INVALID) return;

    if (ws_stub_handshake(fd) != 0) { closesocket_(fd); return; }

    /* hello */
    char *hello_raw = ws_stub_recv_text(fd);
    unsigned char peer_id[EM_ID_LEN] = {0};
    if (hello_raw) {
        cJSON *hello = cJSON_Parse(hello_raw);
        free(hello_raw);
        if (hello) {
            cJSON *action = cJSON_GetObjectItemCaseSensitive(hello, "action");
            st->saw_hello = cJSON_IsString(action) && strcmp(action->valuestring, "hello") == 0;

            cJSON *pub_j = cJSON_GetObjectItemCaseSensitive(hello, "pubkey");
            cJSON *sig_j = cJSON_GetObjectItemCaseSensitive(hello, "sig");
            cJSON *name_j = cJSON_GetObjectItemCaseSensitive(hello, "name");
            if (cJSON_IsString(pub_j) && cJSON_IsString(sig_j) && cJSON_IsString(name_j)) {
                unsigned char pub[EM_PUBKEY_LEN], sig[EM_SIG_LEN];
                em_b64_decode(pub_j->valuestring, pub, sizeof(pub));
                em_b64_decode(sig_j->valuestring, sig, sizeof(sig));
                em_id_of(pub, peer_id);
                memcpy(st->peer_pub, pub, EM_PUBKEY_LEN);

                unsigned char ci[512];
                size_t ci_len = em_canonical_identity(peer_id, name_j->valuestring, ci, sizeof(ci));
                st->saw_valid_selfsig = em_verify(ci, ci_len, sig, pub);
            }
            cJSON_Delete(hello);
        }
    }

    /* hello_ok */
    char id_b64[32];
    em_b64_encode(peer_id, EM_ID_LEN, id_b64, sizeof(id_b64));
    char ack[128];
    snprintf(ack, sizeof(ack), "{\"action\":\"hello_ok\",\"id\":\"%s\"}", id_b64);
    ws_stub_send_text(fd, ack);

    /* query */
    ws_stub_send_text(fd, "{\"action\":\"query\",\"id\":\"q1\",\"body\":\"hi\"}");

    /* result */
    char *result_raw = ws_stub_recv_text(fd);
    if (result_raw) {
        cJSON *result = cJSON_Parse(result_raw);
        free(result_raw);
        if (result) {
            cJSON *action = cJSON_GetObjectItemCaseSensitive(result, "action");
            cJSON *qid = cJSON_GetObjectItemCaseSensitive(result, "id");
            cJSON *items = cJSON_GetObjectItemCaseSensitive(result, "results");
            cJSON *signer_id_j = cJSON_GetObjectItemCaseSensitive(result, "signer_id");
            cJSON *sig_j = cJSON_GetObjectItemCaseSensitive(result, "signature");

            st->saw_result = cJSON_IsString(action) && strcmp(action->valuestring, "result") == 0
                           && cJSON_IsString(qid) && strcmp(qid->valuestring, "q1") == 0
                           && cJSON_IsArray(items)
                           && cJSON_IsString(signer_id_j) && cJSON_IsString(sig_j);

            if (st->saw_result) {
                unsigned char signer_id[EM_ID_LEN], sig[EM_SIG_LEN];
                em_b64_decode(signer_id_j->valuestring, signer_id, sizeof(signer_id));
                em_b64_decode(sig_j->valuestring, sig, sizeof(sig));

                size_t cr_len = 0;
                unsigned char *cr = em_canonical_response(items, &cr_len);
                st->result_ok = (memcmp(signer_id, peer_id, EM_ID_LEN) == 0)
                              && em_verify(cr, cr_len, sig, st->peer_pub);
                free(cr);
            }
            cJSON_Delete(result);
        }
    }

    closesocket_(fd);
}

typedef struct { stub_state_t *st; } stub_thread_arg_t;

static void *stub_thread_fn(void *arg) {
    stub_thread_arg_t *a = (stub_thread_arg_t *)arg;
    run_stub_server(a->st);
    return NULL;
}

int main(void) {
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    const char *key_dir = "test_wsclient_keydir";
    const char *caps[] = {"search"};
    em_identity_t *ident = em_identity_create("relay_test", key_dir, caps, 1);
    CHECK(ident != NULL, "identity created for wsclient test");

    /* bind the stub server */
    sock_t listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(listen_fd, 1);
    struct sockaddr_in bound;
    socklen_t bl = sizeof(bound);
    getsockname(listen_fd, (struct sockaddr *)&bound, &bl);
    int port = ntohs(bound.sin_port);

    stub_state_t st = {0};
    st.listen_fd = listen_fd;

    /* run the stub server on a background thread so main() can drive the
     * client synchronously against it. */
    pthread_t stub_tid;
    stub_thread_arg_t sarg = { .st = &st };
    CHECK(pthread_create(&stub_tid, NULL, stub_thread_fn, &sarg) == 0, "stub server thread starts");

    em_handler_t handler = { .handle = echo_handle, .capabilities = caps, .capabilities_len = 1, .ctx = NULL };
    em_relay_client_t *client = em_relay_client_create(ident, &handler, "127.0.0.1", port, 0, 5000);
    CHECK(client != NULL, "relay client created");

    int session_rc = em_relay_client_session(client);
    CHECK(session_rc == 0, "relay client session completes (hello_ok received, query answered)");

    pthread_join(stub_tid, NULL);

    CHECK(st.saw_hello, "stub server received a hello action");
    CHECK(st.saw_valid_selfsig, "hello payload self-signature verifies against its own pubkey");
    CHECK(st.saw_result, "stub server received a well-shaped result action for id q1");
    CHECK(st.result_ok, "result signer_id matches identity id and signature verifies against its pubkey");

    closesocket_(listen_fd);
    em_relay_client_destroy(client);
    em_identity_destroy(ident);

    if (failures) { fprintf(stderr, "\n%d check(s) FAILED\n", failures); return 1; }
    printf("\nAll wsclient checks PASSED\n");
    return 0;
}
