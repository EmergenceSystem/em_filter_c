#include "server.h"
#include "em_filter/crypto.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
   typedef SOCKET sock_t;
#  define SOCK_INVALID INVALID_SOCKET
#  define close_sock closesocket
#  include <windows.h>
   typedef HANDLE em_thread_t;
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <pthread.h>
   typedef int sock_t;
#  define SOCK_INVALID (-1)
#  define close_sock close
   typedef pthread_t em_thread_t;
#endif

struct em_agent_server {
    em_identity_t *ident;
    em_handler_t  *handler;
    cJSON         *memory;

    char           advertise_host[256];
    int            port;

    sock_t         listen_fd;
    int            running;    /* 0/1, set before start, cleared to request stop */
    em_thread_t    thread;
    int            has_thread;
};

em_agent_server_t *em_agent_server_create(em_identity_t *ident, em_handler_t *handler,
                                           const char *host, int port) {
    em_agent_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    srv->ident = ident;
    srv->handler = handler;
    srv->memory = cJSON_CreateObject();
    strncpy(srv->advertise_host, host ? host : "0.0.0.0", sizeof(srv->advertise_host) - 1);
    srv->port = port;
    srv->listen_fd = SOCK_INVALID;
    return srv;
}

int em_agent_server_port(const em_agent_server_t *srv) { return srv->port; }
const char *em_agent_server_advertise_host(const em_agent_server_t *srv) { return srv->advertise_host; }

/* ── Minimal HTTP/1.1 request/response I/O ───────────────────────────── */

static void send_response(sock_t fd, int code, const char *code_text,
                           const char *content_type, const char *body, size_t body_len) {
    char header[256];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        code, code_text, content_type, body_len);
#ifdef _WIN32
    send(fd, header, hlen, 0);
    if (body_len) send(fd, body, (int)body_len, 0);
#else
    write(fd, header, (size_t)hlen);
    if (body_len) write(fd, body, body_len);
#endif
}

static void send_json(sock_t fd, int code, const char *code_text, cJSON *obj) {
    char *s = cJSON_PrintUnformatted(obj);
    send_response(fd, code, code_text, "application/json", s, s ? strlen(s) : 0);
    free(s);
}

/* Reads the request line + headers (up to "\r\n\r\n"), then any body per
 * Content-Length. Returns 0 on success, -1 on error/malformed request. */
typedef struct {
    char method[8];
    char path[256];
    long content_length;
    char *body; /* heap, NUL-terminated; may be empty string */
} http_request_t;

static int recv_line_headers(sock_t fd, char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
#ifdef _WIN32
        int r = recv(fd, &c, 1, 0);
#else
        int r = (int)read(fd, &c, 1);
#endif
        if (r <= 0) return -1;
        buf[n++] = c;
        if (n >= 4 && buf[n-4]=='\r' && buf[n-3]=='\n' && buf[n-2]=='\r' && buf[n-1]=='\n') {
            buf[n] = '\0';
            return 0;
        }
    }
    return -1;
}

static int parse_request(sock_t fd, http_request_t *req) {
    memset(req, 0, sizeof(*req));
    char head[8192];
    if (recv_line_headers(fd, head, sizeof(head)) != 0) return -1;

    if (sscanf(head, "%7s %255s", req->method, req->path) != 2) return -1;

    req->content_length = 0;
    const char *cl = strstr(head, "Content-Length:");
    if (!cl) cl = strstr(head, "content-length:");
    if (cl) req->content_length = strtol(cl + strlen("Content-Length:"), NULL, 10);

    if (req->content_length < 0) req->content_length = 0;
    if (req->content_length > 8 * 1024 * 1024) return -1; /* refuse absurd bodies */

    req->body = malloc((size_t)req->content_length + 1);
    if (!req->body) return -1;
    long got = 0;
    while (got < req->content_length) {
#ifdef _WIN32
        int r = recv(fd, req->body + got, (int)(req->content_length - got), 0);
#else
        int r = (int)read(fd, req->body + got, (size_t)(req->content_length - got));
#endif
        if (r <= 0) { free(req->body); req->body = NULL; return -1; }
        got += r;
    }
    req->body[req->content_length] = '\0';
    return 0;
}

/* ── Route handlers ───────────────────────────────────────────────────── */

static void handle_agent_query(em_agent_server_t *srv, sock_t fd, const char *body) {
    cJSON *parsed = cJSON_Parse(body);
    cJSON *q = parsed ? cJSON_GetObjectItemCaseSensitive(parsed, "query") : NULL;
    if (!parsed || !cJSON_IsString(q)) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "bad query");
        send_json(fd, 400, "Bad Request", err);
        cJSON_Delete(err);
        if (parsed) cJSON_Delete(parsed);
        return;
    }

    em_result_t r;
    int handler_failed = 0;
    if (srv->handler && srv->handler->handle) {
        r = srv->handler->handle(q->valuestring, srv->memory, srv->handler->ctx);
    } else {
        handler_failed = 1;
        r.result = NULL;
        r.new_memory = NULL;
    }

    if (handler_failed) {
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "handler error");
        send_json(fd, 500, "Internal Server Error", err);
        cJSON_Delete(err);
        cJSON_Delete(parsed);
        return;
    }

    if (r.new_memory && r.new_memory != srv->memory) {
        cJSON_Delete(srv->memory);
        srv->memory = r.new_memory;
    }

    cJSON *items = r.result ? r.result : cJSON_CreateArray();

    char signer_id_b64[32], sig_b64[128];
    em_identity_sign_results(srv->ident, items, signer_id_b64, sizeof(signer_id_b64),
                              sig_b64, sizeof(sig_b64));

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddItemToObject(resp, "results", items); /* resp now owns items */
    cJSON_AddStringToObject(resp, "signer_id", signer_id_b64);
    cJSON_AddStringToObject(resp, "signature", sig_b64);

    send_json(fd, 200, "OK", resp);
    cJSON_Delete(resp);
    cJSON_Delete(parsed);
}

static void handle_pop_gossip(em_agent_server_t *srv, sock_t fd, const char *body) {
    /* Minimal: accept whatever the remote sent (parse-and-discard; SDKs keep
     * only a flat peer map at most, which this server doesn't need to track
     * to answer relay-backs), then reply with our own gossip payload. */
    cJSON *parsed = cJSON_Parse(body);
    if (parsed) cJSON_Delete(parsed);

    cJSON *resp = em_identity_gossip_payload(srv->ident, srv->advertise_host, srv->port);
    send_json(fd, 200, "OK", resp);
    cJSON_Delete(resp);
}

static void handle_connection(em_agent_server_t *srv, sock_t fd) {
    http_request_t req;
    if (parse_request(fd, &req) != 0) {
        send_response(fd, 400, "Bad Request", "text/plain", "bad request", 11);
        close_sock(fd);
        free(req.body);
        return;
    }

    if (strcmp(req.method, "GET") == 0 && strcmp(req.path, "/health") == 0) {
        send_response(fd, 200, "OK", "text/plain", "ok", 2);
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/agent/query") == 0) {
        handle_agent_query(srv, fd, req.body ? req.body : "");
    } else if (strcmp(req.method, "POST") == 0 && strcmp(req.path, "/pop/gossip") == 0) {
        handle_pop_gossip(srv, fd, req.body ? req.body : "");
    } else {
        send_response(fd, 404, "Not Found", "text/plain", "not found", 9);
    }

    free(req.body);
    close_sock(fd);
}

/* ── Accept loop ──────────────────────────────────────────────────────── */

static void *accept_loop(void *arg) {
    em_agent_server_t *srv = (em_agent_server_t *)arg;

    while (srv->running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(srv->listen_fd, &fds);
        struct timeval tv = {0, 200000}; /* 200ms poll so stop() is responsive */

        int sel = select((int)srv->listen_fd + 1, &fds, NULL, NULL, &tv);
        if (sel <= 0) continue;
        if (!srv->running) break;

        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        sock_t fd = accept(srv->listen_fd, (struct sockaddr *)&addr, &addrlen);
        if (fd == SOCK_INVALID) continue;

        handle_connection(srv, fd);
    }
    return NULL;
}

int em_agent_server_start(em_agent_server_t *srv) {
#ifdef _WIN32
    static int wsa_init = 0;
    if (!wsa_init) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        wsa_init = 1;
    }
#endif
    srv->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->listen_fd == SOCK_INVALID) return -1;

    int yes = 1;
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)srv->port);
    if (strcmp(srv->advertise_host, "0.0.0.0") == 0 || strlen(srv->advertise_host) == 0)
        addr.sin_addr.s_addr = INADDR_ANY;
    else if (inet_pton(AF_INET, srv->advertise_host, &addr.sin_addr) != 1)
        addr.sin_addr.s_addr = INADDR_ANY; /* fall back to all-interfaces for hostnames */

    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close_sock(srv->listen_fd);
        srv->listen_fd = SOCK_INVALID;
        return -1;
    }
    if (listen(srv->listen_fd, 16) != 0) {
        close_sock(srv->listen_fd);
        srv->listen_fd = SOCK_INVALID;
        return -1;
    }

    /* Read back the actual bound port (needed when port == 0). */
    struct sockaddr_in bound;
    socklen_t bl = sizeof(bound);
    if (getsockname(srv->listen_fd, (struct sockaddr *)&bound, &bl) == 0)
        srv->port = ntohs(bound.sin_port);

    srv->running = 1;
#ifdef _WIN32
    srv->thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)accept_loop, srv, 0, NULL);
    srv->has_thread = (srv->thread != NULL);
#else
    srv->has_thread = (pthread_create(&srv->thread, NULL, accept_loop, srv) == 0);
#endif
    if (!srv->has_thread) {
        srv->running = 0;
        close_sock(srv->listen_fd);
        srv->listen_fd = SOCK_INVALID;
        return -1;
    }
    return 0;
}

void em_agent_server_stop(em_agent_server_t *srv) {
    if (!srv->running && !srv->has_thread) return;
    srv->running = 0;
    if (srv->has_thread) {
#ifdef _WIN32
        WaitForSingleObject(srv->thread, INFINITE);
        CloseHandle(srv->thread);
#else
        pthread_join(srv->thread, NULL);
#endif
        srv->has_thread = 0;
    }
    if (srv->listen_fd != SOCK_INVALID) {
        close_sock(srv->listen_fd);
        srv->listen_fd = SOCK_INVALID;
    }
}

void em_agent_server_destroy(em_agent_server_t *srv) {
    if (!srv) return;
    em_agent_server_stop(srv);
    if (srv->memory) cJSON_Delete(srv->memory);
    free(srv);
}
