#include "http_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
   typedef SOCKET sock_t;
#  define SOCK_INVALID INVALID_SOCKET
#  define closesocket_ closesocket
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <unistd.h>
   typedef int sock_t;
#  define SOCK_INVALID (-1)
#  define closesocket_ close
#endif

#include <openssl/ssl.h>

typedef struct {
    sock_t   fd;
    SSL     *ssl;
    SSL_CTX *ctx;
} conn_t;

static int conn_write(conn_t *c, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        int n;
        if (c->ssl) {
            n = SSL_write(c->ssl, p + sent, (int)(len - sent));
        } else {
#ifdef _WIN32
            n = send(c->fd, p + sent, (int)(len - sent), 0);
#else
            n = (int)write(c->fd, p + sent, len - sent);
#endif
        }
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

/* Returns bytes read (>0), 0 on clean EOF, <0 on error. */
static int conn_read_some(conn_t *c, void *buf, size_t cap) {
    if (c->ssl) return SSL_read(c->ssl, buf, (int)cap);
#ifdef _WIN32
    return recv(c->fd, buf, (int)cap, 0);
#else
    return (int)read(c->fd, buf, cap);
#endif
}

static sock_t tcp_connect(const char *host, int port) {
#ifdef _WIN32
    static int wsa_init = 0;
    if (!wsa_init) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        wsa_init = 1;
    }
#endif
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return SOCK_INVALID;

    sock_t fd = SOCK_INVALID;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd == SOCK_INVALID) continue;
        if (connect(fd, r->ai_addr, (int)r->ai_addrlen) == 0) break;
        closesocket_(fd);
        fd = SOCK_INVALID;
    }
    freeaddrinfo(res);
    return fd;
}

static void conn_close(conn_t *c) {
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); c->ssl = NULL; }
    if (c->ctx) { SSL_CTX_free(c->ctx); c->ctx = NULL; }
    if (c->fd != SOCK_INVALID) { closesocket_(c->fd); c->fd = SOCK_INVALID; }
}

int em_http_post(const char *host, int port, int tls, const char *path,
                  const char *body, size_t body_len,
                  int *out_status, char **out_body) {
    if (out_status) *out_status = 0;
    if (out_body) *out_body = NULL;

    conn_t c = {0};
    c.fd = tcp_connect(host, port);
    if (c.fd == SOCK_INVALID) return -1;

    if (tls) {
        c.ctx = SSL_CTX_new(TLS_client_method());
        if (!c.ctx) { closesocket_(c.fd); return -1; }
        SSL_CTX_set_default_verify_paths(c.ctx);
        c.ssl = SSL_new(c.ctx);
        SSL_set_fd(c.ssl, (int)c.fd);
        SSL_set_tlsext_host_name(c.ssl, host);
        if (SSL_connect(c.ssl) != 1) { conn_close(&c); return -1; }
    }

    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        path, host, port, body_len);

    if (conn_write(&c, header, (size_t)hlen) < 0 ||
        (body_len > 0 && conn_write(&c, body, body_len) < 0)) {
        conn_close(&c);
        return -1;
    }

    /* Read the whole response (headers + body) until EOF; our own
     * gossip peers (real em_disco or the test stub) always close after
     * responding, per "Connection: close" above. */
    size_t cap = 8192, len = 0;
    char *resp = malloc(cap);
    if (!resp) { conn_close(&c); return -1; }
    for (;;) {
        if (len + 4096 > cap) {
            cap *= 2;
            char *grown = realloc(resp, cap);
            if (!grown) { free(resp); conn_close(&c); return -1; }
            resp = grown;
        }
        int n = conn_read_some(&c, resp + len, cap - len - 1);
        if (n <= 0) break;
        len += (size_t)n;
    }
    resp[len] = '\0';
    conn_close(&c);

    int status = 0;
    sscanf(resp, "HTTP/1.1 %d", &status);
    if (out_status) *out_status = status;

    char *sep = strstr(resp, "\r\n\r\n");
    if (out_body && sep) *out_body = strdup(sep + 4);
    free(resp);
    return 0;
}
