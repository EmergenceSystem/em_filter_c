#include "websocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
   typedef SOCKET sock_t;
#  define SOCK_INVALID INVALID_SOCKET
static char *strcasestr_win(const char *h, const char *n) {
    if (!*n) return (char*)h;
    for (; *h; h++) {
        if (tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            const char *p = h, *q = n;
            while (*p && *q && tolower((unsigned char)*p) == tolower((unsigned char)*q)) { p++; q++; }
            if (!*q) return (char*)h;
        }
    }
    return NULL;
}
#  define strcasestr strcasestr_win
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <unistd.h>
   typedef int sock_t;
#  define SOCK_INVALID (-1)
#  define closesocket close
#endif

#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

/* ── Base64 ────────────────────────────────────────────────────────────── */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const unsigned char *src, size_t len,
                           char *dst, size_t dst_len) {
    size_t out = 0;
    for (size_t i = 0; i < len && out + 4 < dst_len; i += 3) {
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

/* ── Low-level I/O ─────────────────────────────────────────────────────── */

static int sock_write(em_ws_t *ws, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        int n;
        if (ws->ssl)
            n = SSL_write(ws->ssl, p + sent, (int)(len - sent));
        else
#ifdef _WIN32
            n = send(ws->fd, p + sent, (int)(len - sent), 0);
#else
            n = (int)write(ws->fd, p + sent, len - sent);
#endif
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int sock_read_exact(em_ws_t *ws, void *buf, size_t len) {
    char *p = (char *)buf;
    size_t got = 0;
    while (got < len) {
        int n;
        if (ws->ssl)
            n = SSL_read(ws->ssl, p + got, (int)(len - got));
        else
#ifdef _WIN32
            n = recv(ws->fd, p + got, (int)(len - got), 0);
#else
            n = (int)read(ws->fd, p + got, len - got);
#endif
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

/* Read until "\r\n\r\n" — HTTP response headers. Max 4 KB. */
static int read_http_response(em_ws_t *ws, char *buf, size_t buflen) {
    size_t n = 0;
    while (n < buflen - 1) {
        char c;
        if (sock_read_exact(ws, &c, 1) < 0) return -1;
        buf[n++] = c;
        if (n >= 4 &&
            buf[n-4]=='\r' && buf[n-3]=='\n' &&
            buf[n-2]=='\r' && buf[n-1]=='\n') {
            buf[n] = '\0';
            return 0;
        }
    }
    return -1;
}

/* ── TCP connect ───────────────────────────────────────────────────────── */

static sock_t tcp_connect(const char *host, int port) {
#ifdef _WIN32
    static int wsa_init = 0;
    if (!wsa_init) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
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
        closesocket(fd);
        fd = SOCK_INVALID;
    }
    freeaddrinfo(res);
    return fd;
}

/* ── Public: connect + WS upgrade ─────────────────────────────────────── */

int em_ws_connect(em_ws_t *ws, const char *host, int port, int tls,
                  const char *path) {
    memset(ws, 0, sizeof(*ws));

    sock_t fd = tcp_connect(host, port);
    if (fd == SOCK_INVALID) return -1;
    ws->fd = (int)fd;

    if (tls) {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { closesocket(fd); return -1; }
        SSL_CTX_set_default_verify_paths(ctx);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, (int)fd);
        SSL_set_tlsext_host_name(ssl, host);
        if (SSL_connect(ssl) != 1) {
            SSL_free(ssl); SSL_CTX_free(ctx);
            closesocket(fd); return -1;
        }
        ws->ssl     = ssl;
        ws->ssl_ctx = ctx;
    }

    /* Generate Sec-WebSocket-Key: 16 random bytes base64-encoded */
    unsigned char key_bytes[16];
    RAND_bytes(key_bytes, 16);
    char key_b64[25];
    base64_encode(key_bytes, 16, key_b64, sizeof(key_b64));

    /* Send HTTP upgrade request */
    char request[1024];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        path, host, port, key_b64);

    if (sock_write(ws, request, strlen(request)) < 0) {
        em_ws_close(ws); return -1;
    }

    /* Read HTTP response headers */
    char resp[4096];
    if (read_http_response(ws, resp, sizeof(resp)) < 0) {
        em_ws_close(ws); return -1;
    }

    if (!strstr(resp, "101")) {
        em_ws_close(ws); return -1;
    }

    return 0;
}

/* ── Frame writer (RFC 6455 §5.2, client → server, always masked) ──────── */

static int send_frame(em_ws_t *ws, unsigned char opcode,
                       const unsigned char *payload, size_t payload_len) {
    /* Header: max 10 bytes + 4-byte mask + payload */
    unsigned char header[10];
    int header_len = 0;
    header[0] = (unsigned char)(0x80 | opcode);  /* FIN=1 */

    if (payload_len <= 125) {
        header[1] = (unsigned char)(0x80 | payload_len);
        header_len = 2;
    } else if (payload_len <= 65535) {
        header[1] = 0x80 | 126;
        header[2] = (unsigned char)(payload_len >> 8);
        header[3] = (unsigned char)(payload_len & 0xff);
        header_len = 4;
    } else {
        header[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++)
            header[2+i] = (unsigned char)(payload_len >> (56 - 8*i));
        header_len = 10;
    }

    unsigned char mask[4];
    RAND_bytes(mask, 4);

    size_t total = (size_t)header_len + 4 + payload_len;
    unsigned char *buf = malloc(total);
    if (!buf) return -1;

    memcpy(buf, header, (size_t)header_len);
    memcpy(buf + header_len, mask, 4);
    for (size_t i = 0; i < payload_len; i++)
        buf[header_len + 4 + i] = payload[i] ^ mask[i % 4];

    int ret = sock_write(ws, buf, total);
    free(buf);
    return ret;
}

/* ── Public: send text frame ─────────────────────────────────────────── */

int em_ws_send_text(em_ws_t *ws, const char *text) {
    return send_frame(ws, 0x1, (const unsigned char *)text, strlen(text));
}

/* ── Public: receive one text frame (server → client, unmasked) ─────── */

char *em_ws_recv_text(em_ws_t *ws) {
    for (;;) {
        unsigned char hdr[2];
        if (sock_read_exact(ws, hdr, 2) < 0) return NULL;

        uint8_t opcode  = hdr[0] & 0x0f;
        uint8_t masked  = (hdr[1] & 0x80) >> 7;
        uint64_t plen   = hdr[1] & 0x7f;

        if (plen == 126) {
            unsigned char ext[2];
            if (sock_read_exact(ws, ext, 2) < 0) return NULL;
            plen = ((uint64_t)ext[0] << 8) | ext[1];
        } else if (plen == 127) {
            unsigned char ext[8];
            if (sock_read_exact(ws, ext, 8) < 0) return NULL;
            plen = 0;
            for (int i = 0; i < 8; i++) plen = (plen << 8) | ext[i];
        }

        unsigned char fmask[4] = {0};
        if (masked && sock_read_exact(ws, fmask, 4) < 0) return NULL;

        char *payload = malloc(plen + 1);
        if (!payload) return NULL;
        if (sock_read_exact(ws, payload, (size_t)plen) < 0) {
            free(payload); return NULL;
        }
        payload[plen] = '\0';
        if (masked) {
            for (size_t i = 0; i < plen; i++)
                payload[i] ^= fmask[i % 4];
        }

        if (opcode == 0x8) { free(payload); return NULL; }  /* CLOSE */
        if (opcode == 0x9) { /* PING — keepalive: reply PONG with same payload (RFC 6455 §5.5.3) */
            send_frame(ws, 0xA, (const unsigned char *)payload, (size_t)plen);
            free(payload); continue;
        }
        if (opcode == 0xa) { /* PONG — ignore */
            free(payload); continue;
        }
        return payload;  /* opcode 0x1 text or 0x0 continuation */
    }
}

/* ── Public: close ─────────────────────────────────────────────────────── */

void em_ws_close(em_ws_t *ws) {
    if (ws->ssl) {
        SSL_shutdown(ws->ssl);
        SSL_free(ws->ssl);
        ws->ssl = NULL;
    }
    if (ws->ssl_ctx) {
        SSL_CTX_free(ws->ssl_ctx);
        ws->ssl_ctx = NULL;
    }
    if (ws->fd > 0) {
        closesocket(ws->fd);
        ws->fd = 0;
    }
}
