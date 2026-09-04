#include "config_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#  include <windows.h>
#  define strtok_r strtok_s
#  define strncasecmp _strnicmp
#endif

/* ── TLS inference ─────────────────────────────────────────────────────── */

int em_infer_tls(const char *host, int port) {
    if (strcmp(host, "localhost") == 0 ||
        strcmp(host, "127.0.0.1") == 0 ||
        strcmp(host, "::1")       == 0)
        return 0;
    return (port == 443) ? 1 : 0;
}

void em_default_port_tls(const char *host, int *out_port, int *out_tls) {
    if (strcmp(host, "localhost") == 0 ||
        strcmp(host, "127.0.0.1") == 0 ||
        strcmp(host, "::1")       == 0) {
        *out_port = 8080;
        *out_tls  = 0;
    } else {
        *out_port = 443;
        *out_tls  = 1;
    }
}

/* ── Reconnect delay ───────────────────────────────────────────────────── */

int em_reconnect_ms(void) {
    const char *s = getenv("EM_FILTER_RECONNECT_MS");
    if (s) {
        int v = atoi(s);
        if (v > 0) return v;
    }
    return 5000;
}

/* ── emergence.conf path ───────────────────────────────────────────────── */

static void conf_path(char *buf, size_t buflen) {
    buf[0] = '\0';
#ifdef _WIN32
    const char *appdata = getenv("APPDATA");
    if (appdata) {
        snprintf(buf, buflen, "%s\\emergence\\emergence.conf", appdata);
        return;
    }
#else
    const char *home = getenv("HOME");
    if (home) {
        snprintf(buf, buflen, "%s/.config/emergence/emergence.conf", home);
        return;
    }
#endif
}

/* ── Parse comma-separated node list: "localhost:8080, example.com" ─────── */

static int parse_nodes_str(const char *s,
                            em_disco_node_t out[EM_MAX_NODES]) {
    int count = 0;
    char buf[1024];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);
    while (tok && count < EM_MAX_NODES) {
        /* trim whitespace */
        while (*tok && isspace((unsigned char)*tok)) tok++;
        size_t len = strlen(tok);
        while (len > 0 && isspace((unsigned char)tok[len-1])) tok[--len] = '\0';
        if (len == 0) { tok = strtok_r(NULL, ",", &saveptr); continue; }

        em_disco_node_t node = {0};
        /* IPv6 bracket notation: [::1]:9000 */
        if (tok[0] == '[') {
            char *close = strchr(tok, ']');
            if (!close) { tok = strtok_r(NULL, ",", &saveptr); continue; }
            size_t hlen = (size_t)(close - tok - 1);
            strncpy(node.host, tok + 1, hlen < 255 ? hlen : 255);
            node.host[hlen < 255 ? hlen : 255] = '\0';
            if (*(close+1) == ':') {
                node.port = atoi(close + 2);
            } else {
                em_default_port_tls(node.host, &node.port, &node.tls);
            }
            node.tls = em_infer_tls(node.host, node.port);
        } else {
            /* find last ':' for host:port */
            char *last_colon = strrchr(tok, ':');
            if (last_colon) {
                size_t hlen = (size_t)(last_colon - tok);
                strncpy(node.host, tok, hlen < 255 ? hlen : 255);
                node.host[hlen < 255 ? hlen : 255] = '\0';
                node.port = atoi(last_colon + 1);
                node.tls  = em_infer_tls(node.host, node.port);
            } else {
                strncpy(node.host, tok, 255);
                em_default_port_tls(node.host, &node.port, &node.tls);
            }
        }
        out[count++] = node;
        tok = strtok_r(NULL, ",", &saveptr);
    }
    return count;
}

/* ── Parse emergence.conf ───────────────────────────────────────────────── */

static int read_conf_nodes(em_disco_node_t out[EM_MAX_NODES]) {
    char path[1024];
    conf_path(path, sizeof(path));
    if (path[0] == '\0') return 0;

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char section[64] = "";
    char line[512];
    char last_nodes[512] = "";

    while (fgets(line, sizeof(line), f)) {
        /* trim newline */
        size_t l = strlen(line);
        while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = '\0';

        /* trim leading whitespace */
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;

        if (*p == '\0' || *p == ';' || *p == '#') continue;

        if (*p == '[') {
            char *end = strchr(p, ']');
            if (end) {
                size_t slen = (size_t)(end - p - 1);
                strncpy(section, p + 1, slen < 63 ? slen : 63);
                section[slen < 63 ? slen : 63] = '\0';
            }
            continue;
        }

        if (strcmp(section, "em_disco") == 0) {
            char *eq = strchr(p, '=');
            if (eq) {
                *eq = '\0';
                char *key = p;
                char *val = eq + 1;
                /* trim key and val */
                size_t klen = strlen(key);
                while (klen > 0 && isspace((unsigned char)key[klen-1])) key[--klen] = '\0';
                while (*val && isspace((unsigned char)*val)) val++;

                if (strcmp(key, "nodes") == 0) {
                    strncpy(last_nodes, val, sizeof(last_nodes) - 1);
                }
            }
        }
    }
    fclose(f);

    if (last_nodes[0] != '\0') {
        return parse_nodes_str(last_nodes, out);
    }
    return 0;
}

/* ── Public: resolve nodes ─────────────────────────────────────────────── */

int em_resolve_nodes(const em_config_t *cfg,
                     em_disco_node_t out[EM_MAX_NODES]) {
    /* Priority 1: explicit nodes in config */
    if (cfg && cfg->nodes && cfg->nodes_len > 0) {
        int n = cfg->nodes_len < EM_MAX_NODES ? cfg->nodes_len : EM_MAX_NODES;
        memcpy(out, cfg->nodes, (size_t)n * sizeof(em_disco_node_t));
        return n;
    }

    /* Priority 2: env vars */
    const char *host_env = getenv("EM_DISCO_HOST");
    const char *port_env = getenv("EM_DISCO_PORT");

    if (host_env) {
        out[0] = (em_disco_node_t){0};
        strncpy(out[0].host, host_env, 255);
        if (port_env) {
            out[0].port = atoi(port_env);
        } else {
            int dummy_tls;
            em_default_port_tls(out[0].host, &out[0].port, &dummy_tls);
        }
        out[0].tls = em_infer_tls(out[0].host, out[0].port);
        return 1;
    }
    if (port_env) {
        out[0] = (em_disco_node_t){0};
        strcpy(out[0].host, "localhost");
        out[0].port = atoi(port_env);
        out[0].tls  = 0;
        return 1;
    }

    /* Priority 3: emergence.conf */
    int n = read_conf_nodes(out);
    if (n > 0) return n;

    /* Priority 4: default */
    out[0] = (em_disco_node_t){0};
    strcpy(out[0].host, "localhost");
    out[0].port = 8080;
    out[0].tls  = 0;
    return 1;
}

/* ── Public: §4.3 mode dispatch + Model A/B knobs ───────────────────────── */

void em_resolve_mode(const em_config_t *cfg, char out_mode[16]) {
    if (cfg && cfg->mode[0] != '\0') {
        strncpy(out_mode, cfg->mode, 15);
        out_mode[15] = '\0';
        return;
    }
    const char *env = getenv("EM_FILTER_MODE");
    if (env && *env) {
        strncpy(out_mode, env, 15);
        out_mode[15] = '\0';
        return;
    }
    strcpy(out_mode, "relay"); /* spec §4.3: default when the contributor sets nothing */
}

void em_resolve_key_dir(const em_config_t *cfg, const char *name, char *out, size_t out_cap) {
    if (cfg && cfg->key_dir[0] != '\0') {
        strncpy(out, cfg->key_dir, out_cap - 1);
        out[out_cap - 1] = '\0';
        return;
    }
    const char *env = getenv("EM_FILTER_KEY_DIR");
    if (env && *env) {
        strncpy(out, env, out_cap - 1);
        out[out_cap - 1] = '\0';
        return;
    }
    snprintf(out, out_cap, "./empop_key_%s/", name);
}

void em_resolve_advertise_host(const em_config_t *cfg, char *out, size_t out_cap) {
    if (cfg && cfg->advertise_host[0] != '\0') {
        strncpy(out, cfg->advertise_host, out_cap - 1);
        out[out_cap - 1] = '\0';
        return;
    }
    const char *env = getenv("EM_FILTER_HOST");
    if (env && *env) {
        strncpy(out, env, out_cap - 1);
        out[out_cap - 1] = '\0';
        return;
    }
    strcpy(out, "0.0.0.0");
}

int em_resolve_query_port(const em_config_t *cfg) {
    if (cfg && cfg->query_port > 0) return cfg->query_port;
    const char *env = getenv("EM_FILTER_QUERY_PORT");
    if (env) {
        int v = atoi(env);
        if (v > 0) return v;
    }
    return 8090;
}

int em_gossip_interval_ms(void) {
    const char *env = getenv("EM_FILTER_GOSSIP_INTERVAL_MS");
    if (env) {
        int v = atoi(env);
        if (v > 0) return v;
    }
    return 5000;
}
