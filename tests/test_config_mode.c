/* §4.3 mode dispatch + Model A/B config resolution: cfg field takes
 * priority over env var, which takes priority over the documented default.
 * No networking — this is the "runner wiring" piece tested in isolation. */
#include "em_filter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/config_internal.h"

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); failures++; } \
    else { printf("PASS: %s\n", (msg)); } \
} while (0)

int main(void) {
    /* ── mode ─────────────────────────────────────────────────────────── */
    unsetenv("EM_FILTER_MODE");
    char mode[16];

    em_resolve_mode(NULL, mode);
    CHECK(strcmp(mode, "relay") == 0, "mode defaults to relay with no cfg/env");

    setenv("EM_FILTER_MODE", "direct", 1);
    em_resolve_mode(NULL, mode);
    CHECK(strcmp(mode, "direct") == 0, "mode reads EM_FILTER_MODE=direct");

    em_config_t cfg = {0};
    strcpy(cfg.mode, "both");
    em_resolve_mode(&cfg, mode);
    CHECK(strcmp(mode, "both") == 0, "cfg.mode overrides EM_FILTER_MODE");

    unsetenv("EM_FILTER_MODE");

    /* ── key_dir ──────────────────────────────────────────────────────── */
    char key_dir[512];
    em_config_t empty_cfg = {0};
    em_resolve_key_dir(&empty_cfg, "myagent", key_dir, sizeof(key_dir));
    CHECK(strcmp(key_dir, "./empop_key_myagent/") == 0,
          "key_dir defaults to ./empop_key_<name>/");

    setenv("EM_FILTER_KEY_DIR", "/tmp/keys", 1);
    em_resolve_key_dir(&empty_cfg, "myagent", key_dir, sizeof(key_dir));
    CHECK(strcmp(key_dir, "/tmp/keys") == 0, "key_dir reads EM_FILTER_KEY_DIR");
    unsetenv("EM_FILTER_KEY_DIR");

    em_config_t kd_cfg = {0};
    strcpy(kd_cfg.key_dir, "/explicit/dir");
    em_resolve_key_dir(&kd_cfg, "myagent", key_dir, sizeof(key_dir));
    CHECK(strcmp(key_dir, "/explicit/dir") == 0, "cfg.key_dir overrides env/default");

    /* ── advertise_host ───────────────────────────────────────────────── */
    char host[256];
    em_resolve_advertise_host(&empty_cfg, host, sizeof(host));
    CHECK(strcmp(host, "0.0.0.0") == 0, "advertise_host defaults to 0.0.0.0");

    setenv("EM_FILTER_HOST", "203.0.113.9", 1);
    em_resolve_advertise_host(&empty_cfg, host, sizeof(host));
    CHECK(strcmp(host, "203.0.113.9") == 0, "advertise_host reads EM_FILTER_HOST");
    unsetenv("EM_FILTER_HOST");

    /* ── query_port ───────────────────────────────────────────────────── */
    CHECK(em_resolve_query_port(&empty_cfg) == 8090, "query_port defaults to 8090");

    setenv("EM_FILTER_QUERY_PORT", "9700", 1);
    CHECK(em_resolve_query_port(&empty_cfg) == 9700, "query_port reads EM_FILTER_QUERY_PORT");
    unsetenv("EM_FILTER_QUERY_PORT");

    em_config_t qp_cfg = {0};
    qp_cfg.query_port = 12345;
    CHECK(em_resolve_query_port(&qp_cfg) == 12345, "cfg.query_port overrides env/default");

    /* ── gossip interval ──────────────────────────────────────────────── */
    unsetenv("EM_FILTER_GOSSIP_INTERVAL_MS");
    CHECK(em_gossip_interval_ms() == 5000, "gossip interval defaults to 5000ms");

    setenv("EM_FILTER_GOSSIP_INTERVAL_MS", "1500", 1);
    CHECK(em_gossip_interval_ms() == 1500, "gossip interval reads EM_FILTER_GOSSIP_INTERVAL_MS");
    unsetenv("EM_FILTER_GOSSIP_INTERVAL_MS");

    if (failures) { fprintf(stderr, "\n%d check(s) FAILED\n", failures); return 1; }
    printf("\nAll config/mode checks PASSED\n");
    return 0;
}
