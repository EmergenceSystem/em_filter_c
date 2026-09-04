# em_filter_c

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

C SDK for building [Emergence](https://github.com/EmergenceSystem) network agents.

`em_filter_c` lets any C process join the Emergence distributed discovery
network as a **filter agent** — a service that receives search queries from
the mesh (`em_disco` + Emquest), processes them (web search, DNS lookup,
database query, …), and returns ed25519-signed structured results.

This is the mesh-parity SDK: same crypto and wire protocol as the Erlang
`em_filter` leaf library, byte-identical (verified against a shared
cross-language test-vector fixture), and speaking the current signed
`em_pop`/`em_disco` mesh — see [PROTOCOL.md](PROTOCOL.md) for the full wire
format.

---

## How it works

```
 Model B (default, NAT-friendly)          Model A (direct, needs a reachable port)
 ┌─────────────┐   outbound WS    ┌──────────────┐   ┌─────────────┐  inbound HTTP  ┌──────────────┐
 │  em_disco   │ ◄─────────────── │ em_filter_t  │   │  em_disco   │ ─────────────► │ em_filter_t  │
 │  (relay)    │  hello/query/    │ (your agent) │   │  (seed)     │ /agent/query   │ (your agent) │
 └─────────────┘  result          └──────────────┘   └─────────────┘ ◄───────────── │  + gossip    │
                                         │                                   push    │  push loop   │
                                  ┌──────┴──────┐                                    └──────────────┘
                                  │ em_handle_fn│
                                  │  callback   │
                                  └─────────────┘
```

1. `em_filter_create()` builds a runner with your handler callback.
2. `em_filter_run()` loads/creates the ed25519 identity, then starts the
   transport(s) selected by `EM_FILTER_MODE` (§ [Modes](#modes)) and blocks.
3. Your `em_handle_fn` runs on every query and returns results; the SDK
   signs them (ed25519) before sending them back.

Every response is signed and verified by Emquest against the mesh-bound
public key — an unsigned or unbound-signer response is dropped under
`require_signatures = true`.

---

## Requirements

- C11 compiler (GCC, Clang) — targets Linux/macOS via pthreads; a portable
  thread/socket layer is in place for a future Windows build but is
  untested there.
- CMake 3.16+
- OpenSSL (WebSocket TLS + SHA-1 handshake) and **libsodium** (ed25519 +
  SHA-256, via `pkg-config`)
- [cJSON](https://github.com/DaveGamble/cJSON) — bundled in `third_party/`
  (no extra install needed)

---

## Building

```bash
cmake -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

To use the library in your own CMake project:

```cmake
add_subdirectory(em_filter_c)
target_link_libraries(my_filter PRIVATE em_filter)
```

---

## Quick start

```c
#include "em_filter.h"
#include <stdio.h>

static const char *MY_CAPS[] = {"search", "query"};

static em_result_t my_handle(const char *body, cJSON *memory, void *ctx) {
    cJSON *result = cJSON_CreateArray();
    cJSON *item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "url",    "https://example.com");
    cJSON_AddStringToObject(item, "title",  body);
    cJSON_AddStringToObject(item, "resume", "matched your query");
    cJSON_AddItemToArray(result, item);

    return (em_result_t){ .result = result, .new_memory = NULL };
}

int main(void) {
    em_handler_t handler = {
        .handle           = my_handle,
        .capabilities     = MY_CAPS,
        .capabilities_len = 2,
        .ctx              = NULL,
    };
    em_config_t config = {0};   /* all defaults: EM_FILTER_MODE=relay */

    em_filter_t *runner = em_filter_create("my_filter", &handler, &config);
    em_filter_run(runner);       /* blocks forever */
    em_filter_destroy(runner);
    return 0;
}
```

By default the agent relays through `localhost:8080`. Override via
environment variables or `em_config_t` — see [Configuration](#configuration).

See `examples/echo_filter.c` for a runnable version.

---

## The handler callback

```c
typedef em_result_t (*em_handle_fn)(const char *body, cJSON *memory, void *ctx);
```

| Parameter | Description |
|-----------|-------------|
| `body` | Null-terminated query string |
| `memory` | Current memory state (cJSON object, SDK-owned — **do not free**); persists across reconnects (Model B) or the process lifetime (Model A) |
| `ctx` | Opaque user pointer passed via `em_handler_t.ctx` |

Returns `em_result_t`:

```c
typedef struct em_result {
    cJSON *result;      /* items array; SDK signs + sends it, then frees it */
    cJSON *new_memory;  /* next memory state; NULL = keep current memory */
} em_result_t;
```

The SDK takes ownership of `result` and `new_memory` — do not free them
yourself.

### Result format

`result` is a cJSON array of items. Each item's `url` / `title` (or
`label`) / `resume` (or `value`/`description`) fields — read either
straight off the item or from its `properties` sub-object if present — are
what get signed (see [PROTOCOL.md § canonical_response](PROTOCOL.md#1-identity--crypto)).
An empty array means "no results for this query".

### Capabilities

`em_handler_t.capabilities` is a plain array of UTF-8 strings advertised to
the mesh; the disco computes the routing vector from them (SDKs never
compute a vector themselves — see PROTOCOL.md § 4).

---

## Modes

`EM_FILTER_MODE` (or `em_config_t.mode`, which takes priority):

| Mode | Transport | Reachability needed |
|------|-----------|----------------------|
| `relay` (default) | Model B — outbound WS to each disco | None (NAT-friendly) |
| `direct` | Model A — inbound HTTP server + gossip push | `EM_FILTER_HOST:EM_FILTER_QUERY_PORT` must be reachable from the mesh |
| `both` | Both, same identity | Direct's, relay as fallback |

---

## Configuration

### Environment variables

| Variable | Default | Description |
|----------|---------|--------------|
| `EM_DISCO_HOST` / `EM_DISCO_PORT` | — | Disco node (relay target / gossip seed) |
| `EM_FILTER_MODE` | `relay` | `relay` \| `direct` \| `both` |
| `EM_FILTER_KEY_DIR` | `./empop_key_<name>/` | ed25519 keypair directory |
| `EM_FILTER_HOST` | `0.0.0.0` | Advertised host for Model A (`direct`/`both`) |
| `EM_FILTER_QUERY_PORT` | `8090` | Model A HTTP server port (`direct`/`both`) |
| `EM_FILTER_GOSSIP_INTERVAL_MS` | `5000` | Gossip push interval (`direct`/`both`) |
| `EM_FILTER_RECONNECT_MS` | `5000` | Model B reconnect delay |

### Node resolution order

1. `em_config_t.nodes` / `nodes_len` — explicit list (highest priority)
2. `EM_DISCO_HOST` / `EM_DISCO_PORT` env vars
3. `[em_disco] nodes = …` in `emergence.conf`
4. `localhost:8080` — built-in default

### TLS inference

| Host | Port | Transport |
|------|------|-----------|
| `localhost`, `127.0.0.1`, `::1` | any | plain (`ws://` / `http://`) |
| any other | 443 | TLS (`wss://` / `https://`) |
| any other | other | plain |

### `emergence.conf`

```ini
[em_disco]
nodes = localhost:8080, disco.example.com, [::1]:9000
```

Platform paths:
- **Linux / macOS:** `~/.config/emergence/emergence.conf`
- **Windows:** `%APPDATA%\emergence\emergence.conf`

### Programmatic configuration

```c
em_disco_node_t nodes[] = {
    { "disco.example.com",  443, 1 },
};
em_config_t config = {
    .nodes      = nodes,
    .nodes_len  = 1,
    .mode       = "both",
    .query_port = 9600,
};
strcpy(config.advertise_host, "203.0.113.9");
```

---

## HTML utilities

```c
#include "em_filter.h"

/* All functions return heap strings — caller must free() */
char *clean   = em_strip_scripts(html);           /* remove <script>…</script> */
char *text    = em_get_text(clean);               /* strip all tags → plain text */
char *decoded = em_decode_html_entities(text);    /* caf&eacute; → café */
char *href    = em_extract_attribute(elem, "href"); /* NULL if not found */

int skip = em_should_skip_link(url, excluded, excluded_len); /* 1 = skip */

free(clean); free(text); free(decoded); free(href);
```

---

## Protocol

See [PROTOCOL.md](PROTOCOL.md) for the full crypto + wire format (identity,
canonical byte forms, both transports).

---

## License

[MIT](LICENSE)
