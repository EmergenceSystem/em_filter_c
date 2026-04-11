# em_filter_c

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

C SDK for building [Emergence](https://github.com/EmergenceSystem) network agents.

`em_filter_c` lets any C process join the Emergence distributed discovery network
as a **filter agent** — a service that receives search queries from the `em_disco`
broker, processes them (web search, DNS lookup, database query, …), and returns
structured results.

This library is the C equivalent of the Erlang `em_filter` library: same WebSocket
protocol, same configuration contract, minimal C99 API.

---

## How it works

```
 ┌─────────────┐    WebSocket     ┌───────────────┐    WebSocket     ┌─────────────┐
 │  em_disco   │ ◄─────────────── │  em_filter_t  │ ───────────────► │  em_disco   │
 │  (broker)   │  query / result  │  (your agent) │  (multi-node)    │  (replica)  │
 └─────────────┘                  └───────────────┘                  └─────────────┘
                                         │
                                  thread per node
                                         │
                                  ┌──────┴──────┐
                                  │ em_handle_fn│
                                  │  callback   │
                                  └─────────────┘
```

1. `em_filter_create()` builds a runner with your handler callback.
2. `em_filter_run()` connects to all resolved disco nodes (one thread per node) and blocks.
3. Each thread calls your `em_handle_fn` on every `query` frame and sends back a `result`.

---

## Requirements

- C99 compiler (GCC, Clang, MSVC)
- CMake 3.20+
- OpenSSL (for WebSocket TLS; install via system package manager or [vcpkg](https://vcpkg.io/))
- [cJSON](https://github.com/DaveGamble/cJSON) — bundled in `third_party/` (no extra install needed)

---

## Building

```bash
mkdir build && cd build

# Linux / macOS
cmake ..
cmake --build . --config Release

# Windows with vcpkg
cmake .. -DOPENSSL_ROOT_DIR=C:/vcpkg/installed/x64-windows
cmake --build . --config Release
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
#include <string.h>

static const char *MY_CAPS[] = {"search", "query", NULL};

static em_result_t my_handle(const char *body, cJSON *memory, void *ctx) {
    /* Build result: a JSON array of embryo objects */
    cJSON *result = cJSON_CreateArray();
    cJSON *embryo = cJSON_CreateObject();
    cJSON *props  = cJSON_CreateObject();

    cJSON_AddStringToObject(props, "url",   "https://example.com");
    cJSON_AddStringToObject(props, "title", body); /* or format a real title */
    cJSON_AddStringToObject(embryo, "type", "url");
    cJSON_AddItemToObject(embryo, "properties", props);
    cJSON_AddItemToArray(result, embryo);

    return (em_result_t){ .result = result, .new_memory = NULL };
}

int main(void) {
    em_handler_t handler = {
        .handle           = my_handle,
        .capabilities     = MY_CAPS,
        .capabilities_len = 2,
        .ctx              = NULL,
    };
    em_config_t config = { 0 };   /* all defaults */

    em_filter_t *runner = em_filter_create("my_filter", &handler, &config);
    em_filter_run(runner);         /* blocks forever */
    em_filter_destroy(runner);
    return 0;
}
```

By default the agent connects to `localhost:8080`. Override via environment
variables or `em_config_t` — see [Configuration](#configuration).

---

## The handler callback

```c
typedef em_result_t (*em_handle_fn)(const char *body, cJSON *memory, void *ctx);
```

| Parameter | Description |
|-----------|-------------|
| `body` | Null-terminated query string from `em_disco` |
| `memory` | Current memory state (cJSON object, SDK-owned — **do not free**) |
| `ctx` | Opaque user pointer passed to `em_filter_create` via `em_handler_t.ctx` |

Returns `em_result_t`:

```c
typedef struct em_result {
    cJSON *result;      /* JSON to send as "data"; SDK frees after sending */
    cJSON *new_memory;  /* next memory state; NULL = keep current memory */
} em_result_t;
```

The SDK takes ownership of `result` and `new_memory` — do not free them yourself.

### Result format

`result` is typically a cJSON array of **embryo** objects:

| Type | Required properties |
|------|---------------------|
| `"url"` | `url`, `title` |
| `"dns"` | `domain`, `ips` |
| `"text"` | `content` |

`cJSON_CreateNull()` or an empty array means "no results for this query".

### Capabilities

`em_handler_t.capabilities` is a NULL-terminated array of UTF-8 strings.
`em_disco` uses these to route queries to your agent.

---

## Configuration

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EM_DISCO_HOST` | — | Disco broker hostname |
| `EM_DISCO_PORT` | — | Disco broker port |
| `EM_FILTER_JWT_TOKEN` | — | JWT for authenticated brokers |
| `EM_FILTER_RECONNECT_MS` | `5000` | Reconnect delay in milliseconds |

### Node resolution order

1. `em_config_t.nodes` / `nodes_len` — explicit list (highest priority)
2. `EM_DISCO_HOST` / `EM_DISCO_PORT` env vars
3. `[em_disco] nodes = …` in `emergence.conf`
4. `localhost:8080` — built-in default

### TLS inference

| Host | Port | Transport |
|------|------|-----------|
| `localhost`, `127.0.0.1`, `::1` | any | `ws://` (plain) |
| any other | 443 | `wss://` (TLS) |
| any other | other | `ws://` (plain) |

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
    { "disco2.example.com", 443, 1 },
};
em_config_t config = {
    .jwt_token = "eyJ...",
    .nodes     = nodes,
    .nodes_len = 2,
};
```

---

## Multi-node

`em_filter_run()` connects to all resolved nodes simultaneously, one thread per node.
Memory (`cJSON *`) is local to each connection — starts as an empty object and resets
on reconnect (same as Erlang `em_filter` RAM mode).

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

## WebSocket protocol

The agent speaks a minimal JSON-over-WebSocket protocol to `em_disco`.

**Agent → Disco:**
```json
{ "action": "register",    "name": "<agent_name>" }
{ "action": "agent_hello", "capabilities": ["search", "query"] }
{ "action": "result",      "id": "<query_id>", "data": <result> }
```

**Disco → Agent:**
```json
{ "action": "query", "id": "<query_id>", "body": "<query_string>" }
```

The library handles the handshake and reconnection automatically.
Your code only implements the `em_handle_fn` callback.

---

## Example

```bash
# After building:
./build/Release/echo_filter

# With a custom broker:
EM_DISCO_HOST=disco.example.com EM_DISCO_PORT=443 \
EM_FILTER_JWT_TOKEN=eyJ... ./build/Release/echo_filter
```

---

## License

[MIT](LICENSE)
