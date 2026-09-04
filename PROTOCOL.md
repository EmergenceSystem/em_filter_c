# em_filter protocol (mesh parity, ed25519-signed)

This is the wire protocol `em_filter_c` speaks to the Emergence mesh (`em_disco`
+ Emquest). It must be byte-identical to the Erlang reference (`em_pop_crypto.erl`)
and to every other language SDK. See the design spec for the authoritative
version: `2026-09-04-multilang-sdk-mesh-parity-design.md`.

## 1. Identity & crypto

- **Keypair:** ed25519, persisted as raw `pubkey(32) || seed(32)` bytes in
  `<key_dir>/node_ed25519.key` (created on first run if absent). libsodium's
  64-byte "secret key" (`seed || pub`) is derived on demand with
  `crypto_sign_seed_keypair()` — it is never itself persisted.
  - Key directory: `EM_FILTER_KEY_DIR` env, or `em_config_t.key_dir`, else
    `./empop_key_<name>/`.
- **Peer id:** `id = SHA-256(pubkey)[0:16]` — first 16 bytes.
- **On-wire id:** `signer_id = base64(id)` (standard, padded — libsodium
  `sodium_base64_VARIANT_ORIGINAL`, matching Erlang's `base64:encode/1`).
- **canonical_identity:** `id || 0x00 || name` (name = UTF-8 agent name).
  Self-signature `sig = Ed25519_sign(canonical_identity, priv)`, on the wire
  `base64(sig)`. Deliberately excludes host/port so a hub may rewrite a
  leaf's routing fields without invalidating the self-signature.
- **canonical_response(items):** one line per item, concatenated in list
  order. For an object item: `P` = its `properties` sub-object if present
  and an object, else the item itself. `U = P.url` (string or empty),
  `T` = first string among `P.title`, `P.label` (else empty), `R` = first
  string among `P.resume`, `P.value`, `P.description` (else empty). Line
  bytes: `U || 0x00 || T || 0x00 || R || 0x0A`, UTF-8, unescaped. A
  non-object item (or one with no matched fields) produces `0x00 || 0x00 ||
  0x0A`. A non-array `items` value produces empty bytes.
- **Response signature:** `signature = base64(Ed25519_sign(canonical_response(results), priv))`,
  paired with `signer_id = base64(id)`.

`em_filter_c` implements this in `include/em_filter/crypto.h` +
`src/crypto.c` (byte-level primitives) and `include/em_filter/identity.h` +
`src/identity.c` (keypair lifecycle + wire payload builders). Verified
against `fixtures/crypto_vectors.json`, generated from the Erlang reference,
in `tests/test_crypto.c`.

## 2. Transports

Both are implemented by every SDK; `EM_FILTER_MODE` picks which run (§3
below). A filter is reachable through either.

### 2.1 Model A — direct (`src/server.c`, `src/gossip.c`)

The SDK serves inbound HTTP and gossips its own identity:

- `GET /health` → `200 "ok"`.
- `POST /agent/query` — body `{"query": "..."}`. Runs the handler, replies
  `{"results": [...], "signer_id": "<b64>", "signature": "<b64>"}` (200).
  Malformed/absent `query` → 400. Handler error → 500.
- `POST /pop/gossip` — accepts (and discards — this SDK keeps no peer
  table) a remote gossip payload, replies with this agent's own gossip
  payload.
- **Gossip push loop** — every `gossip_interval` (default 5s, env
  `EM_FILTER_GOSSIP_INTERVAL_MS`), `POST`s the self-payload to each
  configured seed's `/pop/gossip`:

  ```json
  {
    "id": "<b64 id>", "name": "<name>",
    "host": "<advertise_host>", "query_port": <int>,
    "pubkey": "<b64>", "sig": "<b64 selfsig>",
    "capabilities": ["search", "query", ...],
    "role": "filter"
  }
  ```

The filter must be reachable at `advertise_host:query_port` for Emquest to
direct-query it — set `EM_FILTER_HOST` / `EM_FILTER_QUERY_PORT` (or
`em_config_t.advertise_host` / `.query_port`) to a real, reachable
address/port (port-forward or public IP).

### 2.2 Model B — WS relay (`src/wsclient.c`, default, NAT-friendly)

The SDK opens an outbound WebSocket to `wss://<disco>/ws/filter` and never
needs inbound reachability.

- **hello** (filter → disco):
  ```json
  {"action": "hello", "name": "<name>", "pubkey": "<b64>",
   "sig": "<b64 selfsig>", "capabilities": ["..."]}
  ```
  Ack: `{"action": "hello_ok", "id": "<b64 id>"}` (or
  `{"action":"error","reason":...}` — the SDK logs and reconnects).
- **query** (disco → filter): `{"action": "query", "id": "<qid>", "body": "<query>"}`.
- **result** (filter → disco):
  ```json
  {"action": "result", "id": "<qid>", "results": [...],
   "signer_id": "<b64>", "signature": "<b64>"}
  ```
  The filter signs `canonical_response(results)` itself — the disco is a
  dumb relay pipe and cannot forge a result (it never holds the private
  key).
- **Keepalive:** WS ping/pong (`src/websocket.c` replies PONG to any PING
  automatically, RFC 6455 §5.5.3). On disconnect (close frame, error, or a
  dropped socket), the SDK reconnects after `EM_FILTER_RECONNECT_MS`
  (default 5s) and repeats the hello handshake. Per-connection memory
  (the handler's `cJSON *memory` state) persists across reconnects within
  one process lifetime.

## 3. Mode selection

`EM_FILTER_MODE` = `relay` (default) | `direct` | `both`, or
`em_config_t.mode` (takes priority over the env var). `both` runs the
Model A HTTP server + gossip pusher and Model B relay session(s)
concurrently, advertising the same identity (`id`/`pubkey`); the relay path
is a NAT-friendly fallback when the direct `query_port` isn't reachable.

`em_config_t.nodes` (or `EM_DISCO_HOST`/`EM_DISCO_PORT`, or
`[em_disco] nodes = ...` in `emergence.conf`) resolves the disco endpoint
list — used as Model B's relay targets *and* Model A's gossip seeds; same
mesh entry points either way.

## 4. Capability vector

SDKs advertise `capabilities` as plain strings only (`em_handler_t.capabilities`).
The disco computes the routing vector from those strings on its side
(`em_filter_vec`, `erlang:phash2/2`-based and not reproducible outside
Erlang) before relaying the peer — SDKs never compute or send a vector.
