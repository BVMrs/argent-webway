# A2A 1.0 SDK and MCP interop constraints

Status: research report (issue #13). This file contains no normative requirements. Section 5 lists candidate requirements for the argent-webway specs (#3–#5) and for the M1 interop smoke test.
Date: 2026-11-07.

## 0. Why this exists, and how it was done

argent-webway will interoperate with A2A (agent-to-agent) and MCP (agent-to-tool) rather than replace them. The specs that build on this can only be right if they know how deployed implementations actually behave, not only what the upstream specs say. This report records that behaviour for every official A2A SDK and for MCP, in the four areas the issue asks about:
- Agent Card signing;
- extension handling;
- streaming and push;
- unknown-field handling.

It also covers what MCP constrains for a bridge, and the requirements all of this implies.

**Method.**
- Every repository below was shallow-cloned at the pinned commit and read as source. Nothing was built or executed.
- Claims are either **verified** (read at the cited `path:line`) or marked *inferred*. A claim is inferred when it follows from library defaults or from something being absent; the reason is given.
- "Not found" means searched for and absent. The search terms are recorded in the working notes.
- Line numbers refer to the pinned commit.
- Library defaults that were not traced into the dependency (for example protobuf-java's handling of enum values) are marked *inferred*.

**What this report does not do.** It does not choose a position for argent-webway relative to A2A and MCP, nor the core language. Those decisions belong to the due diligence document. Section 6 only lists the evidence from this research that is relevant to them.

### 0.1 Sources and versions

| Key | Repository | Pin (commit, date) | Release at pin |
|---|---|---|---|
| `A2A` | github.com/a2aproject/A2A (spec) | `3303592` = tag **v1.0.1** (2026-05-28); `78e1d6a` = tag **v1.1.0-rc** (2026-10-29); HEAD `9fff3e0` (2026-11-05) | v1.0.1 is the current release. v1.1.0-rc sits on a separate `dev 1.1` line and is not an ancestor of HEAD. |
| `py` | github.com/a2aproject/a2a-python | `28f8a62` (2026-11-05) | v1.3.0 + 19 commits (`a2a-sdk`) |
| `js` | github.com/a2aproject/a2a-js | `3d3ca82` (2026-11-05) | v1.3.0 + 22 commits (`@a2a-js/sdk`) |
| `go` | github.com/a2aproject/a2a-go | `ea739de` (2026-11-06) | **v2.8.0** exactly |
| `java` | github.com/a2aproject/a2a-java | `31455e9` (2026-11-06) | v1.5.0.Final + 11 commits |
| `dotnet` | github.com/a2aproject/a2a-dotnet | `e93f834` (2026-11-02) | v1.0.0-preview4 (+ version bump) |
| `rs` | github.com/a2aproject/a2a-rs | `505dbad` (2026-11-06) | crates `a2a-lf` 0.4.2, `a2a-client-lf` 0.2.9, `a2a-server-lf` 0.5.3, `a2a-grpc` 0.3.11, `a2a-pb` 0.3.2, `a2a-slimrpc` 0.3.5 |
| `mcp` | github.com/modelcontextprotocol/modelcontextprotocol (spec) | `fd50278` (2026-11-08); release tag **2026-07-28** = `5f5440b` | current release 2026-07-28; previous 2025-11-25 |
| `mcp-tasks` | github.com/modelcontextprotocol/ext-tasks | `cc9aaac` (2026-11-04) | v0.2.3 |
| `rmcp` | github.com/modelcontextprotocol/rust-sdk | `5596a8a` (2026-11-05) | rmcp **v3.9.0** |
| `mcp-ts` | github.com/modelcontextprotocol/typescript-sdk | `1e608ca` (2026-10-31) | 2.4.0 |
| `mcp-py` | github.com/modelcontextprotocol/python-sdk | `77001c9` (2026-11-05) | v2.3.0 |

Citation shorthand:
- `S1:n` = `A2A@v1.0.1 docs/specification.md` line n.
- `S11:n` = the same file at v1.1.0-rc.
- `P1:n` = `A2A@v1.0.1 specification/a2a.proto`.
- `S26/…` = `mcp docs/specification/2026-07-28/…`.

Everything else is `key path:line`.

**Which SDKs are official.** `A2A@v1.0.1 docs/sdk/index.md:5-12` lists six: Python, Go, Java, JavaScript, C#/.NET and **Rust (a2a-rs)**. The v1.0.1 README lists five (no Rust). The v1.1.0-rc README adds Rust (`cargo add a2a-lf`). There is **no OCaml SDK** for A2A or MCP.

---

## 1. Executive summary

1. **The wire format is shared; the behaviour is not.** All six SDKs implement A2A 1.0 over JSON-RPC, HTTP+JSON and gRPC, and they agree on JSON-RPC error codes. They disagree on:
   - absent version headers;
   - unknown fields;
   - extension enforcement;
   - push headers;
   - HTTP and gRPC status codes.

   An argent-webway node must be **conservative in what it sends** (§5.B). Liberal acceptance alone is not enough.
2. **Agent Card signatures cannot carry identity today.**
   - Only Go, Python and JS can verify, and all three only when the caller opts in.
   - Go silently accepts an *unsigned* card even when a verifier is configured (`go a2aclient/agentcard/resolver.go:210`).
   - Java, .NET and Rust cannot sign or verify, and re-serialise cards, which breaks signatures they relay.
   - The spec has no agent identity field, no algorithm allow-list, and no rule for what to do when verification fails.

   argent-webway identity must therefore be its own layer, and a card signature is only one way to bind it.
3. **Unknown fields are dangerous to send.**
   - a2a-java's protobuf JSON parser **rejects** unknown fields on JSON-RPC and REST requests *and responses*.
   - Every other SDK silently drops them, so they never survive a relay.
   - Unknown enum values, Part kinds or SecurityScheme types make whole messages or cards fail to parse in several SDKs.

   Everything argent-webway adds must travel in `metadata` keyed by an extension URI, or in extension `params`. It must never appear as new top-level fields or new enum values.
4. **No SDK can resume a stream.** No SDK uses SSE ids for resumption and none replays missed events. A2A 1.1's `generation` and `lastSeenGeneration` would fix this, but no SDK implements v1.1.
   - "Reconnect" means SubscribeToTask, which sends a snapshot and then live events. Duplicates and gaps are possible in some SDKs.
   - In Python an evicted slow subscriber sees a *clean* end of stream.
   - **End of stream must never be taken to mean completion.**
5. **Push is best-effort almost everywhere.**
   - Five of six SDKs make one attempt (.NET retries three times).
   - The token header name differs: `A2A-Notification-Token` (Go, Rust) or `X-A2A-Notification-Token` (Python, JS, Java, .NET). Spec v1.0.1 names no header at all.
   - SSRF defences range from none (JS) to strong (.NET).
   - No SDK signs push payloads or offers a receiver-side verifier.
6. **No SDK enforces authorisation.**
   - No SDK enforces the card's `securitySchemes`, and none has per-skill authorisation.
   - Defaults range from fail-closed (Java) to "every anonymous caller shares one scope" (Python, JS, Go).
   - Rust's `ListTasks` is unscoped.

   argent-webway must enforce authorisation per capability itself and assume no peer does.
7. **MCP 2026-07-28 is stateless and audience-bound.**
   - It has no sessions, no `initialize`, no resumable streams and no server-to-client requests; Multi Round-Trip Requests replace them.
   - OAuth 2.1 requires RFC 8707 resource indicators and RFC 9728 metadata, and forbids token passthrough.
   - A bridge needs its own credential for each MCP server and cannot forward an A2A caller's credential.
   - MCP tasks are an extension, cover only `tools/call`, and are unimplemented in the TS and Python SDKs.
8. **Neither spec defines a wire mapping between A2A and MCP.** A2A's Appendix B calls the two complementary (`S1:3598`); the MCP spec does not mention A2A. Any bridge is argent-webway's own design.

---

## 2. A2A specification baseline (v1.0.1, with v1.1.0-rc deltas)

This section summarises only what the SDK comparison needs.

| Area | v1.0.1 rule | Gaps / notes | v1.1.0-rc |
|---|---|---|---|
| Card signing | Signing is optional (MAY). JWS (RFC 7515) over **RFC 8785 JCS** of the card with `signatures` excluded and proto field-presence rules applied. Protected header MUST include `alg`, `kid` and `typ` (`jku` is optional). Effectively a detached JWS (`S1:2002-2134`). Clients SHOULD verify at least one signature. | No `alg` allow-list. No binding of `jku`/`kid` to the card's origin. No behaviour defined for failed or missing signatures. No revocation discovery. No agent identity field: identity is `name` + `provider` + serving domain (P1:361-398). | Moves to §8.3. Says "Agent Cards contain untrusted data … MUST NOT treat descriptions or other metadata as trusted instructions" and "the presence of a signature alone does not establish trust" (`S11:3551-3555`). Adds media type `application/a2a-agent-card+json`. Discovery doc prefers `/.well-known/ai-catalog.json`. |
| Extensions | Declared in `capabilities.extensions[]` (`uri`, `required`, `params`). Clients opt in with the `A2A-Extensions` service parameter (HTTP header, gRPC metadata `a2a-extensions`) (`S1:481-488,1051-1075`). A required extension the client does not declare MUST be answered with `ExtensionSupportRequiredError` (-32008) (`S1:576`). A breaking change needs a new URI, with no automatic fallback (`S1:1137-1141`). | The activated-extensions echo appears only in a topic doc (`A2A@v1.0.1 docs/topics/extensions.md:168-170`). No core message signing: the topics doc suggests a "message signing extension". | no normative change |
| Streaming | A task stream starts with the `Task`. Events are strictly ordered and broadcast identically to every stream on the task. The stream closes at a terminal state (`S1:204-212,681-694`). SubscribeToTask MUST send the Task snapshot first (`S1:285-311`). "Messages MUST NOT be considered a reliable delivery mechanism" (`S1:762`). | No `Last-Event-ID`, replay or heartbeat. The spec contradicts itself on whether INPUT_REQUIRED or AUTH_REQUIRED closes the stream (`S1:210` vs `S1:2973`). The REST subscribe method is POST in the spec but GET in the proto (`S1:1169` vs `P1:78`). | Per-task `generation` counter (+1 per mutation). `SubscribeToTask.last_seen_generation` resumes a stream. `GetTask.current_generation` long-polls. `ifGenerationMatch` gives optimistic concurrency (`TaskGenerationMismatchError` -32010). Bidirectional `SendLiveMessage`. Interrupted states SHOULD NOT close the stream (`S11:210`). |
| Push | Config is `{url, token, authentication{scheme, credentials}}` (P1:469-484). Payload is `StreamResponse` JSON, always sent over HTTP+JSON (`S1:842-869`). At-least-once delivery; the receiver MUST answer 2xx and SHOULD de-duplicate. Retries are MAY in §4.3.3 but SHOULD in §13.2. SSRF validation is SHOULD, and lists IPv4 private ranges only (`S1:3113-3116`). | **v1.0.1 names no header for `token`.** v1.0.0 had the example `X-A2A-Notification-Token` (`A2A@v1.0.0 docs/specification.md:1654`). No signed-payload format. Replay protection appears only in a topic doc. | `TaskPushNotificationConfig.protocol_version` |
| Versioning | Clients MUST send `A2A-Version` (Major.Minor). **An empty value MUST be interpreted as 0.3** (`S1:739`). An unsupported version gets `VersionNotSupportedError` (-32009). | — | — |
| Unknown data | Unrecognised fields SHOULD be ignored (`S1:1273-1275`). ADR-001: ProtoJSON cannot preserve unknown fields. | No rule for unknown enum values. | Clients MUST skip unknown `StreamResponse` kinds. Servers MUST reject unknown `StreamRequest` kinds with `StreamError` (`S11` §3.2.3). |
| Security | Identity is "handled at the protocol layer, not within A2A semantics" (`S1:1873`). Authorisation is implementation-defined, checked on every operation, and results are scoped to the caller (`S1:3079-3098`). `tenant` is a routing string. `MutualTlsSecurityScheme` has only a `description` field (P1:561-564). | No mTLS identity mapping. `tenant` is not an authorisation boundary. No authn/authz error codes. Prompt injection is not mentioned. | §7.6.4: an AUTH_REQUIRED transition is not itself authorisation. |
| Task states | `SUBMITTED, WORKING, INPUT_REQUIRED, AUTH_REQUIRED, COMPLETED, FAILED, CANCELED, REJECTED` (P1:187-208). Terminal states: COMPLETED, FAILED, CANCELED, REJECTED. | No transition table. Deduplication by `messageId` is only MAY (`S1:492-496`). | Terminal tasks MUST NOT accept messages or emit updates. |

---

## 3. A2A SDK behaviour

### 3.1 Protocol versions and transports

All six SDKs implement A2A 1.0 on JSON-RPC, HTTP+JSON/REST and gRPC, client and server (Java, Go, Python and JS verified across all three; .NET has a gRPC client and server; Rust uses the separate `a2a-grpc` crate). None implements v1.1.0-rc (`SendLiveMessage` and `generation` are absent; `rs a2a-pb/proto/a2a.proto` matches the v1.0.1 proto).

| SDK | Sends `A2A-Version` | Absent header on server | Minor version check | 0.3 compatibility |
|---|---|---|---|---|
| py | `1.0` (`py src/a2a/client/client_factory.py:91-106`) | read as 0.3, so 1.0 handlers reject it. **gRPC does no version check** (`py src/a2a/utils/version_validator.py:75-90`; grep of `grpc_handler.py`) | **major only**, although the docstring says major and minor (`version_validator.py:27-29` vs `:90`) | opt-in, all transports (`py src/a2a/server/routes/jsonrpc_routes.py:32`) |
| js | `1.0` | read as 0.3, rejected unless the card declares a 0.3 interface (`js src/server/version.ts:74-111`) | exact, against the card's `supportedInterfaces` | opt-in, all transports |
| go | Major.Minor (`go a2aclient/client.go:186`) | read as 0.3 and rejected (`go a2asrv/intercepted_handler.go:283-299`) | Major.Minor | client and server, all transports |
| java | `1.0` always (`JSONRPCTransport.java:353`) | read as 0.3 (`A2AVersionValidator.java:33-91`). The multi-version router matches exact strings only (`VersionRouter.java:20-38`) | major and minor against the card | full compat modules. **Client transport selection ignores `protocolVersion`** (`ClientBuilder.java:331-388`) |
| dotnet | `1.0` | **accepted** (`dotnet src/A2A.AspNetCore/A2AVersionHeader.cs:14-38`) | exact `{0.3, 1.0}`: **rejects `1.1`**. gRPC accepts only `1.0` | JSON-RPC only |
| rs | `1.0` (`rs a2a-client/src/client.rs:25`) | read as 0.3 and rejected (`rs a2a-server/src/middleware.rs:24-41`) | any `1.x` | none on the server |

.NET treats an absent header as acceptable, which conflicts with `S1:739`. Python ignores the minor version. .NET rejects any minor version above 1.0. So a client that sends `1.1` to an interface advertising `1.0` will fail against .NET.

### 3.2 Agent Card signing

| SDK | Sign | Verify | Canonicalisation | Algorithms | Key lookup | Default | Failure behaviour |
|---|---|---|---|---|---|---|---|
| py | yes, detached (`py src/a2a/utils/signing.py:57-100`) | yes, if any one signature verifies (`:103-173`) | own JCS (`py src/a2a/utils/_jcs.py`) over `MessageToDict(proto card)` with `signatures` removed and empty strings, lists and dicts stripped (`signing.py:176-221`). It signs the **1.0 schema projection**: unknown fields are dropped first. | the verifier requires an `algorithms` allow-list. **The signer defaults to `HS256`** if no `alg` is given (`signing.py:84`). | caller callback `(kid, jku)`; no JWKS fetch | **off** (`signature_verifier=None`, `card_resolver.py:155`) | raises `SignatureVerificationError`, not wrapped as a resolution error |
| js | yes, flattened JWS through `jose` (`js src/signature.ts:59-88`) | yes, any one (`:110-157`) | `AgentCard.fromJSON`→`toJSON` round trip (drops unknown fields and defaults), then `cleanEmpty`, then JCS-like ordering (`:163-238`). Documented: unknown fields are not covered. | **no allow-list** passed to `jose` (`:135-148`) | caller callback | **off** on both sides. `createFromUrl` never verifies (`js src/client/factory.ts:156-159`) | plain `Error` |
| go | yes (`go a2acrypto/sign.go:76-128`). `NewSignedCardProducer` supports key rotation | yes (`go a2acrypto/verify.go:51-105`), over the **raw response bytes** | hand-written JCS. Removes only the top-level `signatures` (`go a2acrypto/canonical.go:31-46,272-275`) | ES256/384/512, EdDSA, RS256/384/512 (`go a2acrypto/alg.go:22-58`). `alg` is not bound to the key's curve (*inferred*) | fixed key set by `kid`, or a JWKS **allow-list**. `jku` is documented as untrusted (`go a2acrypto/keyresolver.go:34-100`). No cache, no body limit. | **off**. **Unsigned cards pass even with a Verifier set** (`go a2aclient/agentcard/resolver.go:210`) | error from `Resolve` |
| java | no | no | — | — | — | — | model only (`AgentCardSignature.java:36`). No JOSE dependency. The card is re-serialised through protobuf (`A2ACardResolver.java:315-318`). |
| dotnet | no | no | — | — | — | — | model only (`dotnet src/A2A/Models/AgentCardSignature.cs`). Refuses to rewrite the extension declarations of a signed card (`A2AExtensionAgentCards.cs:12-24`). **Drops signatures when upgrading a 0.3 card** (`A2ACardResolver.cs:158-163`). |
| rs | no | no | — | — | — | — | model only (`rs a2a/src/agent_card.rs:597-607`). The served card is re-serialised and unknown fields dropped. |

Cross-SDK consequences (*inferred* from the rows above):
- **Signatures are only portable if signer and verifier share a schema.**
  - Go canonicalises the bytes it received, while Python and JS canonicalise their parsed 1.0 projection.
  - A card that carries any field outside the 1.0 schema therefore verifies in Go but fails in Python and JS.
  - The empty-value stripping in Python and JS can also diverge from spec §8.4.1, which says "optional fields explicitly set to default MUST be included".
- **Relays break signatures.** Java, .NET and Rust re-serialise cards, and .NET drops signatures when upgrading 0.3 cards.
- **Downgrade is possible.** Go accepts unsigned cards, and every SDK makes verification opt-in, so stripping the signatures defeats verification.

### 3.3 Extension handling

| SDK | Reads `A2A-Extensions` | Filtered to declared extensions | Required extensions enforced | Activated echo | Client API |
|---|---|---|---|---|---|
| py | yes, HTTP and gRPC. 0.3 also reads `X-A2A-Extensions` (`py src/a2a/server/routes/common.py:116-121`) | **no**: any requested URI reaches the executor | **never**: -32008 is defined but never raised (`py src/a2a/utils/errors.py:111-114`) | none (activation removed in 1.0.0-alpha.2) | `with_a2a_extensions` |
| js | yes (`js src/extensions.ts:24-35`) | yes (`js src/server/request_handler/default_request_handler.ts:265-269`) | SendMessage and SendStreamingMessage only (`:207-217`) | HTTP yes. gRPC streaming probably not (*inferred*, `grpc_service.ts:102-103`) | `withA2AExtensions`. The client does not read the echo. |
| go | yes (`go a2asrv/extensions.go:66-80`) | client `Activator` sends only URIs the card declares | **opt-in** interceptor `NewAgentCardEnforcer` (`go a2asrv/agentcard_enforcer.go:47-106`) | gRPC only (`go a2agrpc/v1/handler.go:318-322`) | `a2aext.NewActivator`, plus propagators that forward extensions along agent chains |
| java | yes | — | **always, on all operations** (`AgentCardRequestPolicy.java:46-49`) | **none**: `getActivatedExtensions()` has no callers | header passthrough |
| dotnet | yes, through a registry. Unknown URIs ignored. | yes | yes, before the handler runs (`A2ACustomOperationRegistry.cs:89-116`) | **yes**, sorted, also on errors (`A2AExtensionNegotiation.cs:16-29`) | no typed send. Reads the echo (`A2AResponseActivation.cs:22`). |
| rs | yes, HTTP and gRPC (`rs a2a-server/src/handler.rs:756-766`) | — | **yes, on every method** (`:745-773`) | none | none (raw `ServiceParams`) |

Consequences:
- **Peers do not reliably confirm that an extension was activated.** Two SDKs echo it fully; Go echoes on gRPC only; three never do.
- **A required extension is not a security control:**
  - a Python server accepts clients that omit it;
  - a JS server enforces it only on message sends;
  - a Go server enforces it only if configured.

### 3.4 Streaming

| SDK | SSE `id:` | Resume / replay | SubscribeToTask | Slow subscriber | Client disconnect | Client reconnect |
|---|---|---|---|---|---|---|
| py | none (`py src/a2a/server/routes/jsonrpc_dispatcher.py:585-619`) | none. In DB cluster mode, version-ordered after the snapshot (`default_request_handler_v2.py:674-715`) | snapshot, then live events (`:632-672`) | bounded at 1024. Evicted on full and sees a **normal end of stream** (*inferred*, `active_task.py:858-882`) | agent keeps running | none (parser ignores `id`/`retry`) |
| js | none (`js src/sse_utils.ts:41-57`) | none. Duplicates are possible (*inferred*) | attaches to the bus, then snapshot. With no live bus it sends the snapshot and closes. | **unbounded**, no backpressure (`res.write` return value ignored) | no close detection. Executor keeps running. | manual `resubscribeTask()`. Skips unknown payload kinds (unreleased). |
| go | random UUID for each event (`go internal/sse/sse.go:78`) | none | snapshot, then events with version greater than the snapshot (`go internal/taskexec/subscription.go:66-101`) | 32-slot buffer with a **blocking** send: a slow subscriber stalls the producer and every other subscriber (`queue_in_memory_impl.go:66-70,140-147`) | detached context; agent keeps running | none |
| java | per-connection counter (`A2AServerRoutes.java:389-391`) | none on the server | snapshot read **before** the tap, so a race can drop events (*inferred*, `DefaultRequestHandler.java:1241` vs `:1260`) | the subscriber is closed when its queue is full (`EventQueue.java:899-938`) | subscription cancelled; agent keeps running | parser tracks `lastEventId` but never reconnects |
| dotnet | none (`JsonRpcStreamedResult.cs:52-67`) | none | snapshot and register under a per-task lock, so no gap (`A2AServer.cs:271-316`) | producer back-pressured (16 slots). Each subscriber channel is **unbounded**. | streaming is detached; a blocking call is cancelled | none |
| rs | monotonic per response, starting at 1 (`rs a2a-server/src/sse.rs:10-26`) | none | snapshot, then sequence numbers greater than the snapshot (`handler.rs:453-487`) | `broadcast(32)`. A lagging subscriber gets an "Internal error" and its stream ends (`:489-497`) | `tokio::spawn`; agent keeps running | none. Client buffer unbounded. |

The same in every SDK: a client disconnect does **not** cancel the task, and the only recovery is SubscribeToTask, which sends a snapshot and then live events.

### 3.5 Push notifications

| SDK | `token` sent as | `authentication` sent as | Retries | SSRF guard | HTTPS only | DNS-rebinding safe | Validated at create | Blocks execution |
|---|---|---|---|---|---|---|---|---|
| py | `X-A2A-Notification-Token` | `Authorization: <scheme> <creds>` (`base_push_notification_sender.py:195-214`) | none | **opt-in**, strong when on (`py src/a2a/utils/push_url_validator.py`) | no | no: TOCTOU (*inferred*) | yes, if configured | no |
| js | `X-A2A-Notification-Token`, only when `authentication` is unset | `Authorization` | none; 5 s timeout | **none** (`default_request_handler.ts:1029-1045`) | no | — | no | no (fire-and-forget). Follows redirects (*inferred*). |
| go | `A2A-Notification-Token` (`go a2asrv/push/sender.go:40`) | `Bearer` or `Basic` only | none | **on** (`sender.go:93-141`) | no (http allowed) | **yes** (dial-time check) | parse only | sequential per config |
| java | `X-A2A-Notification-Token` (`A2AHeaders.java:23`) | `Authorization`, CR/LF rejected | none | **on** (`DefaultPushNotificationUrlValidator`) | **yes** | no: TOCTOU (*inferred*) | at send time | async. Redirects disabled. |
| dotnet | `X-A2A-Notification-Token` (configurable) | `Authorization` | **3 attempts**, backoff, on 408/429/5xx (`PushNotificationDeliveryOptions.cs:16-34`) | **on**, broadest blocklist | **yes** | yes (dials the approved IP) | yes, and before every attempt | no (256-slot queue) |
| rs | `A2A-Notification-Token` | `Authorization` | none. `fail_on_error` fails the task | **on**. Misses 100.64/10, NAT64, 198.18/15 and others (`rs a2a-server/src/push/sender.rs:239-270`) | no | yes (connect-time) | **no** | **yes**: inline, up to 30 s per send (`handler.rs:541-551`) |

No SDK signs push payloads, carries a sender identity, or ships a receiver-side verifier. Every SSRF guard that is on blocks loopback, which matters for local multi-node tests (§5.J).

### 3.6 Unknown fields, enums and metadata

| SDK | Unknown JSON fields | Preserved on re-serialisation | Unknown enum value | Unknown Part / SecurityScheme / stream kind |
|---|---|---|---|---|
| py | ignored (`ParseDict(ignore_unknown_fields=True)`, `jsonrpc_dispatcher.py:302-310`) | no | becomes `*_UNSPECIFIED`, so a required field fails with -32602 (*inferred*) | — |
| js | ignored (hand-written `fromJSON`) | no. A client card that is not proto-shaped is kept **raw and unvalidated** (`js src/client/card-resolver.ts:68-79`) | `UNRECOGNIZED`, re-emitted as the literal string `"UNRECOGNIZED"` | unknown Part becomes `content: undefined`. Unknown stream kind skipped. |
| go | ignored (`encoding/json`) | no | TaskState becomes UNSPECIFIED; Role passes through | **error. An unknown SecurityScheme makes the whole card fail to parse** (`go a2a/auth.go:195-201`). Part and StreamResponse also error. |
| java | **rejected** on JSON-RPC and REST, requests and responses (`JSONRPCUtils.java:461-473`; `RestHandler.java:761`). Only the card fetch is lenient. | no | error (*inferred*, protobuf-java default) | error (`JsonUtil.java:698,845,1106`) |
| dotnet | ignored (STJ default) | no | **error** (-32602/-32700). gRPC ints pass through as undefined values. | first non-null wins, no exclusivity check |
| rs | ignored (pbjson `ignore_unknown_fields`, `rs a2a-pb/build.rs:128-132`) | no | **error** (-32602). gRPC ints become Unspecified. | first match wins, no exclusivity check |

`metadata` (`google.protobuf.Struct` or a map) passes through every SDK. In the Struct-backed SDKs (Python, Java) numbers become doubles, so integers above 2^53 lose precision (`py CHANGELOG.md:30`; Java *inferred*).

### 3.7 Authentication and authorisation hooks

| SDK | Caller identity | Default data scoping | Enforces card `securitySchemes` | Per-skill authorisation |
|---|---|---|---|---|
| py | `User{is_authenticated, user_name}`. The default gRPC builder is always unauthenticated. | all anonymous callers share owner `''` | no | no (unreleased plugin hook `before_handler_run`) |
| js | `userBuilder` (required) | all anonymous callers share `'unknown'`. `tenant` comes from the client. | no | no |
| go | `User{Name, Authenticated, Attributes}` | **shared** unless an Authenticator is configured (`go a2asrv/taskstore/inmemory.go:72-76`) | no | no |
| java | `User` | **fail-closed** (`a2a.authorization.required=true`); a denial looks like TaskNotFound | no (documented: SECURITY.md §9.5) | no: the SPI cannot see skill or message |
| dotnet | none in handlers | none. `tenant` is cleared. | no | no |
| rs | opt-in `RequestAuthorizer(headers, task_id)`. `ExecutorContext.user` is always `None`. The server interceptor type is never wired into a route. | **`ListTasks` is unscoped** (`rs task_store/inmemory.rs:144-170`) | no | no |

The only verified caller identity in any SDK is a2a-rs's non-standard **SLIMRPC** transport. It runs the same A2A protobuf service over AGNTCY SLIM, with MLS-secured sessions and a DID or SPIFFE peer subject (`rs a2a-slimrpc/README.md:25-40`). SLIMRPC is not an A2A binding.

### 3.8 Error mapping

- **JSON-RPC codes agree in all six SDKs:** -32001 to -32009 plus the standard codes.
- **HTTP and gRPC statuses do not:**
  - Java follows the spec **v1.0.0** table; the others follow **v1.0.1** (`java spec/.../A2AErrorCodes.java:19-61`). For example, TaskNotCancelable is 409 in Java and 400 elsewhere, and VersionNotSupported is UNIMPLEMENTED in Java and FAILED_PRECONDITION elsewhere.
  - MethodNotFound is 404 in .NET and Java but 501 in Go and Rust.
- Go emits two codes that are not in the spec, -31401 and -31403, for unauthenticated and unauthorised (`go internal/jsonrpc/jsonrpc.go:71-89`).
- The spec defines no authentication or authorisation error codes.

---

## 4. MCP constraints for a bridge

### 4.1 Transport and session model (2026-07-28)

- **Sessions, `Mcp-Session-Id`, the `initialize` handshake, `Last-Event-ID` resumption, the GET stream and server-to-client requests are all removed** (`S26/changelog.mdx:12-28`; `S26/basic/transports/streamable-http.mdx:157,685-686`).
- **Version and capabilities travel with each request**, in `_meta["io.modelcontextprotocol/protocolVersion"]` and `…/clientCapabilities`. Servers MUST implement `server/discover` (`S26/basic/index.mdx:367-386`; `S26/basic/versioning.mdx:41-78`).
- **Headers are mandatory and must match the body**: `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` (`streamable-http.mdx:250-306,552-598`).
- **Fallback**: a dual-era client falls back to `initialize` (2025-11-25) on a 400 without a modern error body (`:650-668`).
- **Broken streams**: a broken stream loses the in-flight request, which the client MUST re-issue (`S26/changelog.mdx:28`). Closing the stream *is* cancellation (`streamable-http.mdx:233-240`).
- **Change notifications** (`list_changed`, task status) are delivered only to clients holding an open `subscriptions/listen` POST stream.
- **Server questions to the client** go through **Multi Round-Trip Requests** (MRTR): `resultType:"input_required"` with `inputRequests` and an opaque `requestState`. If `requestState` affects authorisation or logic it MUST be integrity-protected, and it SHOULD bind principal, TTL and request digest (`S26/basic/patterns/mrtr.mdx:224-257`).

### 4.2 Authorisation

- **OAuth 2.1.** PKCE with S256 is a MUST. Issuer validation (RFC 9207) is a MUST (`S26/basic/authorization/index.mdx:62,190-213`).
- **RFC 9728.** Protected resource metadata is a MUST for servers (`index.mdx:73-74`).
- **RFC 8707.** The `resource` parameter is a MUST in both the authorisation and token requests (`index.mdx:215-252`).
- **Audience.** The server MUST validate that the token was issued for it (`index.mdx:283-290`).
- **Token passthrough is prohibited.** A server "MUST NOT accept or transit any other tokens". Upstream calls use a separate token (`index.mdx:292-297`; `security-considerations.mdx:126`).
- **Client registration.**
  - Order of preference: pre-registered, then Client ID Metadata Documents, then DCR, which is **deprecated** in 2026-07-28 (`client-registration.mdx:13-51`; `S26/changelog.mdx:93-99`).
  - Credentials are keyed by issuer.
- **Confused deputy.** A proxy that uses a static client ID MUST obtain per-client user consent (`security-considerations.mdx:107-114`).
- **Identity.** `clientInfo` and `serverInfo` are self-reported and SHOULD NOT be used for security decisions (`S26/basic/index.mdx:404-409`). Core MCP cannot carry an end principal downstream.
- **Auth extensions.** `ext-auth` covers client credentials and enterprise-managed authorisation (`index.mdx:415-424`). Their contents were not reviewed for this report.
- **stdio.** The authorisation spec SHOULD NOT be used on stdio; credentials come from the environment.

### 4.3 Tool exposure

- **Listing.** `tools/list` is paginated with an opaque cursor. The list MAY vary by authorisation but MUST NOT vary per connection (`S26/server/tools.mdx:62-69`).
- **Caching.** `ttlMs` and `cacheScope` are now required; a list that varies by authorisation must be `cacheScope:"private"` (schema `2026-07-28/schema.ts:1081-1110`).
- **Schemas.** `inputSchema` (root `type:"object"`) and the optional `outputSchema` use JSON Schema 2020-12. A network `$ref` MUST NOT be dereferenced automatically (`S26/basic/index.mdx:300-317`).
- **Structured results.** `structuredContent` MUST conform to `outputSchema`, and a text copy is SHOULD. An `isError:true` result is distinct from a JSON-RPC error.
- **Annotations.** `readOnlyHint`, `destructiveHint` and the others are hints. Clients "**MUST** consider tool annotations to be untrusted unless they come from trusted servers" (`S26/server/tools.mdx:304-307`).
- **Tool names.** SHOULD be `[A-Za-z0-9_.-]{1,128}` and unique per server. Aggregators SHOULD prefix names (`:309-332`). This is SHOULD only, so a bridge must normalise names.
- **Tool definitions.** Treating tool definitions as untrusted (prompt injection, tool poisoning, "rug pull") appears **only** in the local-server security guide. That guide notes "The protocol does not require this" (`mcp docs/docs/2026-07-28/tutorials/security/local-server-security.mdx:86-100,192-214`). The best-practices doc has no prompt-injection section.

### 4.4 Long-running work, and how it maps to A2A tasks

- **Where tasks live now.** MCP tasks are the `io.modelcontextprotocol/tasks` extension (SEP-2663, `mcp-tasks specification/2026-07-28/tasks.md`).
- **Negotiation.** The extension must be declared **per request**; otherwise the server MUST NOT return `CreateTaskResult` and MUST return -32021 if it cannot serve the request synchronously (`tasks.md:61-63`).
- **Scope.** Tasks cover `tools/call` only.
- **Operations and statuses.** Clients poll with `tasks/get`, answer with `tasks/update` (MRTR `inputResponses`) and cancel with `tasks/cancel`; cancellation is eventually consistent (`:304-410`). Statuses are `working`, `input_required`, `completed`, `failed` and `cancelled`.
- **What `failed` means.** `failed` is used **only for JSON-RPC errors**. A tool result with `isError:true` is `completed` (`tasks.md:837,891-892`).
- **Security.** Task IDs MUST be unguessable. Every task request MUST be authorisation-checked. A task is not a higher-trust channel (`:900-905`).
- **SDK support.** rmcp has the types, but its own conformance runs show 9 expected failures (`rmcp ROADMAP.md:56-59`). **TS 2.4.0 and Python 2.3.0 do not implement the extension** (TS ROADMAP, #2189; `mcp-py ROADMAP.md:13`).
- **Deprecations.** Sampling, roots and logging are deprecated in 2026-07-28 (`S26/deprecated.mdx:26-28`).

| A2A TaskState | MCP equivalent | Bridge must decide |
|---|---|---|
| SUBMITTED | none (a task is created as `working`) | synthesise it |
| WORKING | `working` | — |
| INPUT_REQUIRED | MRTR or task `input_required`, which is **typed** (form elicitation, URL elicitation, sampling, roots) | how to wrap free-text A2A messages as form elicitation |
| AUTH_REQUIRED | HTTP 401/403 step-up for MCP's own auth; URL-mode elicitation for third-party auth | two channels, neither carrying an A2A auth payload |
| COMPLETED | `completed` or a plain `CallToolResult` | whether `isError:true` maps to A2A FAILED |
| FAILED | `failed` (JSON-RPC error) | — |
| CANCELED | `cancelled` (best effort) | — |
| REJECTED | none (closest is a JSON-RPC error before creation) | synthesise it |

MCP also has no `contextId`, no multi-turn conversation, no artifacts beyond content blocks, and no resubscribe.

### 4.5 Unknown fields and extensibility

- **Spec.** `Result` is open (`[key: string]: unknown`). Capabilities have `experimental` and a formal `extensions` map (new in 2026-07-28). `_meta` keys use a reverse-DNS prefix; prefixes whose second label is `modelcontextprotocol` or `mcp` are reserved (`S26/basic/index.mdx:319-433`). There is **no general "ignore unknown fields" rule**, and an unrecognised `resultType` MUST be treated as invalid (`:84`).
- **SDKs.** All three drop unknown members on Tool and result types:
  - rmcp, through serde without `deny_unknown_fields` (`rmcp crates/rmcp/src/model/tool.rs:17-40`);
  - TS, through zod `z.object`, which strips them (`mcp-ts packages/core-internal/src/wire/rev2026-07-28/buildSchemas.ts:705-735`);
  - Python, through pydantic's default `ignore` (`mcp-py src/mcp-types/mcp_types/_types.py:45-48`).

  Only `_meta` and the capabilities/extensions maps survive a round trip.

### 4.6 Readiness of the Rust MCP SDK (rmcp 3.9.0)

**Strengths**
- Implements 2026-07-28 and all earlier spec versions.
- Feature-gated client and server; stdio and Streamable HTTP.
- OAuth **client**: PKCE S256, CIMD and DCR, issuer validation, RFC 9728.
- An HMAC codec for MRTR `requestState`.
- Self-reports 100% conformance and Tier 1 status (`rmcp ROADMAP.md:5-30`). *Not verified; nothing was run.*

**Caveats**
- **Churn:** major versions 1.0 (2026-03), 2.0 (2026-06) and 3.0 (2026-07), then 3.9 by 2026-11 (`CHANGELOG.md`).
- **Insecure server defaults** (`rmcp transport/streamable_http_server/tower.rs:252-349`):
  - an empty `allowed_origins` *disables* Origin validation, which the spec makes a MUST;
  - `legacy_session_mode: true`;
  - a missing protocol metadata header is accepted.
- **No resource-server side:** it does no token or audience validation and serves no protected resource metadata (not found outside the client auth module).
- **Tasks extension:** incomplete (see §4.4).
- **MSRV:** 1.88.

---

## 5. Candidate requirements for argent-webway

These are candidate requirements derived from §2–§4. Specs #3–#5 should adopt, reject or refine each one explicitly. Each ends with the evidence it rests on. The **M1** tag marks a candidate for the interop smoke test.

### A. Baseline and versioning
- **R-A1** Target A2A **1.0** (spec v1.0.1) as the interop baseline. Treat v1.1 features (`generation`, `last_seen_generation`, `SendLiveMessage`, `ifGenerationMatch`) as optional, used only when the peer's interface declares `protocolVersion` ≥ 1.1. *(No SDK implements 1.1, and 1.1 is not on spec main: §3.1, §0.1.)*
- **R-A2** argent-webway nodes MUST send `A2A-Version: <Major.Minor>` on every A2A request, on every binding. They MUST NOT send a minor version higher than the target interface's declared `protocolVersion`. *(An absent header means 0.3 and is rejected by Python, JS, Go, Java and Rust; .NET rejects `1.1`; §3.1.)* **M1**
- **R-A3** Clients MUST select an interface by both `protocolBinding` and `protocolVersion`, never by binding alone. *(Java's client ignores `protocolVersion`.)*

### B. What a node may put on the wire
- **R-B1** argent-webway MUST NOT add top-level fields to any A2A core object that it sends to a peer not known to be argent-webway. All argent-webway data MUST travel in `metadata` under keys that are extension URIs, or in `AgentExtension.params`. *(Java rejects unknown fields on requests and responses; everyone else drops them; §3.6.)* **M1**
- **R-B2** argent-webway MUST NOT introduce new enum values, Part kinds, SecurityScheme types or StreamResponse kinds towards stock peers. argent-webway authentication MUST be described with existing scheme types (`mtls`, `http`, `oauth2`, `openIdConnect`), with refinements in extension params. *(An unknown SecurityScheme makes the whole card fail to parse in Go and Java; unknown enums are errors in .NET, Rust and Java and silently become UNSPECIFIED in Python and Go.)*
- **R-B3** Integer values in `metadata` that may exceed 2^53 MUST be encoded as strings. *(Struct-backed SDKs convert numbers to doubles.)*
- **R-B4** The argent-webway parser SHOULD ignore unknown fields, as A2A §5.7 says, and MUST keep the raw received bytes wherever a signature or a forward depends on them. An unknown enum value MUST be surfaced as "unknown", never silently mapped to a default.

### C. Identity and Agent Card signing
- **R-C1** argent-webway identity MUST NOT depend on stock peers verifying Agent Card signatures. The identity binding (key ↔ agent ↔ owner) needs its own mechanism. A card signature can be one way to carry it, but it is not the trust root. *(Three of six SDKs cannot verify; verification is opt-in everywhere; Go accepts unsigned cards; the spec has no identity field and says a signature "alone does not establish trust"; §2, §3.2.)*
- **R-C2** When an argent-webway node signs a card:
  - it MUST use a detached JWS per A2A §8.4, with explicit `alg`, `kid` and `typ`;
  - `alg` MUST come from an asymmetric allow-list (for example EdDSA, ES256);
  - the card MUST NOT contain fields outside the 1.0 schema;
  - the card SHOULD NOT contain optional fields set to empty values.

  *(Python and JS canonicalise the parsed 1.0 projection with empty values stripped; Go canonicalises raw bytes; Python defaults to HS256.)* **M1**: signed cards produced by our node MUST verify with the Go, Python and JS verifiers.
- **R-C3** When an argent-webway node verifies a card, it MUST apply an `alg` allow-list (no `HS*`, no `none`) and fail closed on an unsigned card whenever policy requires a signature. It MUST fetch `jku` only from an allow-list bound to the card's origin or provider. *(These are spec gaps; Go's downgrade.)*
- **R-C4** Nodes, relays and bridges MUST serve and forward signed cards **byte-for-byte**, never re-serialised. *(Java, .NET and Rust re-serialise; .NET drops 0.3 signatures.)*
- **R-C5** Peer identity at the transport layer (mTLS client certificate, token subject) MUST be mapped explicitly to the argent-webway identity. *(The A2A `MutualTlsSecurityScheme` defines no identity mapping, and only a2a-rs SLIMRPC hands a verified peer identity to handlers.)*

### D. Extensions
- **R-D1** argent-webway capabilities that ride on A2A MUST be A2A extensions with versioned URIs. A breaking change MUST use a new URI.
- **R-D2** argent-webway MUST NOT rely on the `A2A-Extensions` response echo to learn which extensions were activated. Activation MUST be confirmed in-band, for example by a response `metadata` key under the extension URI. *(Only JS and .NET echo; Go echoes on gRPC only.)*
- **R-D3** A `required: true` extension MUST NOT be treated as a security control. The receiving argent-webway node enforces its own policy whatever the peer SDK does. *(Python never enforces; JS enforces on sends only; Go only if configured.)*
- **R-D4** Message-level integrity (signed messages, artifacts and results) MUST be an extension. It MUST sign RFC 8785-canonical bytes of content that survives stock-SDK round trips, meaning 1.0-schema fields plus its own `metadata` subtree. Otherwise it MUST carry a detached envelope over the raw bytes. *(No core message signing exists; unknown fields are dropped by relays.)*

### E. Streaming, delivery and offline peers
- **R-E1** Only an event carrying a terminal state means completion. **End of stream without a terminal state MUST be treated as disconnection** and followed by SubscribeToTask or GetTask. *(A Python eviction ends the stream cleanly; 1.0 removed the `final` flag.)* **M1**
- **R-E2** Clients MUST tolerate the snapshot-first stream, duplicate events after resubscribe, and gaps. They reconcile by fetching the task, and by `generation` when the peer supports 1.1. *(No SDK replays events; JS can duplicate; Java has a snapshot/tap race.)*
- **R-E3** Clients MUST NOT assume a stream stays open, or closes, at INPUT_REQUIRED or AUTH_REQUIRED. *(The v1.0.1 text contradicts itself; JS closes on INPUT_REQUIRED.)*
- **R-E4** Cancellation MUST be explicit (`CancelTask`). Disconnecting never cancels a task in any SDK.
- **R-E5** argent-webway MUST define its own resume and offline-delivery semantics: durable task state plus poll or long-poll, aligned with v1.1 `generation` when available. SSE resumption cannot be relied on.
- **R-E6** argent-webway nodes MUST bound per-subscriber buffers and MUST signal a dropped subscriber with an explicit error, not a silent end of stream. *(Unbounded buffers in JS, .NET and the Rust client; Go stalls all subscribers.)*

### F. Push notifications
- **R-F1** Push MUST be treated as a hint. Receivers MUST de-duplicate and reconcile with GetTask. Senders SHOULD retry with backoff. *(Five of six SDKs make one attempt.)*
- **R-F2** argent-webway receivers MUST accept the config `token` in both `A2A-Notification-Token` and `X-A2A-Notification-Token`, and SHOULD prefer `authentication` (`Authorization`), which every SDK sends. *(Spec v1.0.1 names no header.)* **M1**
- **R-F3** Push authenticity MUST NOT rest on a shared bearer token alone, given "no ambient trust". argent-webway SHOULD define a signed push envelope as an extension, with sender identity, timestamp and nonce. *(No SDK signs pushes; replay protection exists only in a topic doc.)*
- **R-F4** argent-webway senders MUST validate webhook URLs at creation and at connect time (rebinding-safe), require HTTPS outside local test mode, and disable cross-host redirects. *(SSRF handling ranges from none in JS to .NET's model; Rust's blocklist has gaps.)*
- **R-F5** Peers behind NAT cannot generally receive webhooks. argent-webway MUST offer a delivery path that needs no inbound reachability (outbound poll, long-poll or relay).

### G. Authentication and authorisation
- **R-G1** Each argent-webway node MUST authenticate every request and authorise **per capability (skill / operation)**, deny by default. It MUST assume that stock peers enforce nothing, including their own card's `securitySchemes`.
- **R-G2** Anonymous callers MUST NOT share a data scope. Results MUST be scoped to the authenticated principal. `tenant` is routing, never authorisation. *(Python, JS and Go share one anonymous scope; Rust's ListTasks is unscoped.)*
- **R-G3** Authorisation failures MUST NOT reveal whether a resource exists (spec §3.3.2). argent-webway MUST define its authentication error codes and their mapping to each binding. Clients MUST map errors by JSON-RPC code or `ErrorInfo.reason`, never by HTTP or gRPC status, and MUST recognise Go's -31401 and -31403. *(§3.8.)*
- **R-G4** Every authentication decision, authorisation decision, delegation and cross-owner exchange MUST produce an audit record. *(No SDK provides one. A2A §13.4 recommends audit logging but specifies no format.)*

### H. Prompt-injection boundaries
- **R-H1** Everything received from a peer is **untrusted data**, never instructions to the receiving agent's model. That covers Agent Card descriptions, skill text, messages, artifacts, MCP tool descriptions and annotations, elicitation prompts and push payloads. argent-webway MUST attach provenance (originating identity, path) at the boundary, so that agent runtimes can keep peer content apart from their own instructions. *(A2A v1.1 §14.1.2; MCP annotations MUST be treated as untrusted; no SDK marks provenance; the .NET SDK documents prompt injection as a non-goal.)*

### I. MCP bridge
- **R-I1** Target MCP **2026-07-28**. Support for 2025-11-25 (`initialize`, sessions) is a separate, optional fallback. The bridge MUST NOT rely on MCP sessions to carry A2A `contextId` or `taskId`.
- **R-I2** **As an MCP client** (calling tools for an A2A principal), the bridge:
  - MUST use its own audience-bound token for each MCP server (`resource` = canonical server URI);
  - MUST NOT forward the A2A caller's credential;
  - MUST record the on-behalf-of principal in the audit log.

  With a static client ID, per-client consent applies.
- **R-I3** **As an MCP server** (exposing argent-webway or A2A skills as tools), the bridge:
  - MUST publish RFC 9728 metadata, validate token audience and require PKCE S256;
  - MUST mark per-principal `tools/list` responses `cacheScope:"private"`;
  - MUST normalise tool names to `[A-Za-z0-9_.-]{1,128}` with a namespace prefix.

  Derived annotations are hints only.
- **R-I4** The bridge MUST implement the state mapping in §4.4 explicitly, including how it synthesises SUBMITTED and REJECTED and how it handles `isError:true`. Any `requestState` it mints MUST be HMAC- or AEAD-protected and bound to principal, TTL and request digest.
- **R-I5** Long-running A2A work over MCP MUST work without the tasks extension (synchronous calls with timeouts). The bridge uses MCP tasks only when negotiated for that request. *(TS and Python do not implement it; rmcp is partial.)*
- **R-I6** argent-webway data crossing MCP MUST travel in `_meta` under an argent-webway reverse-DNS prefix, never a reserved one. Signed content MUST be wrapped as raw bytes. *(All three MCP SDKs drop unknown members.)*
- **R-I7** If rmcp is embedded, the bridge MUST set `allowed_origins`, disable `legacy_session_mode`, require protocol metadata, and do inbound OAuth validation in argent-webway's own layer.

### J. Inputs to the M1 interop smoke test
- **R-J1** Test peers: at least Go 2.8.0 (the only full card signing), Python 1.3.x, JS 1.3.x, Java 1.5.x (strict parser), .NET 1.0.0-preview (version and echo differences) and Rust a2a-lf 0.4.x. Each pinned by version.
- **R-J2** Run every case over JSON-RPC, and over REST and gRPC where the peer supports them. Assert on JSON-RPC codes and `ErrorInfo.reason`, not on status codes.
- **R-J3** Local multi-node tests that use push towards stock SDK servers need configuration overrides, because their SSRF guards block loopback (Go, Java, Rust, and .NET by default). Python's guard is opt-in and JS has none. The test harness must document each override and must never ship it as a default.
- **R-J4** Divergences in §3 are expected outcomes, not failures. Record them in the test matrix: Python's unenforced required extensions, Go accepting unsigned cards, missing echoes, and so on.

---

## 6. Evidence for the open decisions (not a decision)

- **Positioning.** The evidence points towards **an A2A 1.0 profile plus a set of A2A extensions**, with an MCP bridge, rather than a new wire protocol:
  - all six SDKs share the 1.0 wire format, and the gaps (identity, message signing, resume, signed push, provenance) fit the extension and `metadata` mechanisms;
  - R-B1 and R-B2 are what make this coexist with stock peers.

  A2A **custom bindings** are also allowed (`S1:1277-1302`); a2a-rs SLIMRPC shows the pattern for a routed, NAT-friendly transport with verified identity. The due diligence should weigh both.
- **Core language.**
  - Rust has an official A2A SDK (a2a-rs: 0.x, a single maintainer, no signing, authorisation scaffolding not wired in, but fuzzed and conformance-tested) and a mature-claiming MCP SDK (rmcp, with high churn and insecure defaults).
  - OCaml has **no** official A2A or MCP SDK, so we would write the protobuf, JSON-RPC, SSE and OAuth layers ourselves.
  - Both Rust SDKs would need wrapping and hardening. Neither gives argent-webway its security properties.

---

## 7. Limits and open items

- Nothing was run. The conformance claims (rmcp Tier 1, a2a-rs and .NET ACTS) and every *inferred* runtime behaviour should be confirmed by the M1 smoke test.
- Python and JS were read about 20 commits past their release tags, and Java 11 commits past. A few cited behaviours are unreleased (Python's plugin hooks; JS unknown-kind skipping and the first-event echo). Those are flagged inline.
- The .NET and JS sections came from delegated source reads with partial spot checks. The load-bearing claims (Go's unsigned-card bypass, Python's HS256 default, Java's strict parser, Rust's absent-header rejection, spec `S1:739`) were re-verified directly.
- The MCP `ext-auth` extensions (client credentials, enterprise-managed authorisation, workload identity federation draft) were not reviewed. They may provide the on-behalf-of mechanism that R-I2 needs.
- A2A v1.1.0-rc is a release candidate on a separate line, and its text may change before release.
