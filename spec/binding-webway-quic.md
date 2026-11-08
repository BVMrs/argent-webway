# A2A binding `webway-quic/v0`

Status: draft, binding version **0.1**. Date: 2026-11-07. Roadmap track T1.
Requirement prefix: `BIND` ([conventions](conventions.md)).

This document specifies `webway-quic/v0`, an A2A 1.0 custom protocol binding (A2A §12) over an authenticated QUIC
overlay. It defines identification, ALPN, the connection handshake, stream types, framing, how each A2A operation
maps onto streams, service parameters, deferred delivery for offline peers, the error mapping, version
negotiation, and the security limits a node enforces. The rules for A2A use on top of the binding are in the
[profile](profile.md). Envelope format, canonicalisation and signatures are in `ext/envelope.md` (T2). This
binding treats envelopes as JSON values with the properties listed in §6.2.

Rationale: due diligence §4.3 (transport and NAT traversal), §4.4 (message model), §4.8 (versioning) and Q2/Q5.

## Contents

1. [Identification and A2A §12 compliance](#1-identification-and-a2a-12-compliance)
2. [Transport](#2-transport)
3. [Connections and the control stream](#3-connections-and-the-control-stream)
4. [Streams](#4-streams)
5. [Identity on the binding](#5-identity-on-the-binding)
6. [Framing and payloads](#6-framing-and-payloads)
7. [Service parameters](#7-service-parameters)
8. [Request streams and operation mapping](#8-request-streams-and-operation-mapping)
9. [Deliver streams (deferred delivery)](#9-deliver-streams-deferred-delivery)
10. [Authentication](#10-authentication)
11. [Error mapping](#11-error-mapping)
12. [Version negotiation](#12-version-negotiation)
13. [Paths, NAT traversal and mobility](#13-paths-nat-traversal-and-mobility)
14. [Local testing](#14-local-testing)
15. [Security considerations](#15-security-considerations)
16. [Conformance](#16-conformance)
17. [Examples](#17-examples)

---

## 1. Identification and A2A §12 compliance

| Item | Value |
|---|---|
| Binding URI (`protocolBinding` in the Agent Card) | `https://github.com/BVMrs/argent-webway/spec/binding/webway-quic/v0` |
| Interface URL | `webway://wwn:<node key>/wwa:<agent key>` (keys in lowercase unpadded base32, RFC 4648) |
| ALPN | `webway/0` |
| Binding version | major `0` (in the URI and ALPN), minor `1` (in HELLO) |
| Payload encoding | UTF-8 JSON (I-JSON), A2A JSON-RPC 2.0 objects inside signed envelopes |

How this document meets each obligation A2A 1.0 places on a custom binding:

| A2A requirement | Where |
|---|---|
| §5.8, §12.7: identify the binding by a URI, declare it in the card with an endpoint URL | §1, profile §5 |
| §12.1: implement all core operations, preserve the data model and semantics | §8.1 (every operation is mapped). The payloads are the A2A JSON-RPC objects, unchanged. |
| §12.2: data type mappings (Protobuf types, timestamps, binary, enums) | §6.3 |
| §3.2.6, §12.3: service parameter transmission, value constraints, reserved names, fallback | §7 |
| §5.4, §12.4: error mapping for every A2A error, error format | §11 |
| §12.5: stream mechanism, ordering, reconnection, termination | §8.3 and profile §7 |
| §12.6: authentication schemes, credential transmission, challenges | §10 |
| §12.8: examples and edge cases (SHOULD) | §17, §16 |

## 2. Transport

- [BIND-001] A node MUST carry this binding over QUIC version 1 (RFC 9000) secured with TLS 1.3 (RFC 9001), with
  ALPN `webway/0` (RFC 7301). If the handshake does not select a `webway/*` ALPN, the node MUST abort the
  connection. It MUST NOT carry this binding over any other ALPN.
- [BIND-002] Both endpoints MUST authenticate with TLS raw public keys (RFC 7250), each an Ed25519 key, which is the
  node key. A node MUST NOT accept X.509 chains or any certificate authority in place of the raw key, and MUST
  require the client to authenticate (mutual authentication). The dialer MUST verify that the listener's key is
  the node key it intended to reach, and abort otherwise.
- [BIND-003] A node MUST NOT send or accept 0-RTT data on a `webway/*` connection.

The reference implementation uses iroh (due diligence Q2), which provides QUIC with raw-key authentication, hole
punching and relays. Nothing in this binding depends on iroh: any QUIC stack that satisfies BIND-001 to BIND-003
interoperates, provided it can reach the peer (§13).

## 3. Connections and the control stream

### 3.1 Connections

Either node may dial the other. A node SHOULD keep at most one connection per peer node. When two connections to
the same peer exist (simultaneous dialing), both are valid. The node with the lexicographically greater node key
SHOULD send GOAWAY on the connection it dialed, so that one remains.

- [BIND-004] A node MUST accept requests on any open connection to the peer, whichever side dialed it, and MUST
  NOT bind a request, a task or a stream cursor to a particular connection. A task outlives every connection.

QUIC idle timeouts close unused connections. A node SHOULD use a `max_idle_timeout` of at least 30 s and keep a
connection alive while it has open streams, using QUIC PING frames. Application-level keepalives are not defined.

### 3.2 The control stream and HELLO

Each endpoint opens one unidirectional **control stream** at once after the handshake and sends a HELLO frame on
it. The control stream stays open for the life of the connection.

- [BIND-005] Each endpoint MUST open exactly one control stream and MUST send HELLO as its first and only HELLO
  frame. A second control stream, a second HELLO, a control stream whose first frame is not HELLO, or the closing
  of the peer's control stream MUST be treated as a connection error (`ProtocolError`, or `ClosedCriticalStream`
  for a closed control stream).
- [BIND-006] An endpoint MUST NOT open request, deliver or extension streams before it has received the peer's
  HELLO. Because QUIC does not order streams, an endpoint MUST also hold any stream the peer opens until the peer's
  HELLO has arrived, and process it afterwards. If no HELLO arrives within 10 s of the handshake, it MUST close the
  connection with `HelloTimeout`.

HELLO payload (a JSON object, unsigned: it is authenticated by the connection, and concerns only this hop):

| Field | Type | Required | Meaning |
|---|---|---|---|
| `binding` | string `"0.N"` | yes | Highest binding minor version of the ALPN's major that the sender implements |
| `profiles` | array of `"MAJOR.MINOR"` | yes | Profile versions the sender implements, the highest minor for each major |
| `a2aVersions` | array of `"Major.Minor"` | yes | A2A versions the sender accepts in `a2a-version` |
| `maxFrameSize` | integer | yes | Largest frame payload, in bytes, the sender will accept. At least 65 536 and at most 16 777 216. |
| `maxPendingDeliver` | integer | no, default 64 | Largest number of DELIVER frames without CUSTODY the sender will accept on one deliver stream (§9) |
| `roles` | array of strings | yes | `"node"`, and `"mailbox-host"` if the sender holds envelopes for other nodes (`ext/mailbox.md`) |
| `features` | array of URIs | no | Binding-level features (extension stream or frame types) the sender implements |

Unknown fields are ignored (BIND-030).

- [BIND-034] Until it has the peer's HELLO, an endpoint MUST NOT send frames larger than 16 384 bytes. A HELLO MUST
  NOT exceed 16 384 bytes, and a receiver MUST treat a larger HELLO as a connection error `FrameTooLarge`, whatever
  `maxFrameSize` it announced.

### 3.3 GOAWAY and closing

An endpoint sends GOAWAY on its control stream to stop new work on a connection. GOAWAY payload:
`{"reason": <string>, "retryAfterMs"?: <integer>}`.

- [BIND-007] After sending GOAWAY, an endpoint MUST finish the streams already open, and MUST reset any request or
  deliver stream the peer opens later with `GoingAway`, without processing its content. After receiving GOAWAY, an
  endpoint MUST NOT open new streams on that connection. When all streams are done, either side closes the
  connection with `NoError`.

A request reset with `GoingAway` was not processed, and can be sent again on another connection or deferred.
Requests on streams that were cut off in any other way have an unknown outcome (§8.4).

## 4. Streams

Every stream starts with a QUIC variable-length integer (RFC 9000 §16), the **stream type**. Frames follow.

| Type | Name | Direction | Opened by | Purpose |
|---|---|---|---|---|
| `0x00` | CONTROL | unidirectional | each endpoint, once | HELLO, GOAWAY (§3) |
| `0x01` | REQUEST | bidirectional | the requester | One A2A operation and its response or event stream (§8) |
| `0x02` | DELIVER | bidirectional | the sender | Deferred envelopes and their custody acknowledgements (§9) |
| `0x03` | BLOB | bidirectional | the fetcher | Reserved for `ext/blob.md` |
| `0x04` | DOC | bidirectional | either | Reserved for `ext/shared-doc.md` |
| `0x05`–`0x1f` | — | — | — | Reserved for this binding |
| `0x20`–`0x3f` | — | — | — | Assigned by extensions, announced in HELLO `features` |

- [BIND-008] A node MUST reset (bidirectional) or stop reading (unidirectional) a stream whose type it does not
  implement, with `StreamTypeUnknown`, and MUST NOT treat it as a connection error. A unidirectional stream with
  type REQUEST, DELIVER, BLOB or DOC, or a bidirectional stream with type CONTROL, MUST be treated as a connection
  error `ProtocolError`.

Concurrency is bounded by QUIC's stream limits (`initial_max_streams_bidi`, `initial_max_streams_uni`). A node
SHOULD allow at least 100 concurrent bidirectional streams per connection.

## 5. Identity on the binding

Two keys appear on every exchange. The node key authenticates the connection (BIND-002). The agent key signs each
envelope (`ext/envelope.md`). The A2A `MutualTlsSecurityScheme` defines no identity mapping, so this section
does.

- [BIND-009] On a REQUEST stream, a responder MUST accept a request envelope only if its `from` agent is bound to
  the connection's peer node by a valid binding statement (`ext/capability.md`). Otherwise it MUST answer
  `IdentityUntrusted`. A requester MUST likewise accept response and event envelopes on a REQUEST stream only if
  their `from` is the agent the request was sent `to`, or the node that agent is bound to (§8.2).
- On a DELIVER stream the peer may be a mailbox host carrying other nodes' envelopes, so the connection's peer key
  says nothing about `from`. Each envelope is verified on its own (signature, binding statement, freshness), and
  a response or event counts for a request only if it is signed by the request's `to` agent or the node that agent
  is bound to (profile PROF-078). An error signed by any other node, such as a mailbox host's `RecipientUnknown`,
  is a per-hop failure.

## 6. Framing and payloads

### 6.1 Frames

A frame is:

```text
Frame {
  Type (i),             // QUIC variable-length integer
  Length (i),           // payload length in bytes
  Payload (..),         // Length bytes
}
```

| Type | Name | Allowed on | Payload |
|---|---|---|---|
| `0x00` | HELLO | CONTROL | JSON object (§3.2) |
| `0x01` | GOAWAY | CONTROL | JSON object (§3.3) |
| `0x02` | REQUEST | REQUEST, requester → responder | Signed envelope (§6.2) |
| `0x03` | RESPONSE | REQUEST, responder → requester | Signed envelope |
| `0x04` | EVENT | REQUEST, responder → requester | Signed envelope |
| `0x05` | END | REQUEST, responder → requester | JSON object `{"reason": …}` (§8.3) |
| `0x06` | DELIVER | DELIVER, opener → peer | Signed envelope |
| `0x07` | CUSTODY | DELIVER, peer → opener | JSON object (§9) |
| `0x08`–`0x1f` | — | — | Reserved for this binding |
| `0x20`–`0x3f` | — | — | Assigned by extensions |

- [BIND-010] A sender MUST encode Type and Length as QUIC variable-length integers in their shortest form. A
  receiver MUST accept any valid encoding, including longer ones.
- [BIND-011] A receiver MUST treat a frame whose Length exceeds the `maxFrameSize` it announced as a connection
  error `FrameTooLarge`, without reading the payload. A stream that ends in the middle of a frame MUST be treated
  as a stream error `ProtocolError`.
- [BIND-012] A receiver MUST skip, by its Length, a frame whose type it does not know, and otherwise ignore it. A
  known frame type on a stream or in a direction where the table above does not allow it MUST be treated as a
  connection error `FrameUnexpected`.
- [BIND-013] JSON payloads MUST be UTF-8 encoded I-JSON (RFC 7493), one JSON value per frame, with no byte order
  mark. A receiver MUST treat a HELLO, GOAWAY, END or CUSTODY payload that is not such a JSON object as a
  connection error `ProtocolError`. A REQUEST, RESPONSE, EVENT or DELIVER payload that does not parse is an
  envelope error, not a connection error. A REQUEST whose envelope `id` cannot be read is answered with an
  `EnvelopeInvalid` RESPONSE whose `rpc.id` is `null` and whose `ctx` has no `inReplyTo` (JSON-RPC's rule for
  unreadable requests). The requester matches it by the stream, which carries one request. A DELIVER whose `id` or
  `from` cannot be read gets a CUSTODY `rejected` with `id` and `from` set to `null`, matched by position
  (BIND-024). A RESPONSE or EVENT that does not parse is `InvalidAgentResponseError` for the requester.

### 6.2 Envelopes and the binding body

Every REQUEST, RESPONSE, EVENT and DELIVER payload is one envelope as `ext/envelope.md` defines it. This binding
relies on these envelope properties: it is a JSON object; it is signed by `from`; it names `to`, `id`, `exp` and
`ctx` (`taskId`, `contextId`, `seq`, `inReplyTo`); its `body` is a JSON value that the signature covers; and
`from` may be a node identity (`wwn:`) for errors the node produces itself (BIND-020). `ext/envelope.md` (T2)
must provide all of these. This binding defines `body`, the **binding body**:

```text
BindingBody {
  svc: { <name>: <string>, … }    // service parameters (§7). Absent means {}.
  rpc: <JSON-RPC 2.0 object>       // request, response or notification, per the A2A JSON-RPC binding (A2A §9)
}
```

- [BIND-014] The `rpc` member of a request MUST be a JSON-RPC 2.0 request object whose `method` is an A2A 1.0
  method name (A2A §5.3), whose `params` is the request message in the A2A JSON-RPC form, and whose `id` is the
  string equal to the envelope's `id`. A responder MUST answer a request whose `rpc` breaks this with
  `MethodNotFoundError` if only the method is unknown, and with `InvalidRequestError` otherwise.
- [BIND-015] The `rpc` member of a RESPONSE MUST be a JSON-RPC 2.0 response object (exactly one of `result` and
  `error`) whose `id` equals the request's `id`. The `rpc` member of an EVENT MUST be a JSON-RPC 2.0 response
  object whose `id` equals the request's `id` and whose `result` is an A2A `StreamResponse` (exactly one of
  `task`, `message`, `statusUpdate`, `artifactUpdate`), exactly as one SSE event of the A2A JSON-RPC binding
  carries. Response and event envelopes MUST have `ctx.inReplyTo` equal to the request's `id`, and an `id` of their
  own that differs from it. The one exception is the error answer to an unreadable request (BIND-013). A requester
  MUST treat a RESPONSE or EVENT that breaks this as `InvalidAgentResponseError`.
- [BIND-016] An EVENT whose `StreamResponse` concerns a task (a `task`, a `statusUpdate`, an `artifactUpdate`, or a
  `message` with a `taskId`) MUST carry `ctx.taskId` and `ctx.seq` (profile PROF-020, PROF-021). A requester MUST
  treat one without them as `InvalidAgentResponseError`.

A gateway can therefore turn an overlay exchange into the A2A JSON-RPC binding by taking `rpc` out of each
envelope, and the reverse by wrapping, with no change to the A2A objects.

### 6.3 Data type mappings

A2A §12.2 asks each custom binding to fix these. They are those of the A2A JSON-RPC binding, narrowed to one form
so that signatures are reproducible (the pinned signer form of `ext/envelope.md`):

| `a2a.proto` type | JSON form on this binding |
|---|---|
| message | object, `lowerCamelCase` field names. A field without explicit presence is omitted when it has its default value. A field with explicit presence (`optional` in `a2a.proto`, such as `historyLength`) is present exactly when it is set, even to its default. A `REQUIRED` field is always present. `ext/envelope.md` must pin the same rule. |
| `string` | string |
| `bytes` | standard base64 with padding (RFC 4648 §4) |
| `int32`, `uint32`, `bool`, `double` | number or boolean |
| `int64`, `uint64` | decimal string |
| enum | the value's name as a string (`"TASK_STATE_WORKING"`), never its number |
| `google.protobuf.Timestamp` | RFC 3339 string in UTC with `Z` |
| `google.protobuf.Struct`, `Value` | JSON object or value. Integers above 2^53 as strings (PROF-006). |
| `oneof` | exactly one member present |

## 7. Service parameters

A2A service parameters (A2A §3.2.6) travel in the `svc` member of the binding body, inside the signature. This
binding has no headers and no other mechanism, so there is no fallback to define.

- [BIND-017] `svc` MUST be a JSON object whose keys are lowercase ASCII matching `^[a-z0-9][a-z0-9-]{0,63}$` and
  whose values are strings of at most 4 096 bytes. The whole `svc` object MUST NOT exceed 16 384 bytes. A
  responder MUST reject a request that breaks these rules with `InvalidRequestError`.
- [BIND-018] A request MUST carry `a2a-version`. A responder MUST treat an absent `a2a-version` as `0.3`, and so
  answer `VersionNotSupportedError` (profile PROF-054).

Defined names:

| Name | In | Value | Meaning |
|---|---|---|---|
| `a2a-version` | request | `Major.Minor` | A2A version of the request (A2A `A2A-Version`) |
| `a2a-extensions` | request | comma-separated URIs, no spaces | Extensions the requester asks to activate (A2A `A2A-Extensions`) |
| `a2a-extensions` | response | comma-separated URIs, no spaces | Extensions the responder activated for this request. The signed echo of profile PROF-056. |
| `webway-from-seq` | `SubscribeToTask` request | decimal integer ≥ 0 | Resume cursor (profile §7.2) |
| `webway-reply` | `SendMessage`, `CancelTask` request | `deferred` | Deliver the response by deferred delivery when the request did not arrive on a live REQUEST stream, and deliver the task's later events by deferred delivery to the requester (profile §8.1, PROF-036) |

Names starting `a2a-` are reserved for A2A. Names starting `webway-` are reserved for argent-webway documents.
Unknown names are ignored but, being signed, are forwarded unchanged. A2A says parameter names are
case-insensitive. This binding makes them lowercase on the wire so that signatures are reproducible.

## 8. Request streams and operation mapping

### 8.1 Operations

| A2A 1.0 method | Mode | May also take the deferred path (§9) |
|---|---|---|
| `SendMessage` | unary | yes (profile §8.1) |
| `SendStreamingMessage` | streaming | no |
| `GetTask` | unary | no |
| `ListTasks` | unary | no |
| `CancelTask` | unary | yes |
| `SubscribeToTask` | streaming | no |
| `CreateTaskPushNotificationConfig` | unary | no |
| `GetTaskPushNotificationConfig` | unary | no |
| `ListTaskPushNotificationConfigs` | unary | no |
| `DeleteTaskPushNotificationConfig` | unary | no |
| `GetExtendedAgentCard` | unary | no |

### 8.2 Stream grammar

A REQUEST stream carries exactly one operation:

```text
requester → responder:   REQUEST  FIN
responder → requester:   unary:                 RESPONSE  FIN
                         SendStreamingMessage:  EVENT+ END FIN
                                              | EVENT* RESPONSE FIN    // RESPONSE carries an error
                         SubscribeToTask:       EVENT* END FIN
                                              | EVENT* RESPONSE FIN    // RESPONSE carries an error
```

- [BIND-019] A requester MUST open a new REQUEST stream for each operation, send exactly one REQUEST frame and then
  end its side of the stream. A responder MUST follow the grammar above for the operation. A RESPONSE on a
  streaming operation MUST carry an error, not a result. (A `SendStreamingMessage` stream always starts with the
  task or message. A `SubscribeToTask` stream can end with no event, for example when the responder shuts down
  before anything happened.) Any other sequence MUST be treated as a stream error
  `FrameUnexpected` (unknown frame types excepted, BIND-012).
- [BIND-020] A responder MUST answer a REQUEST that fails envelope verification, authentication, authorisation or
  version checks with a RESPONSE carrying the error (§11). When the error occurs before the request can be
  attributed to an agent the node hosts (for example `RecipientUnknown`), the node signs the error envelope with
  its node key, `from` set to its `wwn` identity.

### 8.3 Streaming: order, termination, reconnection

- **Order.** EVENT frames for a task are sent in `seq` order (profile §7.3). One stream carries one task's events.
- **Termination.** The responder sends END after the event that carries a terminal state (`reason: "terminal"`),
  after the single `Message` of a `SendStreamingMessage` answered without a task (`"message"`), or when it stops
  for its own reasons (`"shutdown"`, `"interrupted"` if it closes at an interrupted state). END is advisory and
  unsigned. Completion is only ever known from a signed terminal event (profile PROF-024).
- **Eviction.** A responder that drops a slow subscriber resets the stream with `SubscriberEvicted` (profile
  PROF-029).
- **Reconnection.** After a stream breaks, the requester opens a new REQUEST stream with `SubscribeToTask` and
  `webway-from-seq` set to one more than the last `seq` it applied (profile §7.2), on any connection.
- **Losing interest.** A requester that no longer wants events resets its stream, or sends STOP_SENDING, with
  `RequestCancelled`. This never cancels the task (profile PROF-026).

- [BIND-021] A responder MUST NOT send END with `reason: "terminal"` unless the last EVENT it sent on the stream
  carries a terminal state. A requester MUST NOT infer anything about the task from END beyond "this stream is
  finished".

### 8.4 Unknown outcomes and retries

If a REQUEST stream is reset (other than with `GoingAway`) or the connection is lost before the RESPONSE arrives,
the requester cannot tell whether the request was processed.

- [BIND-022] After such a failure the requester MUST either give up on the request explicitly (and record that the
  outcome is unknown) or send the byte-identical request envelope again, on a new stream or by the deferred path,
  until `exp`. It MUST NOT create a new envelope for the same intent, because a new `id` defeats the responder's
  de-duplication (profile PROF-023, PROF-033).

## 9. Deliver streams (deferred delivery)

A DELIVER stream carries envelopes that are not tied to a live request: requests to an offline peer, their
responses and events, and the mailbox traffic of `ext/mailbox.md`. The opener sends DELIVER frames. The peer
answers each with a CUSTODY frame, in the same order.

```text
opener → peer:   DELIVER*  FIN
peer → opener:   CUSTODY*  FIN     // one CUSTODY per DELIVER, in order
```

CUSTODY payload:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | The delivered envelope's `id` |
| `from` | string | The delivered envelope's `from` |
| `status` | `"accepted"` \| `"duplicate"` \| `"rejected"` | `accepted`: stored durably by this peer. `duplicate`: already held or processed (dedupe). `rejected`: not stored. |
| `error` | object | With `rejected` only: `{"code", "reason", "retryable", "retryAfterMs"?}` as profile §10 |

- [BIND-023] A peer MUST send `accepted` only after it has stored the envelope durably, either as its final
  recipient (the `to` agent is hosted here, and the envelope has been processed or queued for processing as
  profile §6.5 requires) or as a mailbox host for the `to` agent (`ext/mailbox.md`). Otherwise it MUST send
  `rejected` with the reason (`RecipientUnknown` if it is neither).
- [BIND-024] An opener MUST NOT have more than the peer's `maxPendingDeliver` DELIVER frames without a CUSTODY on
  one stream. A peer MUST answer with CUSTODY frames in the order of the DELIVER frames.
- [BIND-025] On a DELIVER stream, a final recipient answers a request envelope with a response envelope delivered
  back on a DELIVER stream that it opens (to the requester node if reachable, else to the requester's mailbox
  host), never on the same stream. A `duplicate` CUSTODY MUST NOT carry the stored response, because the
  connection's peer need not be the original sender. The original sender gets the stored response by deferred
  delivery, as for any response.

CUSTODY is per hop and unsigned. It moves the requester's delivery state to `sent` (profile §8.3), never to
`acknowledged`. Only the responder's signed response does that. Signed receipts for non-repudiation are
`ext/audit.md`'s.

## 10. Authentication

A2A §12.6 asks each binding to say which schemes it supports, how credentials travel, and how challenges work.

- **Scheme.** The card declares this binding's authentication as the `webway` security scheme of type
  `mtlsSecurityScheme` (profile §5). A2A applies `securityRequirements` card-wide, as alternatives. On this
  binding only the `webway` alternative can be met, and it is the only one a node checks here. The card's other
  alternatives (OAuth 2.0, OIDC …) are for its HTTP interfaces (profile PROF-075).
- **Credentials.** The node key is proved by the QUIC/TLS handshake (BIND-002). The agent key is proved by the
  envelope signature. Authorisation is carried as capability tokens in the envelope's `cap` field
  (`ext/capability.md`), inside the signature. No credential is carried in `svc`, in `metadata` or in message
  content (profile PROF-048).
- **Challenges.** A missing or insufficient credential gets an error RESPONSE (`CapabilityMissing`,
  `CapabilityDenied`, `IdentityUntrusted`, §11). An agent that needs more authorisation in the middle of a task
  uses the A2A `auth-required` state, and the requester obtains a capability out of band (an invite, an owner
  grant), never through message text.

## 11. Error mapping

### 11.1 Operation errors

- [BIND-026] A responder MUST report every A2A error, and every profile error, as a JSON-RPC error object (profile
  §10.1: code, message, `ErrorInfo` with reason, domain and retryability) in the `rpc` member of a signed
  RESPONSE. The codes are those of the A2A JSON-RPC binding (A2A §5.4) and of profile §10.3, unchanged.

| A2A error | On this binding |
|---|---|
| `TaskNotFoundError` … `VersionNotSupportedError` (−32001 … −32009) | RESPONSE, `rpc.error.code` = the A2A JSON-RPC code, `ErrorInfo.reason` as profile §10.2 |
| JSON-RPC standard errors (−32600, −32601, −32602, −32603) | RESPONSE, same codes |
| JSON parse error | The REQUEST payload did not parse: `EnvelopeInvalid` (−30001) |
| Profile errors (−30001 … −30099) | RESPONSE, profile §10.3 |

### 11.2 Transport errors

Problems with frames and streams, as opposed to operations, close the stream or the connection with a QUIC
application error code. These are per hop and unsigned.

| Code | Name | Scope | Meaning |
|---|---|---|---|
| `0x00` | `NoError` | connection, stream | Clean close |
| `0x01` | `ProtocolError` | connection, stream | Violation of this binding not covered below |
| `0x02` | `FrameTooLarge` | connection | Frame over `maxFrameSize` (BIND-011) |
| `0x03` | `FrameUnexpected` | connection, stream | A frame where the stream grammar does not allow it (BIND-012, BIND-019) |
| `0x04` | `ClosedCriticalStream` | connection | A control stream was closed (BIND-005) |
| `0x05` | `HelloTimeout` | connection | No HELLO in time (BIND-006) |
| `0x06` | `VersionMismatch` | connection | No common profile major (§12) |
| `0x07` | `GoingAway` | connection, stream | GOAWAY in effect. The stream was not processed (BIND-007). |
| `0x08` | `RequestCancelled` | stream | The requester lost interest (§8.3) |
| `0x09` | `SubscriberEvicted` | stream | Slow subscriber dropped (profile PROF-029) |
| `0x0a` | `ExcessiveLoad` | connection, stream | The peer is using too many resources (§15) |
| `0x0b` | `StreamTypeUnknown` | stream | Unknown stream type (BIND-008) |
| `0x0c` | `InternalFailure` | connection, stream | The node failed internally |

A failed handshake (no common ALPN, a key that is not the expected node key) is reported by TLS itself, with the
alerts `no_application_protocol` and `bad_certificate`. In this document and in vectors, the first is named
`NoApplicationProtocol`.

- [BIND-027] A node MUST use the codes in the table above for the conditions they name. It MUST NOT use a transport
  error to report an A2A or profile error that it could report as a RESPONSE.

## 12. Version negotiation

Versions are settled in three steps, each failing cleanly:

1. **ALPN** selects the binding major. The dialer offers every `webway/<major>` it implements. The listener selects
   the highest one it also implements. If there is none, the handshake fails (`NoApplicationProtocol`). TLS 1.3
   authenticates the ALPN choice, so a man in the middle cannot force a lower major.
2. **HELLO** settles the binding minor, the profile version and the acceptable A2A versions for the connection.
3. **Each request** carries its own `a2a-version` (§7).

- [BIND-028] With both HELLOs in hand, each endpoint MUST compute: the effective binding minor as the lower of the
  two `binding` values; the effective profile as the highest major present in both `profiles` lists, at the lower
  of the two minors for that major; and the common A2A versions as the intersection of the two `a2aVersions`
  lists. If there is no common profile major, it MUST close the connection with `VersionMismatch`. Each endpoint
  MUST then use only the features of the effective binding minor and profile.
- [BIND-029] A requester MUST set `a2a-version` to the highest version that is in the common A2A versions and not
  above the target interface's `protocolVersion`. If there is none, it MUST NOT send the request, and reports
  `VersionNotSupportedError` to its caller locally.
- [BIND-030] An endpoint MUST ignore HELLO fields it does not know, and MUST NOT close a connection because the
  peer's binding or profile minor is higher than its own.

Minor versions are additive (profile §11.2): a higher minor may add HELLO fields, frame types (ignored by
BIND-012), stream types (refused by BIND-008, harmlessly) and service parameters (ignored), and nothing else. A
change that cannot be expressed that way is a new major: a new ALPN and a new binding URI.

## 13. Paths, NAT traversal and mobility

Connections are addressed by node key, not by IP address. A node resolves a peer's node key to its current direct
addresses and home relay through discovery (due diligence §4.2). The QUIC stack tries hole punching, and falls
back to the relay, which forwards encrypted QUIC packets. About 30% of paths in comparable systems need the relay
(due diligence §4.3), so the relay path is a normal path.

- [BIND-031] A relay MUST NOT terminate TLS or QUIC: it forwards packets between the two endpoints and cannot read
  or alter streams. A node MUST NOT behave differently on a relayed path than on a direct one, except for
  performance.

QUIC connection migration keeps streams alive when a node changes network or moves between relay and direct
paths. When migration fails, the connection closes, and §8.4 applies to requests in flight. A responder's tasks
continue regardless (BIND-004), and the requester resubscribes with its cursor.

## 14. Local testing

Several nodes on one machine (due diligence §4.9, S6) use the same binding:

- **Loopback**: real QUIC over `127.0.0.1` / `::1`, with a static discovery table instead of DNS, and a local test
  relay that can forbid direct paths between chosen pairs ("A cannot dial B"), so relay paths are exercised.
- **In-memory**: a transport that connects endpoints with in-process byte channels. It provides authenticated
  bidirectional and unidirectional streams with the same keys and the same stream and frame bytes as QUIC.
- **Fault injection** in the test relay and the in-memory transport: added latency, loss, reordering across
  streams, partitions, and connection resets at chosen frames. Clocks are explicit and seedable.

- [BIND-032] An in-memory or test transport MUST carry exactly the stream types, frames and payload bytes of this
  binding, so that every conformance case means the same thing on it as on QUIC. Only the packet layer may differ.

## 15. Security considerations

- **No 0-RTT** (BIND-003). 0-RTT data can be replayed by the network. Envelope dedupe would catch replayed
  requests, but not replayed HELLOs or the work done to verify them, and the benefit is small for a protocol whose
  requests are durable.
- **Two signatures, two scopes.** The connection proves which node is at the other end of this hop. The envelope
  proves which agent said what, end to end, across relays and mailboxes. Everything unsigned in this binding
  (HELLO, GOAWAY, END, CUSTODY, transport error codes) is per hop and cannot change what a task did: completion
  needs a signed terminal event (BIND-021), and acknowledgement needs a signed response (§9).
- **Relays and mailbox hosts.** A relay sees node keys, packet sizes and timing, and nothing else. A mailbox host
  sees envelopes until sealed envelopes exist (T15, due diligence §4.5). Both can drop or delay traffic. `exp`
  bounds the delay, and the delivery state machine (profile §8.3) makes drops visible as `expired`.
- **Resource limits.**
  - [BIND-033] A node MUST bound, per connection: concurrent streams (QUIC stream limits), frame size (BIND-011),
    pending DELIVER frames (BIND-024), and the time a stream may stay open without progress. It MUST bound per
    peer node the number of tasks and stream subscriptions it holds. It MUST verify an envelope's signature before
    doing any work for it that is more expensive than the verification, and MUST NOT allocate a buffer from a
    Length before checking it against `maxFrameSize`. Limits exceeded by a peer lead to `ExcessiveLoad` or
    `RateLimited`.
- **Amplification.** QUIC address validation applies unchanged. A node SHOULD not send more than three times the
  bytes received from an unvalidated address.
- **Downgrade.** ALPN selection is authenticated by TLS 1.3. Profile and binding minors only add features.
  `a2a-version` and `a2a-extensions` are inside the envelope signature. There is no unsigned negotiation that an
  attacker could rewrite.
- **Stream-type confusion.** Unknown stream types are refused (BIND-008), and frames are allowed only where the
  table in §6.1 allows them (BIND-012), so a peer cannot slip a REQUEST into a deliver stream to dodge BIND-009.

## 16. Conformance

Vector kinds defined by this document (format in [`conformance/vectors/README.md`](../conformance/vectors/README.md)).
Byte strings are lowercase hex.

| Kind | Input | Output on `accept` | Rejections |
|---|---|---|---|
| `bind/frame` | `{"bidi": <bool>, "direction": "opener-to-peer" \| "peer-to-opener", "streamType"?: <name>, "hex": <bytes>, "fin": <bool>, "maxFrameSize": <int>}` | `{"streamType": <name>, "frames": [{"type": <name>, "length": <int>}…], "ignored": <int>}`. Unknown frames are counted in `ignored`, not listed. | `ProtocolError`, `FrameTooLarge`, `FrameUnexpected`, `StreamTypeUnknown` |
| `bind/stream` | `{"op": <A2A method>, "toResponder": [<frame name>…], "toRequester": [<frame name>…]}` | none | `FrameUnexpected` |
| `bind/negotiate` | `{"dialer": {"alpn": […], "hello": <HELLO>}, "listener": {"alpn": […], "hello": <HELLO>}, "targetProtocolVersion"?: <string>}` | `{"alpn", "binding", "profile", "a2aVersions", "requestA2aVersion"?}` | `NoApplicationProtocol`, `VersionMismatch`, `VersionNotSupportedError` |
| `bind/svc` | `{"svc": <object or absent>, "op": <A2A method>, "supported": [<A2A version>…]}` | `{"a2aVersion", "extensions": […], "fromSeq"?: <int>}` | `InvalidRequestError`, `VersionNotSupportedError` |
| `bind/body` | `{"frame": "REQUEST" \| "RESPONSE" \| "EVENT", "envelope": {"id", "ctx"?, "body"}, "requestId"?: <string>}`. `requestId` (the request envelope's `id`) is given for RESPONSE and EVENT. | `{"method"}` for REQUEST, else none | `InvalidRequestError`, `MethodNotFoundError`, `InvalidAgentResponseError` |

For `bind/frame`, `bidi` and `direction` say which kind of stream the bytes are on and which side sent them. In
the `opener-to-peer` direction the first varint of `hex` is the stream type. In the `peer-to-opener` direction
(bidirectional streams only) the stream type is given as `streamType` and `hex` holds only frames. Stream and
frame types are named as in §4 and §6.1. With `fin: false`, a partial frame at the end is not an error and is not
listed. The frame decoder checks HELLO, GOAWAY, END and CUSTODY payloads for being JSON objects (BIND-013) and
treats REQUEST, RESPONSE, EVENT and DELIVER payloads as opaque.

`bind/negotiate` lists `a2aVersions` in ascending order. `requestA2aVersion` is present only when
`targetProtocolVersion` is given.

| Requirement | Covered by |
|---|---|
| BIND-005 (first frame HELLO), BIND-008, BIND-010, BIND-011, BIND-012, BIND-013, BIND-034 | `bind/frame` |
| BIND-019 | `bind/stream` |
| BIND-028, BIND-029, BIND-030 | `bind/negotiate` |
| BIND-017, BIND-018 | `bind/svc` |
| BIND-014, BIND-015, BIND-016 | `bind/body` |
| All others | Harness scenarios (T4, T5). Not written yet: see profile §15. |

## 17. Examples

### 17.1 HELLO on a control stream

HELLO payload (98 bytes):

```json
{"binding":"0.1","profiles":["0.1"],"a2aVersions":["1.0"],"maxFrameSize":1048576,"roles":["node"]}
```

Stream bytes: stream type `00` (CONTROL), frame type `00` (HELLO), length `4062` (98 as a two-byte varint), then
the payload:

```text
00 00 40 62 7b 22 62 69 6e 64 69 6e 67 22 3a 22 30 2e 31 22 2c …
```

### 17.2 `GetTask`

Request envelope on a new REQUEST stream (envelope fields abridged, see `ext/envelope.md`):

```json
{
  "v": "webway-envelope/0",
  "from": "wwa:planner…", "to": "wwa:tester…",
  "id": "0193a5c4-7d3e-7b11-9f00-2a6c1e000001",
  "ts": "2026-11-07T10:00:00Z", "exp": "2026-11-07T10:05:00Z",
  "ctx": { "taskId": "task-42" },
  "cap": { "access": "<capability token>" },
  "body": {
    "svc": { "a2a-version": "1.0" },
    "rpc": { "jsonrpc": "2.0", "id": "0193a5c4-7d3e-7b11-9f00-2a6c1e000001",
             "method": "GetTask", "params": { "id": "task-42" } }
  },
  "body_hash": "…", "sig": "…"
}
```

RESPONSE, an error because the caller may not see the task (profile PROF-047):

```json
{
  "body": {
    "rpc": { "jsonrpc": "2.0", "id": "0193a5c4-7d3e-7b11-9f00-2a6c1e000001",
             "error": { "code": -32001, "message": "Task not found",
                        "data": [ { "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                                    "reason": "TASK_NOT_FOUND", "domain": "a2a-protocol.org",
                                    "metadata": { "retryable": "false" } } ] } }
  },
  "ctx": { "inReplyTo": "0193a5c4-7d3e-7b11-9f00-2a6c1e000001" }
}
```

### 17.3 `SendStreamingMessage`

```text
requester → responder   REQUEST   rpc.method = "SendStreamingMessage"         FIN
responder → requester   EVENT     ctx.seq = 0   result.task (TASK_STATE_SUBMITTED)
                        EVENT     ctx.seq = 1   result.statusUpdate (TASK_STATE_WORKING)
                        EVENT     ctx.seq = 2   result.artifactUpdate (blob reference, > 64 KiB)
                        EVENT     ctx.seq = 3   result.statusUpdate (TASK_STATE_COMPLETED)
                        END       {"reason": "terminal"}                       FIN
```

If the connection breaks after `seq = 1`, the requester opens a new REQUEST stream with
`SubscribeToTask {"id": <task>}` and `svc: {"a2a-version": "1.0", "webway-from-seq": "2"}`, and receives events 2
and 3 and END.
