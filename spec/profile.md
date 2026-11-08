# argent-webway Profile of A2A 1.0

Status: draft, profile version **0.1** (`webway-profile/0.1`). Date: 2026-11-07. Roadmap track T1.
Requirement prefix: `PROF` ([conventions](conventions.md)).

This document says how argent-webway uses A2A 1.0, and where it sits relative to A2A and MCP. It lists the A2A
features a conforming node must implement, the rules it adds on top of them (task state machine, durability,
idempotency, streaming, offline peers, security posture), the error model, versioning, and how the bridges to the
A2A HTTP bindings and to MCP attach. The transport binding used between argent-webway nodes is specified separately
in [`binding-webway-quic.md`](binding-webway-quic.md).

Design rationale lives in the due diligence ([`docs/due-diligence.md`](../docs/due-diligence.md), §3, §4.3–§4.5,
§4.7, §4.8) and the interop research ([`docs/research/a2a-mcp-interop.md`](../docs/research/a2a-mcp-interop.md),
cited as "research §n"). This document is normative. Those two are not.

## Contents

1. [Position](#1-position)
2. [Terminology and identifiers](#2-terminology-and-identifiers)
3. [A2A baseline and mandatory features](#3-a2a-baseline-and-mandatory-features)
4. [Wire hygiene towards stock A2A peers](#4-wire-hygiene-towards-stock-a2a-peers)
5. [Agent Card](#5-agent-card)
6. [Task model](#6-task-model)
7. [Streaming](#7-streaming)
8. [Offline peers](#8-offline-peers)
9. [Security rules](#9-security-rules)
10. [Error model](#10-error-model)
11. [Versioning](#11-versioning)
12. [Bridges](#12-bridges)
13. [Disposition of the research candidates](#13-disposition-of-the-research-candidates)
14. [Conformance](#14-conformance)
15. [Open issues](#15-open-issues)

---

## 1. Position

argent-webway is **an A2A 1.0 profile, a set of A2A extensions, and one A2A custom binding**. It is not a new
agent protocol. This is option A of due diligence §3.

| Layer | What argent-webway does | Relation |
|---|---|---|
| Data model and operations | A2A 1.0 (`a2a.proto` at tag v1.0.1), unchanged | **Reuse** |
| Rules on top (this document) | Mandatory features, task state machine, durability, idempotency, offline behaviour, security posture, error registry | **Profile** of A2A |
| Signed envelopes, capabilities, mailbox, blobs, provenance, audit, shared docs | `…/ext/<name>/v0` documents | **Extensions** of A2A (§4.6 of A2A) |
| Node-to-node transport | `webway-quic/v0`, an authenticated QUIC overlay with relays | **Custom binding** of A2A (§12 of A2A) |
| Stock A2A clients and servers (JSON-RPC, HTTP+JSON, gRPC) | Edge gateway | **Bridge** |
| MCP (agent-to-tool) | Node is an MCP server to its own agents. Remote skills can be exposed as MCP tools. Local MCP tools can be exposed as skills. | **Bridge**. MCP is not used between nodes. |
| AGNTCY SLIM, NATS | Later (roadmap T18) | **Bridge** |

Two consequences shape the rest of this document:

- Between argent-webway nodes, everything is A2A 1.0 objects inside signed envelopes on `webway-quic/v0`. A node
  can therefore relay to and from the A2A HTTP bindings without translating the data model.
- Stock A2A peers get none of the extra guarantees (signatures, capabilities, durable delivery). The profile says
  exactly what a node does about that: it labels their content `unverified-origin` and enforces its own policy
  (§9, §12).

## 2. Terminology and identifiers

- **Node**: a process that holds network keys, speaks `webway-quic/v0`, and hosts agents. Identified by
  `wwn:<base32 Ed25519 public key>`.
- **Agent**: a logical agent hosted by a node, with its own key held by the node. Identified by
  `wwa:<base32 Ed25519 public key>`. Agents never hold network keys. They reach their node over MCP or a local A2A
  interface (the **local interface**).
- **Owner**: the person or organisation whose key certifies nodes and agents (`ext/capability.md`, T3).
- **Stock peer**: an A2A client or server that does not implement this profile.
- **Requester node / responder node**: the node hosting the agent that sends a request / the agent it is sent to.
- **Bridge agent**: an agent hosted by a node that represents something outside the overlay (a stock A2A
  endpoint, an MCP server). See §12.1.
- **Proxy task**: the task record a requester node shows its own agent for a task on a remote agent (§8.2).
- The A2A task states are written in this document by their short names (`submitted`, `working`,
  `input-required`, `auth-required`, `completed`, `failed`, `canceled`, `rejected`). On the wire they are the
  `a2a.proto` enum names (`TASK_STATE_SUBMITTED` …). **Terminal** states: `completed`, `failed`, `canceled`,
  `rejected`. **Interrupted** states: `input-required`, `auth-required`. **Active** states: the non-terminal ones.

Identifiers fixed by this profile:

| Name | Value |
|---|---|
| Profile URI | `https://github.com/BVMrs/argent-webway/spec/profile/v0` |
| Extension URIs | `https://github.com/BVMrs/argent-webway/spec/ext/<name>/v0`, written `…/ext/<name>/v0` below |
| Binding URI | `https://github.com/BVMrs/argent-webway/spec/binding/webway-quic/v0` |
| Agent address (interface URL) | `webway://wwn:<node>/wwa:<agent>` |
| JSON-RPC error domain | `github.com/BVMrs/argent-webway` |
| MCP `_meta` prefix | `io.github.bvmrs.argent-webway/` |

Profile constants:

| Constant | Value | Meaning |
|---|---|---|
| `SKEW` | 300 s | Clock tolerance (`ext/envelope.md`) |
| `MAX_TTL` | 7 days | Upper bound on `exp − ts` of any envelope |
| `DEFAULT_TTL` | 24 h | Expiry a node uses for a request when its agent does not choose one |
| `INLINE_MAX` | 64 KiB | Largest Part sent inline. Larger content goes by blob reference (`ext/blob.md`). |
| `SUBSCRIBER_MIN_BUFFER` | 64 events | Smallest per-subscriber buffer a node may use before evicting (§7.4) |

## 3. A2A baseline and mandatory features

- [PROF-001] A node MUST implement A2A **1.0** as published at tag v1.0.1 of the A2A repository, with `a2a.proto`
  as the normative schema. A2A 1.1 features (`generation`, `last_seen_generation`, `SendLiveMessage`,
  `ifGenerationMatch`) are OPTIONAL. A node MUST NOT use them towards an interface whose declared
  `protocolVersion` is lower than `1.1`.

Status of each A2A 1.0 feature in this profile:

| A2A 1.0 feature | On `webway-quic/v0` | At the HTTP edge | Notes |
|---|---|---|---|
| `SendMessage` | MUST | MUST | Both blocking and `return_immediately` forms |
| `SendStreamingMessage` | MUST | MUST | |
| `GetTask` | MUST | MUST | Scoped to the caller (§9) |
| `ListTasks` | MUST | MUST | Scoped to the caller (§9) |
| `CancelTask` | MUST | MUST | §6.3 |
| `SubscribeToTask` | MUST | MUST | Plus the profile's cursor (§7.2) |
| Push notification config (Create/Get/List/Delete) | MAY. Otherwise `PushNotificationNotSupportedError` | MAY | Inside the overlay, event delivery to offline requesters is the mailbox (§8.4), not webhooks |
| `GetExtendedAgentCard` | MAY | MAY | |
| Agent Card | MUST, signed (§5) | MUST, the same card | |
| `capabilities.streaming` | MUST be `true` | | |
| Extensions (§4.6 of A2A) | MUST, with in-band activation (§11.3) | MUST | |
| `A2A-Version` service parameter | MUST be sent on every request (PROF-002) | MUST | |
| Messages answered with a `Message` instead of a `Task` | MAY | MAY | No task, so §6 does not apply. Idempotency still does (§6.5). |
| Multi-tenancy (`tenant`) | MAY | MAY | Routing only, never authorisation (PROF-046) |

- [PROF-002] A node MUST implement every operation marked MUST in the table above, on every interface it
  declares. A node MUST send the `A2A-Version` service parameter with value `1.0` on every A2A request it sends, on
  every binding. It MUST NOT send a minor version higher than the target interface's declared `protocolVersion`.
- [PROF-003] A node acting as a client MUST select the interface it calls by both `protocolBinding` and
  `protocolVersion`, never by `protocolBinding` alone. Between two argent-webway agents it MUST prefer the
  `webway-quic/v0` interface over an HTTP interface of the same agent.

## 4. Wire hygiene towards stock A2A peers

Stock SDKs disagree on unknown fields and enum values: one rejects unknown fields outright, the others drop them,
and unknown enum values break parsing in several (research §3.6). The profile is therefore conservative in what
it sends.

- [PROF-004] A node MUST NOT add fields to A2A core objects (those defined in `a2a.proto`) in anything it sends to
  a stock peer. All argent-webway data that travels inside A2A objects MUST be placed in a `metadata` map under a
  key that is the URI of the extension or profile that defines it, or in `AgentExtension.params`.
- [PROF-005] A node MUST NOT send enum values, Part kinds, `SecurityScheme` types or `StreamResponse` kinds that
  are not defined in A2A 1.0. argent-webway authentication MUST be described in an Agent Card with existing scheme
  types only (§5).
- [PROF-006] Integer values in `metadata` that can exceed 2^53 in magnitude MUST be encoded as JSON strings.
- [PROF-007] When a node parses A2A objects, it MUST surface an unknown enum value to its own logic as "unknown",
  never map it silently to a default or to `*_UNSPECIFIED`. Where a signature or a forward depends on the received
  form, the node MUST keep the received JSON value, including unknown fields (the generic-JSON rule of
  `ext/envelope.md`).

Unknown fields that are not argent-webway data SHOULD be ignored, as A2A §5.7 says.

## 5. Agent Card

- [PROF-008] Every agent hosted by a node MUST publish an A2A 1.0 Agent Card that:
  1. lists in `supportedInterfaces` one interface with `protocolBinding` equal to the binding URI, `url` equal to
     the agent address, and `protocolVersion` `"1.0"`, plus any HTTP interfaces the agent's node offers at its
     edge;
  2. sets `capabilities.streaming` to `true`;
  3. declares the profile in `capabilities.extensions` as an `AgentExtension` with `uri` equal to the profile URI,
     `required: false`, and `params` `{"version": "<MAJOR.MINOR>"}`;
  4. declares every argent-webway extension it supports in the same list, each with `required: false`.
- [PROF-009] A profile card MUST NOT set `required: true` on the profile or on any argent-webway extension. On
  `webway-quic/v0` the binding already implies them (§11.3). At the HTTP edge `required: true` would refuse stock
  clients that some SDKs enforce it for (research §3.3), and argent-webway does not treat `required` as a security
  control in any case (PROF-050).
- [PROF-010] A profile card MUST be signed as A2A §8.4 describes (detached JWS over the JCS canonical form). The
  protected header MUST contain `alg`, `kid` and `typ`. `alg` MUST be `EdDSA` with an Ed25519 key. The card MUST
  contain no field outside the A2A 1.0 schema, and SHOULD NOT contain optional fields set to empty values, so
  that the signature verifies in every SDK that can verify (research §3.2).
- [PROF-011] A node verifying a card MUST reject `alg` values other than `EdDSA` and `ES256` (in particular `none`
  and every `HS*`), MUST fail closed when policy requires a signature and the card has none, and MUST NOT fetch a
  `jku` URL unless that URL is on an allow-list bound to the card's origin or provider.
- [PROF-012] Nodes, relays, mailbox hosts and bridges MUST serve and forward signed cards byte for byte. They
  MUST NOT re-serialise them.
- [PROF-013] A card signature MUST NOT be treated as proof of identity on its own. The identity of an agent is its
  key, certified by its owner through the binding statement of `ext/capability.md`. A node MUST check that the
  card's signing key is the agent's owner key named in that binding before using the card for anything except
  display.
- [PROF-014] Card text (`name`, `description`, skill descriptions, examples, extension descriptions) received from
  a peer is untrusted data. A node MUST NOT put it into an agent's instructions. It MUST give it to agents only as
  labelled data (§9.3).

The interface declares argent-webway authentication with an existing scheme type (PROF-005): a `securitySchemes`
entry named `webway` of type `mtlsSecurityScheme`, whose `description` points to the binding URI. It appears in
`securityRequirements` as one alternative next to whatever the HTTP edge uses. Example (abridged, unsigned):

```json
{
  "name": "tester",
  "supportedInterfaces": [
    { "url": "webway://wwn:k3h…q/wwa:7td…a",
      "protocolBinding": "https://github.com/BVMrs/argent-webway/spec/binding/webway-quic/v0",
      "protocolVersion": "1.0" },
    { "url": "https://beta.example.org/a2a/tester", "protocolBinding": "JSONRPC", "protocolVersion": "1.0" }
  ],
  "capabilities": {
    "streaming": true,
    "extensions": [
      { "uri": "https://github.com/BVMrs/argent-webway/spec/profile/v0", "params": { "version": "0.1" } },
      { "uri": "https://github.com/BVMrs/argent-webway/spec/ext/envelope/v0" },
      { "uri": "https://github.com/BVMrs/argent-webway/spec/ext/capability/v0" },
      { "uri": "https://github.com/BVMrs/argent-webway/spec/ext/mailbox/v0" }
    ]
  },
  "securitySchemes": {
    "webway": { "mtlsSecurityScheme": { "description": "argent-webway: https://github.com/BVMrs/argent-webway/spec/binding/webway-quic/v0" } }
  }
}
```

## 6. Task model

A2A 1.0 lists the task states but gives no transition table (research §2). This section fixes one. It is
deliberately permissive where A2A is silent, so that stock agents behind a bridge are not broken by it, and strict
about the two things that matter for durable delivery: tasks start in `submitted`, and terminal states are final.

### 6.1 Who drives the state

- The **responder node** creates the task, in `submitted`, when it accepts a `SendMessage` or
  `SendStreamingMessage` that does not name an existing task (§6.4).
- The **responder agent** drives every later transition, except those listed below.
- The **responder node** itself may move a task to `canceled` (for `CancelTask`), to `rejected` (a policy refusal
  after creation, from `submitted` only), or to `failed` (the agent crashed, timed out or is gone).
- The **requester** never sets a state directly. It acts with `SendMessage` (continue), `CancelTask` and the
  read operations.

### 6.2 Transition table

`∅` is "no task yet". Rows are the current state, columns the next state. ✓ is legal, ✗ illegal.

| from \ to | submitted | working | input-required | auth-required | completed | failed | canceled | rejected |
|---|---|---|---|---|---|---|---|---|
| **∅** | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| **submitted** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **working** | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| **input-required** | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| **auth-required** | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| **completed** | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| **failed** | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| **canceled** | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| **rejected** | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |

In words: a task is born `submitted`. `rejected` is reachable only from `submitted` (the agent declined before
starting). Nothing returns to `submitted`. An active state may repeat itself, which is a progress update carrying a
new status message. Terminal states are final.

- [PROF-015] A node MUST record the first state of every task it creates as `submitted`, and MUST emit only the
  transitions marked ✓ in the table above, for tasks it hosts and for proxy tasks it shows its own agents.
- [PROF-016] A node that receives, from an overlay peer, a status for a task that is not a legal transition from
  the last state it has recorded for that task MUST NOT apply it. It MUST record an audit anomaly, treat the
  event as `InvalidAgentResponseError` (−32006), end that stream (if any), and reconcile with `GetTask`. A task
  it has recorded as terminal MUST stay terminal in its own records whatever later events say.
- [PROF-017] A bridge agent whose upstream (a stock A2A server or an MCP server) reports an illegal transition
  MUST NOT forward it as such. It MUST map it to the nearest legal transition defined in §12.4 or, if none exists,
  move its own task to `failed` with reason `InvalidAgentResponse` in the status message, and record an audit
  anomaly.

### 6.3 Operations by state

What each requester operation does, by the current state of the task it names. "A2A" in a cell means the
behaviour A2A 1.0 already prescribes.

| Operation \ state | submitted | working | input-required | auth-required | terminal |
|---|---|---|---|---|---|
| `SendMessage` / `SendStreamingMessage` with this `taskId` | accepted, appended to history; state unchanged unless the agent changes it | same as submitted | accepted; the agent normally moves to `working` | accepted; the agent normally moves to `working` | `UnsupportedOperationError` (A2A), reason `TASK_TERMINAL` |
| `CancelTask` | MUST move to `canceled` | `canceled`, or `TaskNotCancelableError` if the agent cannot stop | as working | as working | `TaskNotCancelableError` (A2A) |
| `SubscribeToTask` without cursor | snapshot, then live events (A2A) | same | same | same | `UnsupportedOperationError` (A2A), reason `TASK_TERMINAL` |
| `SubscribeToTask` with cursor (§7.2) | replay from cursor, then live | same | same | same | replay from cursor up to the terminal event, then end |
| `GetTask` | snapshot | snapshot | snapshot | snapshot | snapshot |

- [PROF-018] A node MUST handle requester operations as the table above specifies. In particular, `CancelTask`
  on a `submitted` task MUST succeed and move it to `canceled`, because the agent has not started.
- [PROF-019] An `auth-required` state is not an authorisation. A node MUST check authorisation for the message
  that resumes an `auth-required` task exactly as for any other message (§9.2). Credentials the agent asked for
  MUST NOT travel in message text (§9.4).

### 6.4 Creating and continuing tasks

A message without `taskId` creates a task (or yields a single `Message`, with no task). A message with `taskId`
continues that task. A message with `taskId` naming a task the caller cannot see gets `TaskNotFoundError`, the
same answer as for a task that does not exist (PROF-047).

### 6.5 Event log, sequence numbers, durability and idempotency

- [PROF-020] A responder node MUST keep, for every task it hosts, a durable **event log**: the creating `Task`
  snapshot and every later `TaskStatusUpdateEvent`, `TaskArtifactUpdateEvent` and agent `Message` for the task,
  in the order they were produced. Each entry has a per-task sequence number `seq`. The creating snapshot has
  `seq` 0, and each later entry has the previous entry's `seq` plus one. The node MUST store each entry as the
  signed envelope it sends, so that a replay is byte-identical.
- [PROF-021] The `seq` of an event MUST travel in the signed envelope header (`ctx.seq`, `ext/envelope.md`), never
  only in an unsigned frame. A `Task` snapshot sent outside the log (the first frame of a cursorless subscribe,
  a `GetTask` result) carries the `seq` of the last log entry it reflects.
- [PROF-022] A responder node MUST make the new task (or the continuation) and its first log entry durable before
  it sends any response or acknowledgement for the message that caused them. A crash after that point MUST NOT
  lose the task, and a crash before it MUST NOT leave a task the requester was told about.
- [PROF-023] A node MUST de-duplicate received envelopes on `(from, id)` for as long as `ext/envelope.md`
  requires (until at least `exp + SKEW`). The dedupe entry MUST be written in the same atomic transaction as the
  task or event it caused. A duplicate inside that horizon MUST NOT be processed again and MUST be answered with
  the stored original response envelope. For a duplicate streaming request, the "original response" is the
  task's event log: the node replays it from `seq` 0 (byte-identical envelopes) and continues live, as a cursor
  subscribe from 0 would.

A2A makes `messageId` deduplication optional (A2A §3.3.1). In this profile it is mandatory, because at-least-once
delivery with idempotent receivers is how offline peers work (§8).

## 7. Streaming

### 7.1 What ends a stream

- [PROF-024] A requester MUST treat a task as finished only when it has received an event carrying a terminal
  state for that task. The end of a stream without such an event MUST be treated as a disconnection, and
  followed by a cursor subscribe (§7.2) or `GetTask`, never as completion.
- [PROF-025] A requester MUST NOT assume that a stream stays open, or that it closes, when the task enters an
  interrupted state. A responder node SHOULD keep the stream open through interrupted states (the A2A 1.1
  direction). A2A 1.0 contradicts itself on this point (research §2).
- [PROF-026] Closing or abandoning a stream MUST NOT cancel the task. Cancellation is only `CancelTask`.

### 7.2 Resuming from a cursor

A2A 1.0 has no stream resumption, and no SDK replays missed events (research §3.4). The profile adds a cursor.
On `webway-quic/v0` the cursor is the service parameter `webway-from-seq` (binding §7). Over a bridge it is
`metadata["https://github.com/BVMrs/argent-webway/spec/profile/v0"].fromSeq` where the request type has a
`metadata` field.

- [PROF-027] On `SubscribeToTask` with cursor `k`, a responder node MUST send, in order, every log entry with
  `seq ≥ k`, and then live events. It MUST NOT send a snapshot first. If the log no longer holds entry `k`
  (retention), it MUST instead send the current `Task` snapshot first, with the `seq` of the last entry it
  reflects, and then live events. If the task is terminal, it MUST end the stream after the terminal event. A
  cursor greater than the last `seq` plus one MUST be rejected with `InvalidParamsError` (−32602).
- [PROF-028] A requester MUST de-duplicate received events by `seq` per task and MUST ignore an event whose `seq`
  it has already applied. A `Task` snapshot replaces its view of the task and resets its cursor to the
  snapshot's `seq`. A gap (an event whose `seq` is more than one above the last applied) MUST NOT be applied. The
  requester MUST end that stream and resubscribe from the first missing `seq`.

Retention: a responder node SHOULD keep the full event log of a task until at least `MAX_TTL` after the task
became terminal.

### 7.3 Ordering

Events of one task are totally ordered by `seq`. There is no ordering across tasks. The same events, with the same
`seq`, are sent on every stream of a task.

### 7.4 Slow subscribers

- [PROF-029] A responder node MUST bound the buffer of each subscriber, at no fewer than `SUBSCRIBER_MIN_BUFFER`
  events. When it drops a subscriber because the buffer is full, it MUST signal that explicitly (on
  `webway-quic/v0`, the `SubscriberEvicted` stream error of the binding), never as a clean end of stream. A slow
  subscriber MUST NOT stall the task or other subscribers.

An evicted requester resubscribes with its cursor (§7.2) and loses nothing.

## 8. Offline peers

"Peer offline" is a normal state, not an error. This section gives the behaviour a requester's agent sees. The
store-and-forward machinery (outbox, mailbox host, custody) is in `ext/mailbox.md` (T7). The frames that carry it
are in binding §9.

### 8.1 Delivery paths

A request reaches its responder node by one of two paths:

- **Live**: on a request stream of an open `webway-quic/v0` connection (binding §8). The response comes back on
  the same stream.
- **Deferred**: as a `DELIVER` frame (binding §9), directly or through the responder's mailbox host. The response,
  and the task's later events, come back the same way to the requester node or to the requester's mailbox host.

Only `SendMessage` and `CancelTask` may take the deferred path. A deferred `SendMessage` is processed as if
`return_immediately` were `true`, because nobody is waiting on it.

### 8.2 Proxy tasks

A requester node shows its agent every remote task through a **proxy task**: a task record in the node, with its
own `taskId` that never changes, which mirrors the remote task once the remote side has acknowledged it.

- [PROF-030] A requester node MUST answer a `SendMessage` or `SendStreamingMessage` from its own agent to a
  remote agent without blocking on reachability. If the request cannot be delivered live at once, the node MUST
  return (or stream first) a proxy task in `submitted` whose metadata, under the profile URI, has
  `delivery: "queued"`. The proxy task's `taskId` MUST stay the same for its whole life, including after the
  remote task's id becomes known.
- [PROF-031] A requester node MUST keep a proxy task's `delivery` state as the machine in §8.3 specifies, MUST
  expose it in the proxy task's metadata under the profile URI, and MUST mirror the remote task's states and
  events into the proxy task once the delivery is `acknowledged`. Mirrored events MUST obey §6.2.
- [PROF-032] Requests and events for a task MUST NOT be re-ordered by the outbox: a node MUST hand envelopes for
  the same task to the network in the order its agent produced them.

### 8.3 Delivery state machine (requester side)

| State | Meaning | Proxy task state |
|---|---|---|
| `queued` | In the requester node's outbox, never transmitted. Nobody else has it. | `submitted` |
| `sent` | Transmitted at least once, on a live stream or into a mailbox host's custody (binding §9). The responder may or may not have it. | `submitted` |
| `acknowledged` | The responder's response arrived. The remote task id is known (or the answer was a `Message`). | mirrors the remote task |
| `refused` | The responder answered with an error that is not retryable. | `failed`, the error in the status message |
| `expired` | No response before `exp + SKEW` of the request envelope. | `failed`, reason `DELIVERY_EXPIRED` |
| `withdrawn` | Canceled by the requester's agent while still `queued`. | `canceled` |

Events and transitions:

| from \ event | transmit | custody | response | retryable error | final error | `now > exp + SKEW` | local cancel |
|---|---|---|---|---|---|---|---|
| `queued` | `sent` | `sent` | `acknowledged` | `sent` | `refused` | `expired` | `withdrawn` |
| `sent` | `sent` | `sent` | `acknowledged` | `sent` (retry with backoff) | `refused` | `expired` | `sent` (cancel held, PROF-035) |
| `acknowledged` | unchanged | unchanged | unchanged (duplicate) | unchanged | unchanged | unchanged | unchanged (cancel forwarded, PROF-035) |
| `refused` | unchanged | unchanged | unchanged | unchanged | unchanged | unchanged | unchanged |
| `expired` | unchanged | unchanged | unchanged (late response, PROF-034) | unchanged | unchanged | unchanged | unchanged |
| `withdrawn` | illegal | illegal | illegal | illegal | illegal | unchanged | unchanged |

`transmit` is the node starting a live attempt. An error or response always follows a transmission, so in
`queued` those columns describe a transmission the node has not yet recorded. `acknowledged`, `refused`, `expired`
and `withdrawn` are final. Signals that arrive after a final state come from
retries that took another path (a mailbox copy and a live copy of the same envelope), so they are ignored. A
`withdrawn` request never left the node, so a network signal for it is illegal and is an audit anomaly.

- [PROF-033] A requester node MUST implement the delivery state machine above. It MUST stop retrying a request
  when its envelope's `exp` has passed, and MUST move it to `expired` once `now > exp + SKEW` without a response.
  Retries MUST resend the byte-identical envelope (same `id`, same signature), so the responder's dedupe applies.
- [PROF-034] `expired` means "the responder did not acknowledge in time, and will not accept the request any more".
  It does not mean "not processed": the responder may have accepted it just before `exp + SKEW`. A node MUST
  report `expired` to its agent with that meaning (error `DeliveryExpired`, whose definition says so), MUST
  record any response that arrives after `expired` in its audit log, and MUST attach the remote task reference to
  the proxy task's metadata under the profile URI as `lateResponse`, without changing the proxy task's state.
- [PROF-035] A `CancelTask` from the agent for a proxy task in `queued` MUST remove the request from the outbox
  and move the delivery to `withdrawn`. In `sent`, the node cannot recall the request, so it MUST hold the
  cancel and send `CancelTask` for the remote task as soon as the delivery is `acknowledged`. In `acknowledged`
  the node forwards `CancelTask` to the remote task (live or deferred).

### 8.4 Event delivery to an offline requester

Inside the overlay, A2A push webhooks are replaced by deferred delivery. A responder node sends the events of a
task created by a deferred `SendMessage` as `DELIVER` frames (binding §9) to the requester node, or to the
requester's mailbox host when the requester node is unreachable.

- [PROF-036] For a task created through the deferred path, a responder node MUST deliver every event-log entry to
  the requester agent through the deferred path, in `seq` order, until the terminal event. The target MUST be the
  requester agent named in the creating envelope's `from`, and no one else.
- [PROF-037] A push notification config received on `webway-quic/v0`, if the node supports push at all, MUST name
  as its target only the requesting agent's own agent address. Any other URL (in particular an `https` webhook)
  MUST be refused with `InvalidParamsError`, so that a node can never be used to post to third parties (SSRF).

### 8.5 Operations against an offline peer

| Operation from the local agent | Peer unreachable: behaviour |
|---|---|
| `SendMessage` (either form), `SendStreamingMessage` | Proxy task in `submitted`, `delivery: queued` (PROF-030). A streaming call streams the proxy task and stays open. Remote events are streamed when they arrive. |
| `GetTask` on a proxy task | The last known snapshot, with metadata `stale: true` and `asOf` (RFC 3339) under the profile URI |
| `CancelTask` on a proxy task | §8.3, PROF-035 |
| `SubscribeToTask` on a proxy task | Local stream of the proxy task. Mirrored events flow when the peer comes back. |
| `ListTasks` | Local proxy tasks only |
| Blob fetch whose only provider is offline | `PeerUnreachable`, retryable (`ext/blob.md`) |
| Fetching a card that is not cached | `PeerUnreachable`, retryable |

- [PROF-038] A node MUST answer the operations in the table above as the table specifies, and MUST NOT return an
  error for "peer offline" for the operations that the table queues.

On the responder side: a responder node that comes online drains its mailbox host, applies dedupe (PROF-023),
rejects envelopes past `exp + SKEW` with `EnvelopeExpired`, and processes the rest. A responder node whose agent
is down but whose node is up accepts and persists tasks in `submitted`. The agent picks them up when it returns.

## 9. Security rules

This profile adds no security mechanism of its own. Those are in `ext/envelope.md` (signatures, freshness,
replay), `ext/capability.md` (identity, capabilities, delegation), `ext/provenance.md` (taint and trust) and
`ext/audit.md`. It fixes how a node applies them to A2A operations. The threat model is in
[`docs/threat-model.md`](../docs/threat-model.md) (issue #6).

### 9.1 Authentication

- [PROF-039] Every A2A request, response and event that leaves a node MUST be inside a signed envelope
  (`ext/envelope.md`), whatever the owner of the other side, except on an HTTP edge interface towards a stock
  peer. A node MUST reject an unsigned or unverifiable envelope from any overlay peer, including one of its own
  owner's nodes.
- [PROF-040] A node MUST check that the envelope's `from` agent is certified by an owner the node trusts, through
  the binding statement of `ext/capability.md`, before acting on the content. Otherwise it MUST answer
  `IdentityUntrusted`.
- [PROF-041] A node MUST check that the envelope's `to` names an agent it hosts. Otherwise it MUST answer
  `RecipientUnknown` and MUST NOT forward the envelope (a node is not an open relay).

### 9.2 Authorisation per capability

- [PROF-042] A node MUST authorise every A2A operation against a capability token (`ext/capability.md`), deny by
  default. Each operation needs at least the capability below, scoped to the target agent:

  | Operation | Capability |
  |---|---|
  | `SendMessage`, `SendStreamingMessage` creating a task | `skill:<id>` for a skill of the agent, or `agent:<wwa>#message` if the agent declares no skills |
  | `SendMessage` continuing a task, `GetTask`, `SubscribeToTask` | `task:<id>#read` and, for messages, `task:<id>#message`. The node grants these implicitly to the agent that created the task, with the same holder. |
  | `CancelTask` | `task:<id>#cancel`, implicitly granted to the creator |
  | `ListTasks` | none beyond authentication. Results are only tasks the caller holds `task:<id>#read` for. |
  | Push config operations | `task:<id>#read` |
  | `GetExtendedAgentCard` | `agent:<wwa>#card-extended` |

- [PROF-043] A node MUST NOT rely on a stock peer, or on the A2A SDK it uses, to enforce authorisation, the card's
  `securitySchemes`, or required extensions.

### 9.3 Content is data

- [PROF-044] Everything a node receives from a peer (messages, Parts, artifacts, status messages, card text, MCP
  tool descriptions and results, elicitation prompts) MUST be treated as untrusted data. A node MUST give it to its
  agents only inside a delimited, labelled container that carries the provenance and computed trust of
  `ext/provenance.md`, and MUST NOT place it in system or user instructions.
- [PROF-045] Every Part a node sends in an envelope MUST carry the taint of `ext/provenance.md`, and content
  entering through an HTTP edge or an MCP bridge MUST have `taint.unverified = true` (§12).

### 9.4 Scoping, existence and credentials

- [PROF-046] A node MUST scope every task result (`GetTask`, `ListTasks`, `SubscribeToTask`, push configs) to the
  authenticated principal. Anonymous callers MUST NOT share a scope. `tenant` is routing and MUST NOT be used as
  an authorisation boundary.
- [PROF-047] For an operation that names a task the caller is not authorised to see, a node MUST answer
  `TaskNotFoundError`, exactly as for a task that does not exist, so that the error does not reveal the task's
  existence. `CapabilityDenied` is used only where the caller already knows the resource exists (for example a
  skill listed on the card).
- [PROF-048] Capability tokens and other credentials MUST travel only in the envelope's `cap` field (or, at the
  HTTP edge, in the binding's own authentication mechanism). A node MUST NOT put them in message text, Parts or
  `metadata`, and MUST NOT forward a credential it received to a third party.

### 9.5 Audit

- [PROF-049] A node MUST write an audit record (`ext/audit.md`) for every authentication decision, every
  authorisation decision with its outcome and the capability chain used, every task state transition it records,
  every envelope it sends or receives (signed header always, body by policy), every bridge crossing, and every
  anomaly this profile names (PROF-016, PROF-017, PROF-034).

### 9.6 Extensions are not controls

- [PROF-050] A node MUST enforce its own policy regardless of which extensions a peer declares, requires or
  activates. An extension declared `required: true` by a peer is an interoperability statement, not a security
  control.

## 10. Error model

### 10.1 Structure

Errors are JSON-RPC 2.0 error objects, as in the A2A JSON-RPC binding (A2A §9.5), on every binding:
`{"code": <int>, "message": <string>, "data": [<detail>, …]}`.

- [PROF-051] Every error a node returns MUST include in `data` one `google.rpc.ErrorInfo` detail
  (`"@type": "type.googleapis.com/google.rpc.ErrorInfo"`) with:
  - `reason`: the error's `REASON` from the tables below;
  - `domain`: `a2a-protocol.org` for A2A errors, `github.com/BVMrs/argent-webway` for profile errors;
  - `metadata.retryable`: `"true"` or `"false"`, as the tables say;
  - `metadata.retryAfterMs`: a decimal string, when the responder knows how long to wait. Optional.
- [PROF-052] A client MUST classify errors by JSON-RPC `code` and `ErrorInfo.reason`, never by HTTP or gRPC
  status, and MUST also recognise the non-standard codes −31401 (unauthenticated) and −31403 (unauthorised) that
  one stock SDK emits (research §3.8), mapping them to `IdentityUntrusted` and `CapabilityDenied` for retry
  decisions.

Retry rule: a client MAY retry an error marked retryable, with backoff and jitter, honouring `retryAfterMs`. It
MUST NOT retry a non-retryable error with the same envelope. A retry always resends the same envelope (PROF-033).

### 10.2 A2A errors, reused

Codes and meanings are those of A2A §5.4. The profile only adds `retryable` and its own refinement reasons.

| Name | Code | `REASON` | Retryable | Profile use |
|---|---|---|---|---|
| `TaskNotFoundError` | −32001 | `TASK_NOT_FOUND` | no | Also for tasks the caller may not see (PROF-047) |
| `TaskNotCancelableError` | −32002 | `TASK_NOT_CANCELABLE` | no | §6.3 |
| `PushNotificationNotSupportedError` | −32003 | `PUSH_NOTIFICATION_NOT_SUPPORTED` | no | |
| `UnsupportedOperationError` | −32004 | `UNSUPPORTED_OPERATION`, or `TASK_TERMINAL` for an operation on a terminal task | no | §6.3 |
| `ContentTypeNotSupportedError` | −32005 | `CONTENT_TYPE_NOT_SUPPORTED` | no | |
| `InvalidAgentResponseError` | −32006 | `INVALID_AGENT_RESPONSE` | no | PROF-016 |
| `ExtendedAgentCardNotConfiguredError` | −32007 | `EXTENDED_AGENT_CARD_NOT_CONFIGURED` | no | |
| `ExtensionSupportRequiredError` | −32008 | `EXTENSION_SUPPORT_REQUIRED` | no | §11.3 |
| `VersionNotSupportedError` | −32009 | `VERSION_NOT_SUPPORTED` | no | §11.1 |
| `JSONParseError` | −32700 | `PARSE_ERROR` | no | Only at the HTTP edge. On the overlay a parse failure is `EnvelopeInvalid`. |
| `InvalidRequestError` | −32600 | `INVALID_REQUEST` | no | |
| `MethodNotFoundError` | −32601 | `METHOD_NOT_FOUND` | no | |
| `InvalidParamsError` | −32602 | `INVALID_PARAMS` | no | PROF-027, PROF-037 |
| `InternalError` | −32603 | `INTERNAL` | yes | |

### 10.3 Profile errors

A2A reserves −32001 to −32099 for itself (A2A §9.5) and JSON-RPC reserves −32768 to −32000. Profile errors use
**−30001 to −30099**. Extensions register their errors here, in this table, through a change proposal.

| Name | Code | `REASON` | Retryable | Meaning | HTTP edge | gRPC edge |
|---|---|---|---|---|---|---|
| `EnvelopeInvalid` | −30001 | `ENVELOPE_INVALID` | no | Malformed envelope: not I-JSON, wrong signer form, `body_hash` mismatch, missing taint | 400 | `INVALID_ARGUMENT` |
| `SignatureInvalid` | −30002 | `SIGNATURE_INVALID` | no | The signature does not verify against `from` | 401 | `UNAUTHENTICATED` |
| `EnvelopeExpired` | −30003 | `ENVELOPE_EXPIRED` | no | `now > exp + SKEW`, or `ts > now + SKEW`, or `exp − ts > MAX_TTL` | 400 | `FAILED_PRECONDITION` |
| `RecipientUnknown` | −30004 | `RECIPIENT_UNKNOWN` | no | `to` is not an agent hosted by this node (PROF-041) | 404 | `NOT_FOUND` |
| `IdentityUntrusted` | −30005 | `IDENTITY_UNTRUSTED` | no | `from` is not certified by a trusted owner (PROF-040) | 401 | `UNAUTHENTICATED` |
| `CapabilityMissing` | −30010 | `CAPABILITY_MISSING` | no | No capability token where one is needed | 401 | `UNAUTHENTICATED` |
| `CapabilityDenied` | −30011 | `CAPABILITY_DENIED` | no | The token does not grant the operation, or policy denies it | 403 | `PERMISSION_DENIED` |
| `CapabilityRevoked` | −30012 | `CAPABILITY_REVOKED` | no | A block of the token is revoked | 403 | `PERMISSION_DENIED` |
| `PeerUnreachable` | −30020 | `PEER_UNREACHABLE` | yes | No path to the peer now, for an operation that cannot be queued (§8.5) | 503 | `UNAVAILABLE` |
| `MailboxFull` | −30021 | `MAILBOX_FULL` | yes | The mailbox host refuses custody for now | 503 | `RESOURCE_EXHAUSTED` |
| `DeliveryExpired` | −30022 | `DELIVERY_EXPIRED` | no | No acknowledgement before `exp + SKEW`. The responder will not accept the request any more, but may have processed it before (PROF-034). | 504 | `DEADLINE_EXCEEDED` |
| `RateLimited` | −30023 | `RATE_LIMITED` | yes | Local policy rate limit or quota | 429 | `RESOURCE_EXHAUSTED` |
| `BlobNotFound` | −30030 | `BLOB_NOT_FOUND` | no | No provider has the blob, or the caller may not read it (`ext/blob.md`) | 404 | `NOT_FOUND` |
| `ProvenancePolicyViolation` | −30040 | `PROVENANCE_POLICY_VIOLATION` | no | Content of this trust may not trigger this operation (`ext/provenance.md`) | 403 | `PERMISSION_DENIED` |

- [PROF-053] A node MUST use exactly the codes, reasons and retryability of §10.2 and §10.3, and an HTTP edge
  MUST map profile errors to the HTTP and gRPC statuses listed. A2A errors keep the statuses of A2A §5.4.

Duplicates are not errors (PROF-023). There is no `Replayed` error: a replay outside the dedupe horizon is
`EnvelopeExpired`.

## 11. Versioning

Four things are versioned independently. Each fails cleanly when the peer lacks it.

| What | Identifier | Negotiated where | On mismatch |
|---|---|---|---|
| A2A | `Major.Minor` (`1.0`) | `A2A-Version` service parameter on every request; interface `protocolVersion` in the card | `VersionNotSupportedError` |
| Binding | major in the binding URI and ALPN (`webway/0`), minor in HELLO | QUIC handshake, then HELLO (binding §12) | Handshake failure, no downgrade |
| Profile | `MAJOR.MINOR` (`0.1`) | Card (`params.version`), HELLO | HELLO: connection closed with `VersionMismatch` |
| Extensions | major in the URI (`…/ext/envelope/v0`) | Card list; activation per request (§11.3) | `ExtensionSupportRequiredError` |

### 11.1 A2A version

- [PROF-054] A responder MUST answer `VersionNotSupportedError` to a request whose `A2A-Version` it does not
  support, and MUST interpret an absent or empty `A2A-Version` as `0.3`, as A2A requires. This profile supports
  only `1.x`, so an absent version is refused.

### 11.2 Profile version

A minor profile bump is additive: new optional behaviour, new error codes, new metadata keys. A major bump is
breaking and gets a new profile URI (`…/profile/v1`) and a new binding major. Nodes support the current and the
previous profile major for at least 12 months after the new major is published.

- [PROF-055] A node MUST accept any profile minor version of a major it supports, MUST ignore metadata keys and
  HELLO fields it does not know, and MUST use only the behaviour of the lower of the two minors when talking to a
  peer.

### 11.3 Extension activation

- [PROF-056] On `webway-quic/v0`, the profile, `envelope/v0` and `capability/v0` are always active and MUST NOT be
  listed in `a2a-extensions` to make them so. Any other extension is active for a request only if the requester
  lists it in `a2a-extensions` and the responder confirms it in the response's signed `a2a-extensions` service
  parameter (binding §7). A requester MUST NOT infer activation from anything else. At the HTTP edge, where stock
  peers rarely echo activation (research §3.3), a node MUST confirm activation in the response `metadata` under
  the extension's URI.
- [PROF-057] A breaking change to an extension, the profile or the binding MUST get a new URI. A node MUST NOT
  fall back silently to an older major.

## 12. Bridges

### 12.1 How bridges attach

A bridge is a component of a node. It attaches to the overlay **as one or more bridge agents** hosted by that
node, each with its own `wwa` key certified by the node's owner. From the overlay, a bridged stock A2A server, or
a bridged MCP server, is an ordinary profile agent: it has a signed profile card, it takes envelopes and
capabilities, it keeps an event log and supports cursors. The bridge does the translation on the other side and
holds the durable task records that the upstream cannot hold (R-E5).

```
 overlay (signed envelopes)                 node with bridges                         outside
 ──────────────────────────┐   ┌──────────────────────────────────────────┐   ┌──────────────────────
  other nodes ─ webway-quic ┼──►│ bridge agent wwa:Kb  ── A2A client ──────┼──►│ stock A2A server
                            │   │ bridge agent wwa:Km  ── MCP client ──────┼──►│ MCP server (tools)
                            │   │ HTTP edge (A2A server) ◄─────────────────┼───│ stock A2A client
                            │   │ MCP facade (MCP server, loopback) ◄──────┼───│ local agent
 ──────────────────────────┘   └──────────────────────────────────────────┘   └──────────────────────
```

- [PROF-058] A bridge agent's card MUST be a profile card (§5) signed by the node's owner, and MUST declare in the
  profile extension's `params` the bridge kind (`"bridge": "a2a-http"` or `"mcp"`) and the upstream endpoint. The
  original upstream card or tool list, if any, MUST be kept byte for byte and made available (as a blob or through
  `GetExtendedAgentCard`), and skill text copied from it is untrusted data (PROF-014).
- [PROF-059] Content a bridge receives from outside the overlay MUST enter with `taint.unverified = true` and the
  bridge's owner in `taint.owners`, and keeps that taint for its whole life (`ext/provenance.md`). The audit record
  of the crossing MUST name the outside principal (§12.2) or upstream (§12.3, §12.5).
- [PROF-060] A bridge MUST NOT forward credentials across the bridge in either direction: not a webway capability
  token to an upstream, not an upstream or HTTP-edge credential into the overlay. Each side uses its own
  credentials, and the on-behalf-of principal is recorded in the audit log.

### 12.2 A2A HTTP edge, inbound (stock A2A client → overlay)

The node offers the A2A JSON-RPC, HTTP+JSON and (later) gRPC bindings for agents it hosts, listed in their cards
next to the `webway-quic/v0` interface.

- [PROF-061] The HTTP edge MUST authenticate callers with the schemes in the card (OAuth 2.0/OIDC, mTLS, or HTTP
  Message Signatures by a webway key) and MUST map each authenticated caller to an **edge principal**
  (issuer plus subject, or certificate key) that has its own task scope (PROF-046). It MUST map the caller's
  credential to capabilities through local policy, deny by default. It MUST NOT accept anonymous callers unless
  policy grants an anonymous capability explicitly, and then each anonymous request gets its own scope.
- [PROF-062] Towards stock clients the edge MUST obey §4: no envelopes, no extra fields, argent-webway data only in
  `metadata` under extension URIs. It MAY attach the signed envelope of a response in `metadata` under the
  `envelope/v0` URI for clients that can verify it.
- [PROF-063] When content from the HTTP edge is forwarded into the overlay (to another node), the forwarding agent
  signs the envelope with its own key, and the content carries `taint.unverified = true` (PROF-059). The receiving
  node computes trust `unverified-origin` for it, never `foreign` or higher.
- [PROF-064] If the edge supports push notifications, it MUST validate webhook URLs when the config is created and
  again at connect time (resolving once and connecting to the validated address), MUST require `https` outside an
  explicit local test mode, MUST NOT follow redirects to another host, and MUST send the config `token` in both
  `A2A-Notification-Token` and `X-A2A-Notification-Token`. As a push receiver it MUST accept either header, treat
  every push as a hint, de-duplicate, and reconcile with `GetTask`.

### 12.3 A2A HTTP edge, outbound (overlay → stock A2A server)

A bridge agent `wwa:Kb` represents one stock A2A agent. Overlay agents send it envelopes as to any agent.

- [PROF-065] The bridge MUST call the upstream with its own credential for that upstream, with `A2A-Version: 1.0`
  (PROF-002), choosing the interface by binding and version (PROF-003), and MUST obey §4 towards it. It MUST keep
  its own durable task records, event log and `seq` for every upstream task (§6.5), so that cursors, dedupe and
  deferred delivery work even though the upstream supports none of them. It MUST reconcile with `GetTask` after
  any upstream stream ends without a terminal state (PROF-024).
- [PROF-066] When an upstream task has a state the bridge cannot represent as a legal transition (PROF-017), or
  the upstream returns an unknown enum value (PROF-007), the bridge MUST NOT invent a state. It applies PROF-017.

### 12.4 MCP facade (local agent → its own node)

The node is an MCP server (MCP revision **2026-07-28**) for its own agents. This is the low-friction path: an LLM
agent sees "delegate to remote agent X" as an MCP tool.

- [PROF-067] The MCP facade MUST listen only on stdio or on a loopback address. On HTTP it MUST validate `Origin`,
  require the protocol version metadata on every request, and authenticate the client with a per-agent secret the
  node provisions. Each facade client is bound to exactly one local agent key, which the node signs for.
- [PROF-068] The facade MUST return remote content only as tool *results*, as the labelled container of PROF-044,
  with the provenance under `_meta["io.github.bvmrs.argent-webway/provenance"]`. Remote content MUST NOT appear in
  tool names, tool descriptions, prompts, resource descriptions or server instructions.
- [PROF-069] Long-running remote work MUST be usable without the MCP tasks extension: a tool call waits up to a
  caller-given timeout and then returns the proxy task snapshot, and a separate tool waits on or reads the proxy
  task. The facade uses the MCP tasks extension only when the client negotiates it for that request.

Tools the facade offers (names normalised to `[A-Za-z0-9_.-]{1,128}`): `webway.agents.list`,
`webway.message.send`, `webway.task.get`, `webway.task.wait`, `webway.task.cancel`, `webway.artifact.fetch`. Their
schemas are specified with the MCP facade (roadmap T12).

### 12.5 MCP bridges to and from other parties

**Remote skills as MCP tools** (an external MCP client calls overlay agents through this node):

- [PROF-070] An MCP server that exposes overlay skills to MCP clients other than the node's own agents MUST publish
  RFC 9728 protected resource metadata, MUST validate the audience of every access token, MUST require PKCE S256
  for its authorisation flow, MUST mark per-principal `tools/list` results `cacheScope: "private"`, and MUST name
  tools `<agent petname>.<skill id>` normalised to `[A-Za-z0-9_.-]{1,128}`.

**MCP tools as skills** (a bridge agent `wwa:Km` exposes an MCP server's tools to the overlay):

- [PROF-071] The bridge MUST call the MCP server with its own audience-bound token for that server (`resource` =
  the server's canonical URI), MUST NOT forward any overlay credential, and MUST record the on-behalf-of overlay
  principal in the audit log. Tool descriptions, annotations and results from the MCP server are untrusted data
  (PROF-044) and MUST NOT relax any policy. Any `requestState` the bridge mints MUST be protected with an HMAC or
  AEAD bound to the principal, a TTL and a digest of the request.
- [PROF-072] The bridge MUST map MCP outcomes to A2A task states as follows, and in no other way:

  | MCP outcome | A2A state of the bridge task |
  |---|---|
  | request accepted (always) | `submitted` (synthesised: MCP has none) |
  | call started, or MCP task `working` | `working` |
  | MRTR `input_required`, or MCP task `input_required` | `input-required`. The elicitation is sent as a data Part; free-text answers are wrapped back as the requested form. |
  | HTTP 401/403 step-up from the MCP server | `auth-required`. The bridge, not the requester, completes the step-up with its own credential. |
  | `CallToolResult` with `isError` absent or `false`, or task `completed` with such a result | `completed`, the content as an artifact |
  | `CallToolResult` with `isError: true` | `failed`, the tool's content in the status message |
  | JSON-RPC error, or task `failed` | `failed` |
  | task `cancelled` | `canceled` |
  | JSON-RPC error before any work, for authorisation or invalid arguments | `rejected` |

The bridge targets MCP 2026-07-28 and MUST NOT rely on MCP sessions. MCP data the bridge adds travels in `_meta`
under `io.github.bvmrs.argent-webway/`, and signed content crossing MCP is carried as opaque bytes.

## 13. Disposition of the research candidates

The interop research (research §5) asks the specs to adopt, refine or reject each candidate requirement. For this
document and the binding:

| Candidate | Disposition | Where |
|---|---|---|
| R-A1 target 1.0, 1.1 optional | Adopted | PROF-001 |
| R-A2 always send `A2A-Version` | Adopted | PROF-002 |
| R-A3 select by binding and version | Adopted, plus prefer `webway-quic` | PROF-003 |
| R-B1 no new top-level fields | Adopted | PROF-004 |
| R-B2 no new enums or kinds | Adopted | PROF-005, §5 |
| R-B3 big integers as strings | Adopted | PROF-006 |
| R-B4 unknown fields, unknown enums | Refined: generic JSON kept for signatures, unknown enums surfaced | PROF-007 |
| R-C1 identity not from card signatures | Adopted | PROF-013 |
| R-C2 how we sign cards | Refined: `EdDSA` only for signing | PROF-010 |
| R-C3 how we verify cards | Adopted (`EdDSA`, `ES256` allowed) | PROF-011 |
| R-C4 cards byte for byte | Adopted | PROF-012 |
| R-C5 map transport identity explicitly | Adopted: the node key is the QUIC identity, the agent key signs the envelope | binding §5, PROF-040 |
| R-D1 extensions with versioned URIs | Adopted | §2, PROF-057 |
| R-D2 in-band activation | Adopted: signed `a2a-extensions` in the response on the overlay, `metadata` at the edge | PROF-056 |
| R-D3 required is not a control | Adopted | PROF-009, PROF-050 |
| R-D4 message integrity as extension | Adopted: `envelope/v0` | PROF-039 (details T2) |
| R-E1 end of stream is not completion | Adopted | PROF-024 |
| R-E2 tolerate snapshot, duplicates, gaps | Refined: cursor, `seq` dedupe, gap → resubscribe | PROF-027, PROF-028 |
| R-E3 interrupted states and stream close | Adopted | PROF-025 |
| R-E4 explicit cancellation | Adopted | PROF-026 |
| R-E5 own resume and offline semantics | Adopted | §6.5, §7.2, §8 |
| R-E6 bounded buffers, explicit eviction | Adopted | PROF-029 |
| R-F1 push is a hint | Adopted at the edge | PROF-064 |
| R-F2 both token headers | Adopted | PROF-064 |
| R-F3 signed push | Refined: inside the overlay push is replaced by signed deferred delivery. A signed webhook payload at the edge is deferred to `ext/mailbox.md`. | §8.4 |
| R-F4 SSRF-safe webhooks | Adopted | PROF-037, PROF-064 |
| R-F5 delivery without inbound reachability | Adopted | §8.4, binding §9 |
| R-G1 authorise per capability | Adopted | PROF-042, PROF-043 |
| R-G2 no shared anonymous scope | Adopted | PROF-046, PROF-061 |
| R-G3 no existence leak, error codes | Adopted | PROF-047, PROF-052, §10.3 |
| R-G4 audit everything | Adopted (format in T9) | PROF-049 |
| R-H1 peer content is data | Adopted | PROF-014, PROF-044 |
| R-I1 MCP 2026-07-28, no sessions | Adopted | §12.4, §12.5 |
| R-I2 bridge as MCP client | Adopted | PROF-071 |
| R-I3 bridge as MCP server | Adopted | PROF-070 |
| R-I4 explicit state mapping | Adopted, with `isError: true` → `failed` | PROF-072 |
| R-I5 work without MCP tasks | Adopted | PROF-069 |
| R-I6 `_meta` prefix, opaque signed bytes | Adopted | §12.5 |
| R-I7 rmcp hardening | Deferred to the MCP facade implementation (T12). It is about one library, not the protocol. | — |
| R-J1 … R-J4 interop smoke-test inputs | Deferred to the conformance harness (T4) and the HTTP edge (T11) | — |

## 14. Conformance

Requirements are checked by test vectors (format in
[`conformance/vectors/README.md`](../conformance/vectors/README.md)) and by harness scenarios. This section defines
the vector kinds this document introduces.

| Kind | Input | Output on `accept` | Rejections |
|---|---|---|---|
| `task/transition` | `{"from": <state or null>, "to": <state>}`, states as `a2a.proto` enum names | none | `InvalidAgentResponseError` |
| `task/operation` | `{"op": <A2A method>, "state": <state>, "fromSeq"?: <int>}` | `{"state": <resulting state>}` where the profile fixes it, else none | the A2A error of §6.3 |
| `stream/resume` | `{"lastSeq": <int>, "retainedFrom": <int>, "terminal": <bool>, "fromSeq": <int or null>}` | `{"snapshotFirst": <bool>, "replay": [<seq>…], "thenLive": <bool>}` | `UnsupportedOperationError`, `InvalidParamsError` |
| `stream/observe` | `{"applied": <int or null>, "received": [{"seq": <int>, "kind": "task" \| "event", "terminal"?: <bool>} …], "streamEnded": <bool>}` | `{"applied": <int>, "finished": <bool>, "action": "none" \| "resubscribe", "fromSeq"?: <int>}` | none |
| `delivery/step` | `{"state": <delivery state>, "event": "transmit" \| "custody" \| "response" \| "retryable-error" \| "final-error" \| "expiry" \| "local-cancel"}` | `{"state": <delivery state>}` | any (illegal step) |
| `error/map` | `{"name": <error name>, "context"?: "task-op"}` | `{"name", "code", "reason", "retryable", "http"?, "grpc"?}` | none |
| `card/check` | `{"card": <Agent Card JSON>}` | none | any (card does not satisfy §5) |
| `bridge/mcp-state` | `{"mcp": <outcome>, "isError"?: <bool>}` | `{"state": <A2A state>}` | none |

The vectors are under `conformance/vectors/` (`task/`, `stream/`, `delivery/`, `error/`, `card/`, `bridge/`).
Requirements that need running nodes (durability across a crash, live and deferred paths, authorisation, audit
records, the bridges) are covered by harness scenarios, starting with the M1 scenario of due diligence §6. The
table below says which.

| Requirement | Covered by |
|---|---|
| PROF-015, PROF-016 | `task/transition` |
| PROF-018 | `task/operation` |
| PROF-024, PROF-028 | `stream/observe` |
| PROF-027 | `stream/resume` |
| PROF-033, PROF-035 (state part) | `delivery/step` |
| PROF-008, PROF-009, PROF-010 (shape), PROF-004, PROF-005 (card part) | `card/check` |
| PROF-047, PROF-051, PROF-053 | `error/map` |
| PROF-072 | `bridge/mcp-state` |
| All others | Harness scenarios (T4, T5, T11, T12). Not written yet: see §15. |

## 15. Open issues

1. **Harness coverage.** Most requirements here are behavioural and need the harness (T4) and a node (T5). Until
   then `webway-conformance check` reports them as untested (CONV-004).
2. **`DeliveryExpired` is "unknown", not "failed".** Reporting a possibly processed request as `failed` is the
   honest choice available in A2A's state set, and `lateResponse` lets the agent find the remote task. A cleaner
   answer needs an A2A state for "unknown outcome", which A2A does not have.
3. **Capability names** in PROF-042 (`skill:`, `task:`, `agent:`) are fixed here so the profile is testable. Their
   token encoding is T3's.
4. **A2A 1.1.** When an SDK ships 1.1, `generation` should be mapped to `seq` (same role) and the cursor
   parameter aligned with `last_seen_generation`.
5. **Upstreaming.** The cursor (§7.2) and the transition table (§6.2) are generic and are candidates for the A2A
   project (roadmap T20).
