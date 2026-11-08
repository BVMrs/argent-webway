# Extension `mailbox/v0`: store-and-forward, outbox, resumable streams

Status: **draft v0**, for review. Date: 2026-11-08. Roadmap track T7 (M1 step 6). Issue #9.
Extension URI: `https://github.com/BVMrs/argent-webway/spec/ext/mailbox/v0`, written `…/ext/mailbox/v0` below.
Requirement prefix: `MBX` ([conventions](../conventions.md)).

Inputs: due diligence [§4.4](../../docs/due-diligence.md#44-message-and-task-model),
[§4.5](../../docs/due-diligence.md#45-delivery-offline-peers-streaming-and-artefacts),
[§4.7.3](../../docs/due-diligence.md#473-integrity-confidentiality-replay),
[§6](../../docs/due-diligence.md#6-first-milestone-m1) (scenario step 6) and
[Q7](../../docs/due-diligence.md#q7-relay-and-mailbox-operation); the profile (`profile.md` §6.5, §7, §8), the
binding (`binding-webway-quic.md` §3.2, §6.1, §9), `ext/envelope.md` (§6 freshness, §8 replay, §11
intermediaries), `ext/capability.md` (§4 statements, §5 tokens, §8 invites) and the threat model
(`docs/threat-model.md`): rows REL-3, MBX-1 to MBX-7, RPL-8, META-2, DOS-4 and gaps G3, G4, G12, G15.

Test vectors: [`conformance/vectors/mailbox/`](../../conformance/vectors/mailbox/), checked by the reference model
in [`conformance/tools/mailbox-model/`](../../conformance/tools/mailbox-model/) ([§14](#14-conformance)).

**Summary.** Every node keeps a durable **outbox** and retries each envelope, byte for byte, until the recipient
confirms it or its signed `exp` passes. When the recipient's node is unreachable, the outbox hands the envelope to
one of the recipient's **mailbox hosts**, which holds it until the recipient's node connects and then delivers it.
A mailbox host admits an envelope only with a **deposit token** issued by the recipient's owner and a signature by
the **deposit key** the token names, so a mailbox is not free storage for strangers, and admission does not depend
on who the sender is. A mailbox host can store, delay and drop, but it cannot forge, alter, or claim delivery:
only the recipient's node moves an envelope to `delivered`. Streams survive disconnection because every task event
has a signed `seq` and the requester resumes with `SubscribeToTask` from its last applied `seq`. Nothing in this
extension needs a new error code, and nothing in it relies on clocks agreeing beyond `SKEW`.

---

## Contents

1. [Scope and relation to other documents](#1-scope-and-relation-to-other-documents)
2. [Terminology and constants](#2-terminology-and-constants)
3. [Declaring mailbox hosts](#3-declaring-mailbox-hosts)
4. [Deposit keys and deposit tokens](#4-deposit-keys-and-deposit-tokens)
5. [The `DEPOSIT_AUTH` frame](#5-the-deposit_auth-frame)
6. [Registration with a mailbox host](#6-registration-with-a-mailbox-host)
7. [Mailbox host: admission](#7-mailbox-host-admission)
8. [Mailbox host: held envelopes](#8-mailbox-host-held-envelopes)
9. [Outbox](#9-outbox)
10. [Recipient node](#10-recipient-node)
11. [Resumable streams](#11-resumable-streams)
12. [Error model](#12-error-model)
13. [Versioning](#13-versioning)
14. [Conformance](#14-conformance)
15. [Security considerations](#15-security-considerations)
16. [Open issues](#16-open-issues)

---

## 1. Scope and relation to other documents

"Peer offline" is a normal state (due diligence R2). The profile already fixes what an agent sees: a proxy task in
`submitted` with `delivery: "queued"` (PROF-030), the requester-side delivery state machine (`queued`, `sent`,
`acknowledged`, `refused`, `expired`, `withdrawn`, profile §8.3), deferred delivery of responses and events
(PROF-036), cursor resumption (PROF-027, PROF-028) and dedupe (PROF-023). The binding fixes the frames: `DELIVER`
and `CUSTODY` on deliver streams (binding §9). `ext/envelope.md` fixes freshness (`exp`, `SKEW`) and replay
(dedupe until `exp + SKEW`).

This document specifies the machinery underneath:

| Part | Section |
|---|---|
| Where a recipient's mailbox hosts are declared, and which ones a sender may use | §3 |
| Who may deposit into a mailbox (deposit tokens, threat-model G4) | §4, §5 |
| How a recipient's node registers with a mailbox host and how held envelopes reach it | §6, §8, §10 |
| What a mailbox host checks before it takes custody, in which order | §7 |
| The outbox: entry state machine, paths, retry schedule, ordering | §9 |
| Reconnection and stream resumption | §11 |

Out of scope: sealed envelopes (T15, threat-model G12; until then a mailbox host can read what it holds, §3.2),
signed receipts (`ext/audit.md`), blob transfer to offline peers (`ext/blob.md`), the A2A HTTP edge (push webhooks
stay there, profile §8.4).

### 1.1 How the parts fit

```text
 requester node R                     mailbox host H (of B)                  responder node B
 ┌──────────────┐  DEPOSIT_AUTH+DELIVER  ┌───────────────┐  DELIVER (B online)  ┌──────────────┐
 │ outbox entry ├──────────────────────►│ held envelope ├────────────────────►│ dedupe, task │
 │  pending     │◄──────────────────────┤               │◄────────────────────┤ store        │
 │  → stored    │   CUSTODY accepted     │ → delivered   │  CUSTODY accepted   │              │
 │  → received* │                        └───────────────┘                     │              │
 │  → delivered │◄─────── signed response, by deferred delivery (to R or R's host) ─────────────┤
 └──────────────┘                                                              └──────────────┘
      * `received` is reached when B's own node confirms custody of a request (direct DELIVER).
```

## 2. Terminology and constants

- **Outbox**: a node's durable store of envelopes it has signed (or forwards for its agents) and must still get to
  their recipients (§9). One **entry** per envelope.
- **Mailbox host**: a node that holds envelopes for other nodes' agents while they are offline. It announces the
  role `mailbox-host` in HELLO (binding §3.2). It is reached as an agent, the **host agent** (`wwa:`), certified
  to the host node like any agent (`ext/capability.md` §4.6), so registrations are ordinary signed requests.
- **Recipient**: the agent named in an envelope's `to`. **Recipient node**: the node that agent is bound to by its
  agent certificate.
- **Depositor**: any node that hands an envelope to a mailbox host. Usually the sender's node, sometimes a
  responder delivering events.
- **Custody**: a `CUSTODY` frame with status `accepted` or `duplicate` (binding §9). **Host custody** comes from a
  mailbox host. **Recipient custody** comes from the recipient node, on a connection authenticated as that node.
- **Content-trusted host**: a mailbox host that the sender's owner accepts to read unsealed envelopes (§3.2).
- **Header digest**: `BLAKE3(signing input)` of an envelope (`ext/envelope.md` §8.1).
- `SKEW`, `MAX_TTL`, `DEFAULT_TTL`: as in the profile and `ext/envelope.md` (300 s, 7 days, 24 h).

Constants of this extension:

| Name | Value | Meaning |
|---|---|---|
| `RETRY_BASE` | 1 s | First retry delay before jitter (§9.4) |
| `RETRY_MAX` | 300 s | Largest retry delay before jitter (§9.4) |
| `MAX_HOSTS` | 4 | Most mailbox hosts declared for one agent (§3.1) |
| `LEASE_MAX` | 30 days | Longest registration lease a host grants (§6) |
| `MAX_DEPOSIT_TTL` | 30 days | Largest `expires − issued` of a deposit token (§4.2). Equal to `MAX_ACCESS_TTL` of `ext/capability.md`. |
| `MAX_DEPOSIT_AUTH_BYTES` | 12 288 | Largest `DEPOSIT_AUTH` payload (§5) |
| `DEPOSIT_SIG_PREFIX` | ASCII `webway-mailbox-deposit/0` followed by one `0x00` byte | Domain separation for deposit signatures (§5.1) |

## 3. Declaring mailbox hosts

### 3.1 Agent Card parameters

An agent whose node implements this extension lists it in its signed Agent Card (profile §5) with parameters:

```json
{ "uri": "https://github.com/BVMrs/argent-webway/spec/ext/mailbox/v0",
  "params": {
    "depositKey": "ZmFrZS1kZXBvc2l0LWtleS0zMi1ieXRlcy1sb25nISE",
    "hosts": [
      { "agent": "wwa:…", "node": "wwn:…", "owner": "did:key:z6Mk…" }
    ]
  } }
```

| Member | Type | Meaning |
|---|---|---|
| `depositKey` | string | The agent's deposit public key (§4.1): 32 bytes, base64url without padding (43 characters) |
| `hosts` | array, 0 to `MAX_HOSTS` | Mailbox hosts that hold envelopes for this agent, in order of preference |
| `hosts[].agent` | `wwa:` | The host agent, the `to` of registrations (§6) |
| `hosts[].node` | `wwn:` | The host node, dialled for deposits |
| `hosts[].owner` | `did:key:` | The owner the recipient says operates the host. A depositor verifies it (MBX-005). |

- [MBX-001] An Agent Card that lists `…/ext/mailbox/v0` MUST carry `params` with a `depositKey` in the form above
  and a `hosts` array of at most `MAX_HOSTS` entries, each with `agent`, `node` and `owner` in the identifier forms
  of `ext/capability.md` §3. A node MUST treat a card whose mailbox parameters break this as not supporting the
  extension for that agent (it uses only direct paths and its own outbox) and MUST NOT use any of its hosts.
  Unknown members are ignored.
- An empty `hosts` is valid: the agent accepts deposits only directly, at its own node.

### 3.2 Which hosts a depositor may use (threat-model MBX-2)

A host declaration is only useful if it is authentic, and before sealed envelopes (T15) a mailbox host reads
everything it holds. So a depositor needs two things: the list of hosts must come from the recipient, and the
sender's owner must be willing to show the content to the operator of the host.

- [MBX-003] *Pending: T4, T5.* A depositor MUST take a recipient's mailbox hosts only from: the recipient's Agent Card, verified as
  the profile and `ext/capability.md` §4.7 require; an invite from the recipient's owner (`ext/capability.md` §8,
  the `deposit` claim, §4.4 below); or the `cap.mailbox.hosts` of a verified envelope whose `from` is the recipient
  (§4.3). The most recently verified of these replaces the others. It MUST NOT take hosts from any other source,
  in particular not from message text, Parts, artefacts or another agent's envelope.
- [MBX-004] A node MUST NOT hand an unsealed envelope to a mailbox host unless the host is **content-trusted**: it is
  operated by the sender's owner, or by the recipient's owner, or the sender's owner has listed it (by node key or
  by operating owner) in local policy as trusted with content. A host operated by any other owner MUST NOT be used
  for unsealed envelopes, even if the recipient declares it.
- [MBX-005] A node MUST establish who operates a mailbox host from the host agent's certificate chain
  (`ext/capability.md` §4.6, an agent certificate for `hosts[].agent` bound to `hosts[].node`, chaining to
  `hosts[].owner`), never from the `owner` member alone, and MUST deposit only on a connection whose peer node key
  is `hosts[].node`. If the chain does not verify, or names another owner, the host is not content-trusted and is
  not used.

The recipient's owner is content-trusted by default because the content is addressed to that owner's agent, which
will read it anyway. What the host additionally learns is metadata (who writes to the agent, when, how much), the
same as the recipient. An owner who also wants to hide that from its own counterparties' operators can remove the
default in local policy. This follows DD §4.5: "M1 deployments must use a mailbox host the sender's owner trusts
with that content".

## 4. Deposit keys and deposit tokens

Threat-model gap G4: anyone could fill a mailbox. A mailbox host therefore admits an envelope only when the
depositor proves it holds a **deposit token** for the recipient's mailbox. The token is issued by the recipient's
owner and bound to a **deposit key**. The host checks the token and a signature by that key over the envelope's
header digest. It never looks at `from`, `ctx` or `prov` to decide, so admission keeps working when T15 seals
those members (G12).

### 4.1 Deposit keys

- [MBX-002] *Pending: T4, T5.* Each agent that sends envelopes through mailbox hosts MUST have a deposit key: an Ed25519 key pair
  held by its node, distinct from every other key (`ext/capability.md` CAP-003, role "deposit key"), and published
  as `depositKey` in the agent's card. The deposit key MUST sign nothing but deposit signatures (§5.1).

A deposit key is a pseudonym for one sending agent at mailbox hosts (threat-model META-2). A node rotates it by
publishing a new card. Tokens bound to the old key stop working at the next deposit, which the outbox treats as a
path failure (§9.3) until the peer sends a token for the new key.

### 4.2 Deposit token format

A deposit token is a Biscuit token ([Biscuit]) with a single block, the authority block, signed by an **issuing
key** (`wwi:`) of the recipient's owner, whose issuer certificate has a resource scope covering `mailbox:*`
(`ext/capability.md` §4.5). Facts of the authority block:

| Fact | Meaning |
|---|---|
| `webway("mailbox/v0", "deposit")` | Marks a deposit token. Exactly one. |
| `issuer($wwi)` | The issuing key that signed the block. Exactly one. |
| `owner($did)` | The recipient's owner. Exactly one. |
| `issued($date)`, `expires($date)` | Validity. Exactly one each. `expires − issued` at most `MAX_DEPOSIT_TTL`. |
| `right($c)` | Exactly one, `$c` = `"mailbox:<recipient wwa>#deposit"` (capability kind `mailbox:`, `ext/capability.md` §5.2). |
| `deposit_key($k)` | The holder's deposit public key, base64url as in `depositKey`. Exactly one. |
| `quota_envelopes($n)`, `quota_bytes($n)` | Optional, at most one each, integers ≥ 1. Most envelopes held at one time for this token at one host, and most bytes (`JCS(envelope)` length). |

- [MBX-010] A mailbox host MUST reject as `CapabilityInvalid` a deposit token that has more than one block, lacks
  any fact that the table marks "exactly one", has more than one of any fact, has a fact of the wrong arity or term
  type, carries a quota fact that is not an integer ≥ 1, has `expires − issued` above `MAX_DEPOSIT_TTL`, has an
  `issuer` other than the key that signed the block, or exceeds `MAX_TOKEN_BYTES` (`ext/capability.md` §2.1).
- [MBX-011] A mailbox host MUST reject as `CapabilityDenied` a well-formed deposit token whose `owner` is not the
  owner of the registration for the envelope's `to` (§6), whose issuer certificate does not chain to that owner
  with a resource scope covering the `right`, whose `right` is not `mailbox:<to>#deposit` for the envelope's `to`,
  whose `expires` is earlier than the host's current time (no `SKEW`, as for access tokens), or whose
  `deposit_key` is not the key that made the deposit signature. A token or issuer certificate listed in a verified
  revocation list (`ext/capability.md` §9) MUST be rejected as `CapabilityRevoked`.

The token has no holder chain and cannot be re-delegated: whoever holds the deposit key's private half is the only
one who can use it. It authorises nothing else. Deposits never run Datalog; the facts are read from the decoded
block (as CAP-104 requires for access tokens).

### 4.3 Handing out tokens: `cap.mailbox`

A node gives a peer a deposit token for its own agent's mailbox inside the signed header of an ordinary envelope,
next to the capability members of `ext/capability.md` §5.8:

```json
"cap": {
  "capability": "skill:run-tests",
  "access": "…",
  "mailbox": {
    "deposit": "<base64url Biscuit deposit token>",
    "hosts": [ { "agent": "wwa:…", "node": "wwn:…", "owner": "did:key:z6Mk…" } ]
  }
}
```

The token is bound to the *receiver's* published deposit key, so it is useless to anyone else, and carrying it in
the signed header (kept in audit logs and mailbox indexes) reveals nothing secret.

- [MBX-012] *Pending: T4, T5.* A node MUST act on `cap.mailbox` only after the envelope verified, and only if the token's `right` names
  the envelope's `from`. It MUST otherwise ignore the member and record an anomaly. A valid `cap.mailbox` replaces
  the deposit token and host list the node held for that agent, unless the held token expires later and names the
  same hosts.
- A node SHOULD include `cap.mailbox` in every request to an agent of another node that does not yet hold an
  unexpired token for the sender's agent, and in every response whose request carried none or one that expires
  within a quarter of its lifetime. A requester that may receive deferred responses or events needs to have given
  the responder a token (PROF-036), so the first request to a peer SHOULD always carry one.
- [MBX-013] *Pending: T4, T5.* A node MUST NOT give a deposit token, or a deposit key, to an agent, and MUST NOT put either in message
  text, Parts or artefacts (as `ext/capability.md` CAP-151 requires for all tokens).

Activation: `cap.mailbox` changes nothing about the request it travels in, so a node that implements this
extension honours it whether or not `…/ext/mailbox/v0` is active for that request (profile PROF-056). A node that
does not implement the extension keeps it as an unknown signed member (ENV-002) and ignores it.

### 4.4 Bootstrap through invites

A recipient that is offline, or not yet in contact, cannot hand out tokens on demand. The first token comes with
the invite (threat-model G4 (i), `ext/capability.md` §8.1 `deposit` claim). Because the invite is created before
the inviting owner knows the invitee's deposit key, the invite carries a fresh key pair:

```json
"deposit": {
  "agent": "wwa:…",
  "token": "<base64url Biscuit deposit token, deposit_key = the public half of key>",
  "key": "<base64url 32-byte Ed25519 private key seed>",
  "hosts": [ { "agent": "wwa:…", "node": "wwn:…", "owner": "did:key:z6Mk…" } ]
}
```

- [MBX-014] *Pending: T4, T5.* The `deposit` claim of an invite MUST have the members above, with `token` bound to the public key of
  `key` and `right` naming `agent`. An invitee MUST use that key only for deposits to `agent`, and MUST stop using
  it once it holds a token for `agent` bound to its own deposit key (from a `cap.mailbox`).

The invite is secret and passed out of band. Someone who intercepts it can deposit, within the token's quota, until
it expires (threat-model ID-4). That is the bound G4 accepts.

## 5. The `DEPOSIT_AUTH` frame

Deposit proofs travel in the binding's framing, not in the envelope (ENV-701: nothing may be added to a signed
envelope). This extension assigns one frame type from the extension range of binding §6.1:

| Type | Name | Allowed on | Payload |
|---|---|---|---|
| `0x20` | `DEPOSIT_AUTH` | DELIVER, opener → peer | JSON object `{"token": <base64url Biscuit>, "sig": <base64url Ed25519 signature>}` |

`DEPOSIT_AUTH` applies to the `DELIVER` frame that follows it on the same stream. `CUSTODY` frames still match
`DELIVER` frames one to one (BIND-024): `DEPOSIT_AUTH` gets no answer of its own.

- [MBX-020] *Pending: T4, T5.* A depositor MUST send `DEPOSIT_AUTH` only on a deliver stream to a peer whose HELLO lists the role
  `mailbox-host` and the feature `…/ext/mailbox/v0`, and MUST send it immediately before the `DELIVER` frame it
  authorises. A mailbox host MUST treat a `DEPOSIT_AUTH` that is followed by anything other than a `DELIVER`
  frame, or by the end of the stream, or whose payload exceeds `MAX_DEPOSIT_AUTH_BYTES` or is not such a JSON
  object, as a stream error `ProtocolError` (binding §11.2).
- A peer that does not implement this extension skips the frame by its length (BIND-012). A recipient node that
  receives a `DELIVER` for an agent it hosts ignores any `DEPOSIT_AUTH` before it.

### 5.1 Deposit signature

- [MBX-021] The deposit signature MUST be the Ed25519 signature, by the deposit key, of the byte string
  `DEPOSIT_SIG_PREFIX ‖ D`, where `D` is the 32-byte header digest of the envelope in the following `DELIVER`
  frame. A host MUST verify it with the strict rules of `ext/capability.md` CAP-002 against the token's
  `deposit_key`.

The prefix starts with `w`, so a deposit signature can never be mistaken for a JWS signing input (starts `eyJ`), an
envelope signing input (starts `{`) or a Biscuit block (binary). The digest covers the whole signed header, so the
authorisation cannot be moved to another envelope; it does not cover the body, so a host can check admission
before it hashes up to `MAX_ENVELOPE_BYTES` of body.

## 6. Registration with a mailbox host

A host must know, for each agent it holds envelopes for, which node to deliver them to and which owner's tokens to
accept. The recipient's node tells it with a signed request from the agent itself:

- `op`: `https://github.com/BVMrs/argent-webway/spec/ext/mailbox/v0#Register`
- `from`: the agent whose mailbox this is. `to`: the host agent.
- `cap.capability`: `mailbox:<host agent>#register`, with an access token rooted in the host owner's issuing key
  and held by the registering agent (`ext/capability.md` §5.4). A host operated by the agent's own owner may accept
  a token the owner issues itself.
- `a2a-extensions`: `…/ext/mailbox/v0`.
- params (`rpc.params`):

| Member | Type | Meaning |
|---|---|---|
| `leaseUntil` | Timestamp | Requested end of the lease |
| `agentCert` | statement | The registering agent's agent certificate (`ext/capability.md` §4.6), binding it to its node and owner |
| `issuerCerts` | array of statements | Issuer certificates of the owner's issuing keys that sign this agent's deposit tokens |
| `ownerKeys` | array | Optional: the owner-key event chain, if the owner has rotated (`ext/capability.md` §4.3) |

Result: `{"leaseUntil": <Timestamp>, "quota": {"envelopes": <int>, "bytes": <int>}}`, the lease and the
per-registration quota the host grants.

- [MBX-030] A mailbox host MUST authorise `#Register` like any operation (profile PROF-042) with the capability
  `mailbox:<host agent>#register`, MUST verify `agentCert` and `issuerCerts` as `ext/capability.md` §4 requires, and
  MUST reject a request whose `agentCert` does not certify the envelope's `from` (`IdentityUntrusted`) or whose
  `leaseUntil` is not later than its current time (`InvalidParamsError`).
- [MBX-031] A mailbox host that accepts `#Register` MUST record the registration (agent, node and owner from
  `agentCert`, the issuer certificates, the lease) and MUST grant a lease ending at the earlier of the requested
  `leaseUntil` and its current time plus `LEASE_MAX`. A later accepted `#Register` for the same agent replaces the
  earlier one, including its node: held envelopes then go to the new node.
- [MBX-032] *Pending: T4, T5.* A recipient node MUST renew the lease at every host its agent declares before the lease ends, while it
  declares that host. A node SHOULD declare a host in the card only once it holds a lease there.

When a lease ends, the host stops admitting deposits for the agent (RecipientUnknown, §7) and keeps what it holds
until each envelope's `exp` (§8): the registration's node and owner stay recorded for that purpose.

## 7. Mailbox host: admission

When a mailbox host receives `DEPOSIT_AUTH` + `DELIVER` for an agent it does not host itself, it decides whether
to take custody. The checks are ordered cheapest first (threat-model G15) and the first failure is reported.

- [MBX-040] A mailbox host MUST apply the following checks in this order, and MUST answer the `DELIVER` with a
  `CUSTODY` `rejected` carrying the error of the first check that fails, or with the status given:

| Step | Check | On failure |
|---|---|---|
| 1 | The envelope parses as I-JSON and `to`, `from`, `id`, `ts`, `exp` are readable in the forms of `ext/envelope.md` §3.2 | `EnvelopeInvalid` |
| 2 | A `DEPOSIT_AUTH` preceded the `DELIVER` | `CapabilityMissing` |
| 3 | The host has a registration for `to` whose lease has not ended | `RecipientUnknown` |
| 4 | `now ≤ exp + SKEW` | `EnvelopeExpired` |
| 5 | `ts ≤ now + SKEW` | `EnvelopeNotYetValid` (retryable, `retryAfterMs` until `ts − SKEW`) |
| 6 | `ts < exp` and `exp − ts ≤ MAX_TTL + SKEW` | `EnvelopeInvalid` |
| 7 | Deposit token well-formed (MBX-010) | `CapabilityInvalid` |
| 8 | Deposit token authorises this deposit (MBX-011) | `CapabilityDenied` or `CapabilityRevoked` |
| 9 | Deposit signature verifies (MBX-021) | `CapabilityDenied` |
| 10 | Envelope steps 1–5 of `ext/envelope.md` §9 pass (format, signature by `from`, `body_hash`) | that step's error (`EnvelopeInvalid`, `SignatureInvalid`) |
| 11 | No held record or tombstone has the same (`from`, `id`) | same header digest: status **`duplicate`**. Different digest: `EnvelopeInvalid` (id reuse), and an anomaly is recorded. |
| 12 | Held envelopes for this token stay within its quota facts, and held envelopes for this registration within the registration quota, counting this one | `MailboxFull` (retryable, `retryAfterMs` SHOULD be set) |
| 13 | The envelope is stored durably (binding BIND-023) | status **`accepted`** |

- [MBX-041] A mailbox host MUST NOT take custody of an envelope whose signature or `body_hash` does not verify
  (step 10). `ext/envelope.md` ENV-702 makes this a SHOULD for intermediaries in general. For a mailbox host it is
  a MUST, because a stored forgery would occupy a sender's (`from`, `id`) and later make the genuine envelope look
  like a duplicate.
- [MBX-042] A duplicate deposit (step 11) MUST NOT count against any quota and MUST NOT create a second held record.
- [MBX-043] A mailbox host's admission decision MUST NOT depend on `from`, `ctx`, `cap` (other than through steps 1
  and 10, which only check form and signature) or `prov`. In particular it MUST NOT admit an envelope without a
  valid deposit token because of who sent it.

Step 6 accepts up to `MAX_TTL + SKEW` for every `typ` because answers and events may reach that bound (profile
PROF-076). The recipient applies its own, stricter rule on delivery.

## 8. Mailbox host: held envelopes

Each admitted envelope becomes a **held record**: the envelope as received, its header digest, the deposit token
it was admitted under (for quota accounting), and its state.

| State | Meaning |
|---|---|
| `held` | Stored, not yet confirmed by the recipient node. Deliverable while `now ≤ exp`. |
| `delivered` | The recipient node gave custody (`accepted` or `duplicate`). |
| `dropped` | The recipient node rejected it with a non-retryable error. |
| `expired` | `exp` passed while it was `held`. |

Events and transitions (`illegal` means the event cannot happen in that state, and an implementation that sees it
has a bug):

| from \ event | recipient accepted | recipient duplicate | recipient refusal | retryable error | `now > exp` | re-deposit |
|---|---|---|---|---|---|---|
| `held` | `delivered` | `delivered` | `dropped` | `held` | `expired` | `held` |
| `delivered` | illegal | illegal | illegal | illegal | `delivered` | `delivered` |
| `dropped` | illegal | illegal | illegal | illegal | `dropped` | `dropped` |
| `expired` | illegal | illegal | illegal | illegal | `expired` | `expired` |

"Recipient refusal" is a `CUSTODY` `rejected` from the recipient node whose error is not retryable. "Retryable
error" is a `CUSTODY` `rejected` with a retryable error, a transport failure, or no connection. "Re-deposit" is
the same envelope deposited again (step 11 answers `duplicate`).

- [MBX-050] A mailbox host MUST implement the state machine above. In `delivered`, `dropped` and `expired` it MUST
  delete the envelope body and keep only a **tombstone** (`from`, `id`, header digest, `exp`) until
  `now > exp + SKEW`, so that a re-deposit is answered `duplicate` (step 11) and never delivered twice by this host.
  It MAY delete the tombstone after that.
- [MBX-051] *Pending: T4, T5.* A mailbox host MUST deliver a held envelope only to the node recorded in the registration for its `to`
  (MBX-031), only on a connection whose peer node key is that node, and only on a DELIVER stream it opens (binding
  §9). It MUST NOT deliver held envelopes to anyone else, whatever they ask.
- [MBX-052] *Pending: T4, T5.* A mailbox host MUST deliver the held envelopes of one recipient agent in the order it admitted them,
  and MUST NOT start delivering an envelope while an earlier one for the same agent and the same `ctx.taskId` is
  without a `CUSTODY` answer.
- [MBX-053] A mailbox host MUST NOT deliver an envelope once `now > exp` (ENV-304) and MUST then move it to
  `expired`.
- [MBX-054] *Pending: T4, T5.* A mailbox host MUST NOT tell a depositor, or anyone, that an envelope was delivered, and MUST NOT sign or
  send any envelope about a held envelope on the recipient's behalf. Its only statement to a depositor is the
  per-hop `CUSTODY` at deposit time.
- [MBX-055] *Pending: T4, T5.* A mailbox host MUST start delivering a registered node's held envelopes once that node's HELLO has
  arrived on a new connection, without waiting for a request from it.

Delivering in order per task (MBX-052) keeps continuations of a task in order. Events need no help: they carry
`seq` and the requester orders them itself (PROF-028). A host SHOULD keep a durable purge watermark as
`ext/envelope.md` ENV-504 describes for dedupe entries, so that a clock stepping back does not revive a purged
tombstone.

## 9. Outbox

### 9.1 Entries

- [MBX-060] *Pending: T4, T5.* A node MUST keep every envelope that it must get to another node (requests to offline peers, deferred
  responses and events, `CancelTask` by deferred path) as an outbox entry in durable storage, written before it
  first transmits the envelope and before it tells its agent the request is `queued` (PROF-030). The entry MUST
  hold the signed envelope exactly as signed, so every attempt sends the same signed envelope (ENV-500, PROF-033).

An entry records: the envelope, its header digest, the recipient, an **order key** (the local task it belongs to:
the proxy task for a request, the task for a response or event; none if it belongs to no task), the entry state,
the attempt count, the next attempt time, and per path whether it failed or gave custody.

### 9.2 Entry state machine

| State | Meaning | Profile delivery state (requests, §8.3) |
|---|---|---|
| `queued` | Never transmitted | `queued` |
| `pending` | Transmitted at least once. No custody. | `sent` |
| `stored` | A mailbox host gave custody. The recipient node has not confirmed. | `sent` |
| `received` | Requests only: the recipient node gave custody of the request. Its answer is still to come. | `sent` |
| `delivered` | Requests: the signed answer arrived (PROF-078). Other entries: the recipient node gave custody. | `acknowledged` |
| `refused` | The recipient refused it, non-retryably (requests: PROF-078; others: a non-retryable `CUSTODY` `rejected` from the recipient node). | `refused` |
| `expired` | `now > exp + SKEW` without reaching `delivered` or `refused` | `expired` |
| `withdrawn` | Requests only: canceled by the local agent while `queued` (PROF-035) | `withdrawn` |

Events:

- **transmit**: the node starts an attempt on some path (§9.3).
- **host-custody**: `accepted` or `duplicate` from a mailbox host.
- **recipient-custody**: `accepted` or `duplicate` from the recipient node (MBX-061).
- **response**: requests only: a signed `response` or `ack` envelope that answers the request and passes PROF-078.
- **recipient-refusal**: requests: a signed non-retryable error passing PROF-078. Other entries: a non-retryable
  `CUSTODY` `rejected` from the recipient node.
- **retryable-error**: anything else that ends an attempt: a `CUSTODY` `rejected` from a host (whatever its code,
  PROF-078), a retryable error (signed or not), a transport failure.
- **expiry**: `now > exp + SKEW`.
- **local-cancel**: requests only: the agent cancels the proxy task.

Requests:

| from \ event | transmit | host-custody | recipient-custody | response | recipient-refusal | retryable-error | expiry | local-cancel |
|---|---|---|---|---|---|---|---|---|
| `queued` | `pending` | illegal | illegal | illegal | illegal | illegal | `expired` | `withdrawn` |
| `pending` | `pending` | `stored` | `received` | `delivered` | `refused` | `pending` | `expired` | `pending` (held, PROF-035) |
| `stored` | `stored` | `stored` | `received` | `delivered` | `refused` | `stored` | `expired` | `stored` (held) |
| `received` | `received` | `received` | `received` | `delivered` | `refused` | `received` | `expired` | `received` (held) |
| `delivered` | unchanged | unchanged | unchanged | unchanged | unchanged | unchanged | unchanged | unchanged |
| `refused` | unchanged | unchanged | unchanged | unchanged | unchanged | unchanged | unchanged | unchanged |
| `expired` | unchanged | unchanged | unchanged | unchanged (late, PROF-034) | unchanged | unchanged | unchanged | unchanged |
| `withdrawn` | illegal | illegal | illegal | illegal | illegal | illegal | unchanged | unchanged |

Responses, events, errors and acks (state `received` and `withdrawn` do not exist for them; `response` and
`local-cancel` are illegal in every state, because nobody answers an answer, ENV-402, and a node never withdraws
one):

| from \ event | transmit | host-custody | recipient-custody | recipient-refusal | retryable-error | expiry |
|---|---|---|---|---|---|---|
| `queued` | `pending` | illegal | illegal | illegal | illegal | `expired` |
| `pending` | `pending` | `stored` | `delivered` | `refused` | `pending` | `expired` |
| `stored` | `stored` | `stored` | `delivered` | `refused` | `stored` | `expired` |
| `delivered`, `refused`, `expired` | unchanged | unchanged | unchanged | unchanged | unchanged | unchanged |

- [MBX-061] A node MUST implement the two tables above for its outbox entries. It MUST count a `CUSTODY` as
  recipient custody only if it arrived on a connection whose peer node key is the node that the envelope's `to`
  agent is bound to by its agent certificate. Every other custody is host custody, and host custody MUST NOT move
  an entry to `delivered` (threat-model G3).
- [MBX-062] A node MUST NOT transmit an entry once `now > exp` (ENV-304). It MUST keep the entry, waiting for an
  answer, until `now > exp + SKEW`, and then move it to `expired` and tell the agent (requests: PROF-034). An
  `expired` or `refused` event or response entry is not reported as a task failure: the requester recovers events
  with its cursor (§11).

The mapping column of §9.2 is how the profile's agent-visible delivery state is derived from the entry. A response
that arrives after `expired` changes nothing here and is handled by PROF-034.

### 9.3 Paths

An entry can be transmitted on three kinds of path, tried in this order:

1. **direct**: to the recipient node, live on a REQUEST stream (requests that can be answered live) or as a
   `DELIVER`;
2. **host *i***: a `DEPOSIT_AUTH` + `DELIVER` to the *i*-th declared mailbox host of the recipient (§3);
3. none: wait for the next attempt.

- [MBX-063] When it attempts an entry, a node MUST try the direct path first if the recipient node can be reached
  (an open connection, or a successful dial), and otherwise the recipient's declared hosts in declaration order.
  A host is eligible only if it is content-trusted (MBX-004, MBX-005), the node holds an unexpired deposit token
  for the recipient bound to a deposit key it holds, the host has not failed for this entry, and the entry is
  `queued` or `pending`. In `stored` and `received` only the direct path is used.
- [MBX-064] A `CUSTODY` `rejected` from a host with a non-retryable error marks that host as failed for that entry
  (the next attempt skips it). It MUST NOT change the entry's state beyond `retryable-error` (PROF-078).
- [MBX-065] While an entry is `stored`, the node MUST keep attempting the direct path, on the schedule of §9.4,
  until the entry is `delivered`, `refused` or past `exp`. A host may drop what it holds (threat-model MBX-4), and
  only these direct attempts recover from that.
- [MBX-066] While a request entry is `received`, the node MUST keep attempting the direct path with the delay
  `RETRY_MAX` (before jitter) until it is `delivered`, `refused` or past `exp`. Each attempt is a duplicate for the
  recipient, which then sends its stored answer again (MBX-081). This recovers an answer lost on its way back.

### 9.4 Retry schedule

After the `n`-th failed attempt (`n ≥ 1`), the delay before attempt `n + 1` is computed from a random `r` drawn
uniformly from `[0, 1)`:

```text
d      = min(RETRY_MAX, RETRY_BASE × 2^(n−1))           // in milliseconds: 1000, 2000, 4000, …, 300000
delay  = floor(d / 2 + r × d / 2)                        // "equal jitter": between d/2 and d
delay  = max(delay, retryAfterMs)                        // if the failure carried retryAfterMs
next   = now + delay
if next > exp: no further attempt (the entry waits for an answer until exp + SKEW, MBX-062)
```

- [MBX-067] A node MUST schedule retries no earlier than the formula above gives, MUST honour `retryAfterMs` from
  any error or `CUSTODY` it receives, and MUST NOT schedule an attempt after the envelope's `exp`.
- A node SHOULD attempt `pending` and `stored` entries for a recipient at once (resetting `n` to 1) when it learns
  the recipient node is reachable again: a connection from it, a discovery update, a successful attempt for
  another entry to the same node. The jitter keeps many senders from retrying a returning node in step.

### 9.5 Order

- [MBX-068] A node MUST NOT transmit an entry while an earlier entry (in the order the agent or task produced them)
  with the same recipient and the same order key is `queued` or `pending`. Entries without an order key are not
  ordered.

This is how PROF-032 ("hand envelopes for the same task to the network in the order its agent produced them") is
met when paths differ: an entry waits until the one before it has reached custody somewhere. Once both are in
custody they may still arrive out of order (one through a host, one direct). Requests to one task are then ordered
by the host (MBX-052) or by the agent's own waiting for answers, and events by `seq` (PROF-028).

## 10. Recipient node

A recipient node receives envelopes for its agents live, by direct `DELIVER`, or from its mailbox hosts. It treats
them the same: every one is verified in full (`ext/envelope.md` §9), deduplicated (PROF-023, ENV-510) and checked
for freshness. An envelope that waited in a mailbox for longer than `SKEW` but whose `exp` has not passed is
fresh (ENV-302). One past `exp + SKEW` is rejected with `EnvelopeExpired` (ENV-300), even when it was in custody
in time.

- [MBX-080] A node whose agents declare mailbox hosts MUST, while it is online, keep a connection to each declared
  host for which it holds a lease, or reconnect within `RETRY_MAX`, and MUST accept the DELIVER streams those
  hosts open. It MUST answer each `DELIVER` with `CUSTODY` as binding BIND-023 requires: `accepted` only once the
  envelope's effects are durable together with its dedupe entry (ENV-503), `duplicate` for a duplicate, `rejected`
  with the verification or processing error otherwise.
- [MBX-081] *Pending: T4, T5.* When a final recipient answers a duplicate of a request that carried `webway-reply: deferred` (whether
  the duplicate came live, direct or from a host), and the stored answer (ENV-520) is not already in its outbox, it
  MUST put the stored answer, byte for byte, into its outbox again for deferred delivery to the request's `from`
  (binding BIND-025).
- [MBX-082] *Pending: T4, T5.* A responder node MUST give each event it sends by deferred delivery an envelope with `exp − ts` at most
  `MAX_TTL`, and SHOULD use `DEFAULT_TTL`. An event entry that expires undelivered MUST NOT be removed from the task's
  event log because of that: the requester fetches it with its cursor (§11).
- A recipient node SHOULD drain its hosts before it reports itself ready to its agents after a restart, so that
  queued requests are processed in admission order before new live ones for the same task.

## 11. Resumable streams

A requester that was offline or crashed may have missed events: the stream it held was closed, deferred event
envelopes may have expired in an outbox or been dropped by a host, and events arrive from two paths in any order.
The signed `seq` (PROF-020, PROF-021) is the single source of truth, and the cursor of PROF-027 the recovery.

- [MBX-090] *Pending: T4, T5.* A requester node MUST store, for each proxy task, the highest `seq` it has applied, durably and in the
  same transaction as the applied event, so that a restart neither re-applies nor skips an event.
- [MBX-091] After a requester node restarts or reconnects, and once it has drained its own mailbox hosts (MBX-080),
  it MUST, for each proxy task whose delivery is `acknowledged` and whose remote task it has not seen in a terminal
  state, send `SubscribeToTask` with `webway-from-seq` equal to the applied `seq` plus one, as soon as the responder
  node is reachable. Until then it keeps the proxy task as it is (`stale: true`, profile §8.5).

M1 scenario step 6, "kill `alpha` mid-stream, restart, `SubscribeToTask fromSeq=k`, and no events are lost or
duplicated", follows: events up to `k − 1` were applied and recorded (MBX-090), the responder replays from `k`
(PROF-027), and a copy of an event that also arrives by deferred delivery is dropped by `seq` (PROF-028).

## 12. Error model

This extension defines no new error codes. It uses the profile's (profile §10) and `ext/capability.md`'s, with
retryability as registered there:

| Where | Error | Retryable | Meaning here |
|---|---|---|---|
| `CUSTODY` from a host | `EnvelopeInvalid` | no | Step 1, 6, 10 or 11 (id reuse) of §7 |
| | `SignatureInvalid` | no | Step 10 |
| | `EnvelopeExpired` | no | Step 4 |
| | `EnvelopeNotYetValid` | yes | Step 5 |
| | `CapabilityMissing` | no | Step 2: no `DEPOSIT_AUTH` |
| | `CapabilityInvalid` | no | Step 7 (MBX-010) |
| | `CapabilityDenied` | no | Steps 8, 9 (MBX-011, MBX-021) |
| | `CapabilityRevoked` | no | Step 8 |
| | `RecipientUnknown` | no | Step 3: no registration or the lease ended |
| | `MailboxFull` | yes | Step 12: a quota is reached. `retryAfterMs` SHOULD say when space is expected. |
| `#Register` | `CapabilityMissing`, `CapabilityDenied`, `CapabilityRevoked` | no | Authorisation (MBX-030) |
| | `IdentityUntrusted` | no | `agentCert` does not certify `from` or does not verify |
| | `InvalidParamsError` | no | `leaseUntil` not in the future, missing members |
| Agent-visible | `DeliveryExpired` | no | The entry of a request reached `expired` (PROF-034) |

- [MBX-070] A depositor MUST treat every `CUSTODY` `rejected` from a mailbox host as a per-hop failure: a
  `retryable-error` event for the entry (§9.2), never as the recipient's answer, whatever the code (PROF-078). A
  non-retryable code only marks the host as failed for that entry (MBX-064).

Errors a host reports go to the depositor only, as `CUSTODY` (unsigned, per hop, binding §9). The detailed reason
(which check, which fact) goes to the host's audit log (threat-model G15), not to the depositor.

## 13. Versioning

| What | Identifier | On mismatch |
|---|---|---|
| Extension | `…/ext/mailbox/v0` in the Agent Card (§3.1), HELLO `features` (§5), `a2a-extensions` of `#Register` | Card: the agent is treated as not supporting it (MBX-001). HELLO: no `DEPOSIT_AUTH` is sent to that peer, so it is not used as a host. `#Register`: `ExtensionSupportRequiredError`. |
| Deposit token | `webway("mailbox/v0", "deposit")` | `CapabilityInvalid` |
| Deposit signature | `DEPOSIT_SIG_PREFIX` `webway-mailbox-deposit/0` | The signature does not verify: `CapabilityDenied` |
| Frame | `0x20` `DEPOSIT_AUTH` | Skipped by peers that lack the feature (BIND-012) |

- A **minor** revision may add optional members to the card parameters, `cap.mailbox`, the invite `deposit` claim,
  `#Register` params and result, and the `DEPOSIT_AUTH` payload; new optional token facts that a host may ignore;
  new SHOULDs. Receivers ignore unknown members (and keep them where they are signed, ENV-002).
- A **major** revision (`…/ext/mailbox/v1`) is needed to change admission, the state machines, or the meaning of
  any existing member. It gets a new URI, a new token marker (`webway("mailbox/v1", …)`), a new signature prefix,
  and a new frame type, so a v0 host can never accept a v1 deposit by mistake (PROF-057: no silent fallback).
- Sealed envelopes (T15) will change what a host can read but not admission, which already ignores `from`, `ctx`
  and `prov` (MBX-043). They are expected as a minor revision plus an `envelope` change.

## 14. Conformance

Test vectors are in `conformance/vectors/mailbox/`, in the format `webway-vectors/v0` of
[`conformance/vectors/README.md`](../../conformance/vectors/README.md). Time values are RFC 3339 timestamps as in
`ext/envelope.md` §3.2. Cryptographic checks other than the deposit signature are given as their results
(booleans), because their own vectors live with `ext/envelope.md` and `ext/capability.md`.

| Kind | Input | Output on `accept` | Rejections |
|---|---|---|---|
| `mailbox/card` | `{"params": <card extension params>}` | `{"hosts": <int>}` | any (MBX-001) |
| `mailbox/token` | `{"blocks": <int>, "facts": {<fact name>: [<term array>…]}, "signedBy": <wwi>, "now", "recipient": <wwa>, "registrationOwner": <did>, "issuerChainOwner": <did>, "issuerScope": [<capability pattern>…], "depositSigner": <base64url key>, "revoked": <bool>}` | `{"quota": {"envelopes"?, "bytes"?}}` | `CapabilityInvalid`, `CapabilityDenied`, `CapabilityRevoked` |
| `mailbox/deposit-sig` | `{"depositKey": <base64url>, "headerDigest": <hex>, "sig": <base64url>}` | `{"signingInput": <hex>}` | `CapabilityDenied` |
| `mailbox/admit` | `{"now", "registration": {"agent", "leaseUntil"} or null, "envelope": {"parsed", "to", "from", "id", "ts", "exp", "digest", "bytes", "verify": "ok" \| "signature" \| "body-hash" \| "format"}, "deposit": {"token": "ok" \| "invalid" \| "denied" \| "revoked", "sigValid"} or null, "held": [{"from", "id", "digest"}…], "usage": {"envelopes", "bytes"}, "quota": {"envelopes", "bytes"}}` | `{"custody": "accepted" \| "duplicate"}` | the error of the failing step (§7) |
| `mailbox/register` | `{"now", "leaseUntil", "capability": "ok" \| "missing" \| "denied" \| "revoked", "certifiesFrom": <bool>}` | `{"leaseUntil"}` | `CapabilityMissing`, `CapabilityDenied`, `CapabilityRevoked`, `IdentityUntrusted`, `InvalidParamsError` |
| `mailbox/host-step` | `{"state", "event"}` (§8) | `{"state"}` | any (illegal) |
| `mailbox/outbox-step` | `{"request": <bool>, "state", "event"}` (§9.2) | `{"state"}` | any (illegal) |
| `mailbox/path` | `{"state", "direct": <bool>, "hosts": [{"operator": "sender-owner" \| "recipient-owner" \| "other", "allowListed", "chainValid", "token", "failed"}…]}` | `{"paths": ["direct" \| "host:<i>"…]}` | none |
| `mailbox/backoff` | `{"attempt": <n ≥ 1>, "r": <[0,1)>, "now", "exp", "retryAfterMs"?}` | `{"next": <timestamp> or null}` | none |
| `mailbox/order` | `{"entries": [{"key": <string or null>, "state"}…]}` | `{"eligible": [<index>…]}` | none |
| `mailbox/timing` | `{"role": "outbox" \| "host" \| "recipient", "now", "ts", "exp"}` | `{"action": "attempt" \| "await" \| "expire" \| "deliver" \| "stop" \| "accept"}` | `EnvelopeExpired`, `EnvelopeNotYetValid` (recipient) |
| `mailbox/reconnect` | `{"delivery": <profile delivery state>, "remoteTerminal": <bool>, "applied": <int>, "responderReachable": <bool>}` | `{"action": "none" \| "wait" \| "subscribe", "fromSeq"?}` | none |

Meaning of `mailbox/timing` actions: outbox `attempt` (`now ≤ exp`), `await` (`exp < now ≤ exp + SKEW`: no
attempt, an answer is still accepted), `expire` (`now > exp + SKEW`); host `deliver` (`now ≤ exp`), `stop`
(`now > exp`); recipient `accept` or the freshness error of `ext/envelope.md` §6.

Coverage:

| Requirement | Covered by |
|---|---|
| MBX-001 | `mailbox/card` |
| MBX-010, MBX-011 | `mailbox/token` |
| MBX-021 | `mailbox/deposit-sig` |
| MBX-040, MBX-041, MBX-042, MBX-043 | `mailbox/admit` |
| MBX-030, MBX-031 | `mailbox/register` |
| MBX-050, MBX-053 | `mailbox/host-step`, `mailbox/timing` |
| MBX-061, MBX-062, MBX-070 | `mailbox/outbox-step`, `mailbox/timing` |
| MBX-004, MBX-005, MBX-063, MBX-064, MBX-065, MBX-066 | `mailbox/path` |
| MBX-067 | `mailbox/backoff` |
| MBX-068 | `mailbox/order` |
| MBX-091 | `mailbox/reconnect` |
| MBX-080 (freshness on delivery) | `mailbox/timing` |
| MBX-002, MBX-003, MBX-012, MBX-013, MBX-014, MBX-020, MBX-032, MBX-051, MBX-052, MBX-054, MBX-055, MBX-060, MBX-081, MBX-082, MBX-090 | Harness scenarios (T4, T5, T10), not written yet. These carry the pending marker `*Pending: T4, T5.*` of change 0001 (`CONV-007`, proposed with `ext/capability.md`). The M1 scenario step 6 (due diligence §6) covers MBX-060, MBX-080, MBX-081, MBX-090 and MBX-091 end to end: `beta` down longer than `SKEW`, delivery exactly once despite outbox retries, crash before ack, a third task expiring, `alpha` killed mid-stream. |

The reference model `conformance/tools/mailbox-model` implements every kind above. `cargo run -- check` runs all
vectors against it; `cargo run -- adapter` is a stdio adapter (CONV-006) for the harness.

## 15. Security considerations

| Threat (threat model) | What this extension does | Residual |
|---|---|---|
| MBX-1 host alters or forges | Hosts store and forward the envelope unchanged (ENV-700) and must verify it before custody (MBX-041). The recipient verifies again. | None |
| MBX-2 host reads bodies | Only content-trusted hosts get unsealed envelopes (MBX-004), and who operates a host is checked from certificates (MBX-005). Host declarations come only from the recipient (MBX-003). | The host's operator sees content and metadata until T15. |
| MBX-3, META-2, G12 host reads headers | Not solved: v0 headers are clear. Admission already ignores `from`, `ctx` and `prov` (MBX-043), so T15 can seal them without changing §7. | A deposit key is a stable pseudonym per sending agent. |
| MBX-4, G3 host claims delivery | Hosts never report delivery (MBX-054). Only recipient custody on the recipient node's own connection, or the signed answer, moves an entry to `delivered` (MBX-061). Senders keep trying direct while `stored` (MBX-065). | A host can delay up to `exp`. The sender sees `sent` and then `expired`, never a false `delivered`. |
| MBX-5, RPL-8 host replays | Recipient dedupe (PROF-023, ENV-510). A replayed request gets the stored answer only over the sender's or its host's connection (ENV-531), and is re-sent only to the request's `from` (MBX-081). | None |
| MBX-6 host reorders or withholds events | Per-task `seq`, held out-of-order events, cursor resubscribe (PROF-028, MBX-091), events kept in the log (MBX-082). | Withholding delays, never loses, while the responder is reachable. |
| MBX-7, DOS-4, G4 mailbox flooding | Deposit tokens issued by the recipient's owner, bound to a deposit key, with quotas per token and per registration (§4, §7). Duplicates cost no quota (MBX-042). | A token holder can fill its own quota. An intercepted invite gives its quota to the interceptor (ID-4). |
| REL-3 selective relay DoS | Several hosts, direct retries, jittered backoff (§9). | As in the threat model. |
| G15 resource limits | Ordered checks, cheapest first, before hashing the body (§7). `MAX_DEPOSIT_AUTH_BYTES`, `MAX_HOSTS`, `LEASE_MAX`, `MAX_DEPOSIT_TTL`. Reasons go to the audit log only. | Per-node connection limits are the binding's. |
| Prompt injection (§4.7.4) | Nothing in this extension reads content. Taint travels in the signed `prov` and is unchanged by storage. Host lists and tokens never come from content (MBX-003, MBX-013). | — |

A host learns, per recipient, who deposits (by deposit key), when and how much, and keeps tombstones until
`exp + SKEW`. Owners who care run their own host (DD Q7 (a)).

## 16. Open issues

1. **Binding: extension methods.** `#Register` needs `rpc.method` to be an extension operation, which BIND-014
   (A2A method names only) does not allow yet. Proposed fix: allow `<extension URI>#<name>` for extensions that are
   active for the request.
2. **Capability: `cap.mailbox` and deposit tokens.** `ext/capability.md` §5.8 should list the `mailbox` member, §5.2
   the `mailbox:<host agent>#register` operation, and §8.1 should point to §4.4 here for the `deposit` claim. The
   deposit token is a third token role (`webway("mailbox/v0", "deposit")`) next to access tokens and mandates; its
   format is defined here because it needs no holder chain.
3. **Sibling inconsistencies** to settle in review: `exp − ts` above `MAX_TTL` is `EnvelopeInvalid` in ENV-011 but
   `EnvelopeExpired` in profile §10.3, and ENV-011 caps answers at `MAX_TTL` while PROF-076 allows `MAX_TTL + SKEW`.
   This document stays out of it by admitting up to `MAX_TTL + SKEW` at hosts (§7 step 6) and leaving the final
   check to the recipient.
4. **Receipts.** A sender that wants proof of delivery, not just a state, needs `ext/audit.md` receipts.
5. **Host-to-host forwarding** (a host relaying to another host) is not defined. A recipient that changes hosts
   re-registers and declares the new host; envelopes held at the old host are delivered when the node connects to
   it, or expire.
6. **Documents on other branches.** `profile.md`, `binding-webway-quic.md` (issue #5), `ext/envelope.md` (#3),
   `ext/capability.md` (#4), `docs/threat-model.md` (#6), `conventions.md` and the vector format (#7). Links
   resolve once those land.

[Biscuit]: https://doc.biscuitsec.org/reference/specifications
