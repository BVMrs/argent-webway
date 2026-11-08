# Extension `capability/v0`: identities, owner bindings, capability tokens, invites, revocation

Status: **draft v0**, for review. Date: 2026-11-07. Roadmap track T3.
Extension URI: `https://github.com/BVMrs/argent-webway/ext/capability/v0` ([Q6](../../docs/due-diligence.md#q6-namespace-and-governance) (b)).
Requirement prefix: `CAP` ([conventions](../conventions.md)).

Inputs: due diligence [§4.2](../../docs/due-diligence.md#42-identity-and-discovery),
[§4.7.1](../../docs/due-diligence.md#471-authentication), [§4.7.2](../../docs/due-diligence.md#472-authorisation-per-capability),
[Q3](../../docs/due-diligence.md#q3-human-readable-identity-binding), [Q4](../../docs/due-diligence.md#q4-capability-token-format),
and the threat model (`docs/threat-model.md`, issue #6) gaps assigned to T3: G2 (domain separation), G4 (deposit
token in invites), G10 (a) (mandates on cross-owner sub-delegation), G11 (revocation freshness, pre-rotation),
G15 (limits), G16 (invites, card versions), G19 (issuing keys), and open items ID-1, META-6, PEER-7.

Test vectors: [`conformance/vectors/capability/`](../../conformance/vectors/capability/) and
[`conformance/vectors/identity/`](../../conformance/vectors/identity/), generated and checked by the reference
model in [`conformance/tools/capgen/`](../../conformance/tools/capgen/) (§12).

**Summary.** Every principal is an Ed25519 key. An owner's offline **root key** certifies, with short signed
**statements** (JWS over JCS), the owner's nodes, agents and per-node online **issuing keys**. An issuing key is the
root of **Biscuit** capability tokens. A request carries an **access** token rooted in the *resource owner's*
issuing key, and, when it acts for someone else (S4), a **mandate** rooted in the *principal's* issuing key. Both
are bound to the presenting agent through a **holder chain** of third-party blocks, so only the last holder can use
a token and every re-delegation hop is signed by the hop that made it. Trust in an owner comes only from a
**pin**, made out of band, usually from an **invite**. Revocation uses **signed revocation lists** with sequence
numbers and a freshness rule that fails closed for long-lived tokens.

---

## Contents

1. [Model](#1-model)
2. [Constants and errors](#2-constants-and-errors)
3. [Identifiers and keys](#3-identifiers-and-keys)
4. [Signed statements](#4-signed-statements)
5. [Capability tokens](#5-capability-tokens)
6. [Authorisation algorithm](#6-authorisation-algorithm)
7. [Mandates: acting on behalf of someone (S4)](#7-mandates-acting-on-behalf-of-someone-s4)
8. [Invites](#8-invites)
9. [Revocation](#9-revocation)
10. [Obligations of issuers and senders](#10-obligations-of-issuers-and-senders)
11. [Security and privacy considerations](#11-security-and-privacy-considerations)
12. [Conformance](#12-conformance)
13. [Changes from the due diligence, and open questions](#13-changes-from-the-due-diligence-and-open-questions)

---

## 1. Model

```
 owner root key (offline)  ── owner-key events (rotation, pre-rotation commitment)
   │ signs statements
   ├── node-cert ─────────► node key  (wwn:…, also the QUIC identity)
   ├── issuer-cert ───────► issuing key (wwi:…, online, one per node, scoped, ≤ 30 days)
   │                           │ signs
   │                           ├── Biscuit authority blocks: access tokens and mandates
   │                           ├── agent-certs (if scoped), Agent Card signatures, invites, revocation lists
   └── agent-cert ────────► agent key (wwa:…, held by its node)
                               │ signs
                               ├── envelopes (envelope/v0)
                               └── Biscuit third-party "holder blocks" (re-delegation)
```

- **Who trusts what.** A verifier trusts an owner only if it holds a **pin** for the owner (§4.9). Everything
  else is accepted only through a chain of statements that ends at a pinned owner's root key: an issuing key
  through its issuer-cert, an agent through its agent-cert, a token through its issuing key.
- **Two token roles.** An **access** token says what its holder may do at a resource. It is rooted in the issuing
  key of the *resource owner* (the owner of the agent receiving the request). A **mandate** says that its holder
  acts for a *principal* agent, within limits the principal's owner set. It is rooted in the principal's owner's
  issuing key. A mandate grants nothing alone (§7).
- **Holder binding.** A token names its first holder. Each re-delegation appends a block signed by the current
  holder's agent key that names the next holder. The verifier walks this chain in code and allows only the last
  holder, proven by the envelope signature, to present the token (§5.5).
- **No ambient trust.** Being on the overlay, on the same LAN, behind the same relay, or under the same owner
  grants nothing. Every request is authorised by a token, except the follow-ups on a task by the agent that
  created it (§6.4).

## 2. Constants and errors

### 2.1 Constants

| Name | Value | Meaning |
|---|---|---|
| `SKEW` | from `envelope/v0` (5 minutes) | Clock tolerance for `iat` checks. Token expiry has no tolerance (§5.4). |
| `MAX_TOKEN_BYTES` | 8192 | Largest serialised Biscuit, after base64url decoding. |
| `MAX_BLOCKS` | 16 | Most blocks in one token, authority included. |
| `MAX_HOLDER_DEPTH` | 4 | Highest holder depth. A token has at most 5 holders: the first and 4 re-delegations. |
| `MAX_FACTS`, `MAX_ITERATIONS`, `MAX_TIME` | 1000, 100, 5 ms | Datalog run limits per authorisation (the `biscuit-rust` defaults, `MAX_TIME` raised from 1 ms). |
| `MAX_ACCESS_TTL` | 30 days | Largest `expires − issued` of an access token. |
| `MAX_MANDATE_TTL` | 24 hours | Largest `expires − issued` of a mandate. |
| `REVOCATION_EXEMPT_TTL` | 1 hour | Tokens with `expires − issued` at most this need no fresh revocation list (§9.3). |
| `MAX_LIST_VALIDITY` | 24 hours | Largest `validUntil − iat` of a revocation list signed by an issuing key. |
| `MAX_ISSUER_CERT_TTL` | 30 days | Largest `exp − iat` of an issuer-cert. Also the largest validity of a root-signed revocation list. |
| `MAX_CERT_TTL` | 400 days | Largest `exp − iat` of a node-cert or agent-cert signed by a root key. |
| `MAX_INVITE_TTL` | 7 days | Largest `exp − iat` of an invite. The default is 24 hours. |
| `MAX_STATEMENT_BYTES` | 16384 | Largest signed statement (JSON text of the JWS object). |

These limits close part of threat-model gap G15 for this extension. Exceeding any of them is `CapabilityInvalid`
or `StatementInvalid`.

### 2.2 Errors

The error names below are registered by the profile in the argent-webway error range, with A2A-style codes. A
peer receives only the name, `retryable` and `retryAfter`. The detailed reason (which check, which block) goes to
the local audit log only (G15).

| Name | Retryable | When |
|---|---|---|
| `IdentifierInvalid` | no | A `wwa:`, `wwn:`, `wwi:` or `did:key:` identifier does not parse (§3). |
| `StatementInvalid` | no | A statement is malformed, has the wrong `typ`, a bad signature, or breaks a limit. |
| `StatementUntrusted` | no | A statement is well-formed and validly signed, but its chain does not end at a pinned owner key, or its signer lacks the scope. |
| `StatementExpired` | no | A statement is outside its validity period. |
| `StatementRevoked` | no | A statement is listed in a verified revocation list. |
| `CapabilityMissing` | no | The operation needs a token and none was sent. |
| `CapabilityInvalid` | no | A token cannot be verified: encoding, signature, unknown or unscoped issuer, schema, limits, broken holder chain. |
| `CapabilityDenied` | no | A token verifies but does not authorise this request: expired, presenter is not the current holder, capability or operation not granted, a check failed, a required mandate is missing. |
| `CapabilityRevoked` | no | A block of the token, or the certificate of its issuer, is revoked. |
| `RevocationStatusUnavailable` | **yes** | A long-lived token needs a fresh revocation list and the verifier has none (§9.3). `retryAfter` is a hint. The sender can staple a fresh list. |
| `InviteInvalid` | no | An invite is malformed, badly signed, or inconsistent (§8). |
| `InviteExpired` | no | An invite is past its `exp`. |
| `InviteConsumed` | no | A single-use invite has already been redeemed (§8.4). |
| `MandateRequired` | no | Local only, never on the wire: a node refuses to send a request that needs a mandate it does not hold (CAP-186). |

## 3. Identifiers and keys

All keys are Ed25519 ([RFC 8032]). Identifiers are self-certifying: the public key is in the identifier.

| Principal | Form | Example |
|---|---|---|
| Owner | `did:key:z` + base58btc(`0xed 0x01` ‖ 32-byte key) ([did:key]) | `did:key:z6Mk…` |
| Issuing key | `wwi:` + base32(32-byte key) | `wwi:` + 52 characters |
| Node | `wwn:` + base32(32-byte key) | `wwn:` + 52 characters |
| Agent | `wwa:` + base32(32-byte key) | `wwa:` + 52 characters |

base32 is [RFC 4648] §6, lowercase alphabet `a–z2–7`, no padding.

- [CAP-001] A receiver MUST reject an identifier that is not exactly one of the four forms: wrong prefix, wrong
  length, characters outside the alphabet (including uppercase in `wwa:`/`wwn:`/`wwi:`), padding, non-canonical
  base32 (non-zero trailing bits), a `did:key` whose multicodec prefix is not `0xed 0x01` or whose key is not 32
  bytes. The error is `IdentifierInvalid`, or the error of the enclosing object.
- [CAP-002] A verifier MUST verify every Ed25519 signature defined in this document with the strict rules of
  `ed25519-dalek`'s `verify_strict`: reject `S ≥ L`, reject non-canonical or small-order encodings of the public
  key `A` and of `R`, and use the cofactorless equation `[S]B = R + [k]A`. Identifiers whose key is a small-order
  point are invalid (CAP-001 applies). This is the common rule threat-model RPL-10 asks for.
- [CAP-003] An implementation MUST use each key in one role only (owner root, issuing, node, agent, invite key,
  deposit key) and MUST NOT sign with an agent key anything other than envelopes and Biscuit holder blocks, or
  with an issuing key anything other than Biscuit authority blocks and the statements of §4 its scope allows.
  The signed byte strings of the three formats cannot collide: JWS signing inputs start with `eyJ` (base64url of
  `{"`), envelope signing inputs start with `{`, and Biscuit signs binary payloads that start with a block
  protobuf or the external-signature prefix. Together with `typ` (CAP-012) this is the domain separation G2 asks
  for, inside this extension.
- The node key is also the QUIC TLS identity ([§4.3](../../docs/due-diligence.md#43-transports-and-nat-traversal)).
  That is its role. It signs no statement and no token.

## 4. Signed statements

A **statement** is a signed claim about keys: owner key events, certificates, revocation lists, invites. It uses
the JWS flattened JSON serialisation ([RFC 7515] §7.2.2) with a JCS payload ([RFC 8785]), the same building blocks
as A2A Agent Card signatures.

### 4.1 Format

```json
{
  "protected": "<base64url(JCS(header))>",
  "payload":   "<base64url(JCS(claims))>",
  "signature": "<base64url(Ed25519(signer, ASCII(protected || '.' || payload)))>"
}
```

- `header` is exactly `{"alg": "EdDSA", "kid": <signer identifier>, "typ": <statement type>}`.
- `claims` is a JSON object. Common members: `iss` (the signer identifier, equal to `kid`), `iat` and, unless the
  type says otherwise, `exp`. Times are RFC 3339 UTC with `Z` and whole seconds (`2026-11-07T12:00:00Z`).
- base64url is [RFC 4648] §5 without padding.

Statement types:

| `typ` | Signed by | Section |
|---|---|---|
| `webway-owner-key+jws` | the owner's new root key | §4.3 |
| `webway-node-cert+jws` | owner root key | §4.4 |
| `webway-issuer-cert+jws` | owner root key | §4.5 |
| `webway-agent-cert+jws` | owner root key, or an issuing key with `agentCerts` scope | §4.6 |
| `webway-revocation+jws` | owner root key, or an issuing key | §9 |
| `webway-invite+jws` | an issuing key with `invites` scope | §8 |

The **statement ID** is `b3:` + base64url(BLAKE3(ASCII(protected || '.' || payload))). Revocation lists refer to
statements by this ID.

### 4.2 Verification

A verifier verifies a statement *as* an expected type, with a time `now`, its pins (§4.9) and the verified
revocation lists it holds (§9).

- [CAP-010] A verifier MUST reject as `StatementInvalid` a statement that is larger than `MAX_STATEMENT_BYTES`, is
  not a JSON object with exactly the members `protected`, `payload` and `signature` (strings), whose header or
  claims are not I-JSON objects, whose decoded header or claims bytes are not exactly their JCS form, whose header
  has members other than `alg`, `kid` and `typ`, whose `alg` is not `EdDSA`, whose `kid` is not a valid
  identifier, or whose claims `iss` differs from `kid`.
- [CAP-011] A verifier MUST verify the signature over `ASCII(protected || '.' || payload)` with the key in `kid`
  (CAP-002) and reject a failure as `StatementInvalid`.
- [CAP-012] A verifier MUST reject as `StatementInvalid` a statement whose `typ` is not the type it expects at that
  point. A node-cert is never accepted as an agent-cert, an invite is never accepted as a revocation list, and so
  on (domain separation, threat model G2 and RPL-7).
- [CAP-013] A verifier MUST accept a statement only if its signer is authorised for that type: the current root key
  of a pinned owner (§4.3), or an issuing key whose issuer-cert verifies (§4.5) and has the needed scope, and only
  for the owner named in the claims `owner`. Otherwise the error is `StatementUntrusted`.
- [CAP-014] A verifier MUST reject as `StatementExpired` a statement with `iat > now + SKEW` or `now > exp`, and as
  `StatementInvalid` one whose `exp − iat` exceeds the limit for its type (§2.1). A statement signed by an issuing
  key MUST also lie inside the issuer-cert's validity (`exp` not later than the issuer-cert's `exp`), else
  `StatementInvalid`.
- [CAP-015] A verifier MUST reject as `StatementRevoked` a statement whose ID, or the ID of any statement in its
  chain, appears in a verified revocation list of the same owner (§9).

### 4.3 Owner keys, rotation and pre-rotation

An owner is identified by the `did:key` of its **inception key**, the first root key. The owner identifier never
changes. Rotation changes the current root key behind it, as in KERI or `did:plc`, and closes threat-model gap
G11 (b).

Claims of `webway-owner-key+jws`:

| Member | Meaning |
|---|---|
| `owner` | The owner identifier (the inception key's `did:key`). |
| `seq` | 0 for inception, then +1 per rotation. |
| `key` | The root key this event establishes, as `did:key`. Equal to `iss`. For `seq` 0, equal to `owner`. |
| `prev` | For `seq` > 0: the statement ID of the previous event. Absent for `seq` 0. |
| `next` | Optional. `b3:` + base64url(BLAKE3(next root public key, 32 bytes)): the **pre-rotation commitment**. |
| `compromised` | Optional, `seq` > 0 only. `true` means every earlier root key is treated as compromised. |
| `iat` | Time of the event. No `exp`: key events do not expire. |

- [CAP-020] A verifier MUST accept a rotation event (`seq` = n+1) only if it is signed by the key it establishes,
  `prev` is the ID of the event `seq` = n it holds, and the previous event's `next` equals the commitment computed
  from `key`. An event that fails any check, or a rotation from an event without `next`, is rejected
  (`StatementUntrusted`) and does not change the pin. A thief of the current root key cannot rotate, because it
  does not know the committed next key.
- [CAP-021] After a verified rotation, a verifier MUST treat only the new key as the owner's current root key for
  new statements. Statements signed earlier by an older root key stay valid until their own `exp`, unless the
  rotation has `compromised: true`, in which case the verifier MUST reject every statement signed by an older root
  key (`StatementUntrusted`), and the owner must reissue its certificates.
- Owners SHOULD always include `next` and keep the next key offline and separate from the current key. An owner
  without a commitment can only rotate by asking every peer to re-pin out of band.
- Recovery when the next key is lost or both keys are stolen is out of scope for v0.

### 4.4 Node certificates

Claims of `webway-node-cert+jws`: `owner`, `node` (`wwn:`), `iat`, `exp` (at most `MAX_CERT_TTL` after `iat`).

- A node-cert binds the QUIC identity of a node to its owner. The binding spec uses it to check that the node at
  the other end of a connection belongs to the owner of the agent in `from` or `to` (threat-model REL-2).

### 4.5 Issuer certificates and scopes (G19)

The root key is offline, but tokens are minted online by node code. The **issuing key** is the online key that
does it. There is one per node (or per owner per machine), certified by the root key with a short validity and a
scope, so a compromised node can mint only inside that scope until the certificate expires or is revoked.

Claims of `webway-issuer-cert+jws`:

```json
{
  "iss": "did:key:z6Mk…owner-root",
  "owner": "did:key:z6Mk…owner",
  "issuer": "wwi:…",
  "node": "wwn:…",
  "iat": "2026-11-01T00:00:00Z",
  "exp": "2026-11-30T00:00:00Z",
  "scope": {
    "resource": ["skill:*", "blob:*", "task:*", "mailbox:*", "invite:*"],
    "mandate": { "targets": ["*"], "capabilities": ["skill:*"], "maxTtl": 3600 },
    "agentCerts": true,
    "cards": true,
    "invites": true
  }
}
```

| Scope member | Meaning |
|---|---|
| `resource` | Capability patterns (§5.2) this key may grant in **access** tokens. A pattern is a capability name, or a prefix ending in `*`. Empty or absent: no access tokens. |
| `mandate` | Absent or `null`: no mandates. Otherwise: `targets` (resource owners the mandate may name, or `["*"]`), `capabilities` (patterns), `maxTtl` (seconds, at most `MAX_MANDATE_TTL`). |
| `agentCerts` | May sign agent-certs for agents on `node`. |
| `cards` | May sign Agent Cards of agents on `node`. |
| `invites` | May sign invites. |

- [CAP-030] A verifier MUST accept a token rooted in an issuing key only if the issuer-cert verifies as
  `webway-issuer-cert+jws` (§4.2) for the owner the token's role requires (§6, §7), is valid at `now`, and its
  scope covers the token: for an access token, every `right` in the authority block matches a `resource` pattern;
  for a mandate, `mandate` is present, every `grant` names a target in `targets` (or `targets` is `["*"]`) and a
  capability matching `capabilities`, and `expires − issued ≤ maxTtl`. Otherwise `CapabilityInvalid`.
- [CAP-031] A verifier MUST accept a mandate only if its `principal` agent has an agent-cert of the mandate's
  owner whose `node` equals the issuer-cert's `node`. An issuing key on node N can speak for the agents certified
  to N, and for no other agents of the owner. Otherwise `CapabilityInvalid`.
- An issuer-cert's `exp − iat` is at most `MAX_ISSUER_CERT_TTL`. Owners renew it from the offline root key, for
  example monthly. Owners who delegate across owners rarely SHOULD issue issuer-certs without `mandate`.

### 4.6 Agent certificates

Claims of `webway-agent-cert+jws`: `owner`, `agent` (`wwa:`), `node` (`wwn:`, the node holding the agent key),
`iat`, `exp`.

- [CAP-040] A verifier MUST accept an agent-cert signed by an issuing key only if that key's issuer-cert has
  `agentCerts: true` and the same `node` as the agent-cert. Otherwise `StatementUntrusted`.
- [CAP-041] A receiver MUST determine the owner of an envelope's verified `from` agent only from a valid agent-cert
  of that agent (§4.2). An agent without one, or whose agent-cert chain does not end at a pinned owner or the
  receiver's own owner, is unauthenticated: its requests fail with `CapabilityDenied` regardless of the tokens they
  carry, and its content is `unverified-origin` for `provenance/v0`.

### 4.7 Agent Card signatures

The profile requires Agent Cards to be signed (A2A 1.0 `AgentCardSignature`: a JWS over the JCS of the card without
`signatures`).

- [CAP-050] A card signature MUST be made by the owner root key, or by an issuing key with `cards: true` whose
  issuer-cert `node` hosts the card's agents, and its protected header MUST carry `kid` (the signer identifier),
  `wwseq` (a non-negative integer, increased on every change) and `wwexp` (RFC 3339, at most 30 days after
  signing). A receiver MUST reject a card whose signature does not verify through this chain, which has expired,
  or whose `wwseq` is lower than the highest it has seen for the same agent (a stale card served again, G16).
  Vanilla A2A verifiers ignore the extra header parameters.

### 4.8 What a verifier stores

Per pinned owner: the owner identifier, the latest verified owner-key event (current root key, `next`), and the
petname. Per issuing key: the latest verified issuer-cert. Per owner and signer: the revocation list with the
highest `seq`. Per agent: the highest card `wwseq`. Per token authority block: a call counter (§5.6).

### 4.9 Pins and name bindings (Q3)

A **pin** says "I trust owner O": the owner identifier, optionally the current owner-key event, a petname and where
the pin came from (invite, manual, directory).

- [CAP-060] A node MUST create or change a pin only through an explicit local action: the owner accepting an invite
  (§8.3), an operator command, or local configuration. Receiving a statement, a card or an envelope MUST NOT create
  a pin.
- [CAP-061] A name binding (`did:web`, DNS TXT, ANP `did:wba`, T17) MUST NOT override or replace an existing pin. A
  binding that maps a name to a key other than the pinned one is reported as a conflict and ignored. First contact
  by name alone is trust on first use and needs the same explicit local action as CAP-060 (threat-model ID-1).
- v0 (M1) uses pins only, as Q3 (a) recommends. Name bindings arrive with T17.

## 5. Capability tokens

### 5.1 Biscuit profile

Tokens are [Biscuit] v3 tokens, as implemented by `biscuit-auth` 6.0 ([biscuit-rust]).

- [CAP-100] A verifier MUST reject as `CapabilityInvalid` a token that is not a base64url string (no padding) of
  a serialised Biscuit, that is larger than `MAX_TOKEN_BYTES` decoded or has more than `MAX_BLOCKS` blocks, that uses
  any algorithm other than Ed25519 for its root, block, next or external keys, whose block versions are outside
  what `biscuit-auth` 6.0 accepts, or whose third-party blocks use an external-signature version other than 1.
  Version 1 external signatures cover the previous block's signature, so a holder block cannot be cut out of one
  token and pasted into another.
- [CAP-101] A verifier MUST run the Datalog of one authorisation with at most `MAX_FACTS` facts and
  `MAX_ITERATIONS` iterations and SHOULD stop it after `MAX_TIME`. Hitting a limit is `CapabilityInvalid`.
- The Biscuit `root_key_id` is not used. The root key is found from the `issuer` fact (§5.4).
- Sealed tokens are allowed. A sealed token can no longer be attenuated or re-delegated.

### 5.2 Capability names

A capability is a string `<kind>:<name>` with an optional `#<operation>`:

| Capability | Allows these operations | Defined by |
|---|---|---|
| `skill:<skill-id>` | `SendMessage`, `SendStreamingMessage` (create a task for that skill, or continue it) | this document, the profile |
| `task:<task-id>#read` | `GetTask`, `SubscribeToTask` | this document |
| `task:<task-id>#cancel` | `CancelTask` | this document |
| `blob:<hash>#read` | blob fetch | `blob/v0` |
| `doc:<doc-id>#read`, `doc:<doc-id>#append` | shared-doc sync and append | `shared-doc/v0` |
| `mailbox:<agent>#deposit` | mailbox deposit | `mailbox/v0` |
| `invite:<invite-id>#redeem` | `InviteRedeem` (§8.4) | this document |

`<skill-id>` is the A2A `AgentSkill.id` from the recipient's card. Names are case-sensitive and contain no spaces.

- [CAP-102] A verifier MUST reject as `CapabilityDenied` a request whose operation is not one the requested
  capability allows according to this table (or the extension that defines the capability kind).
- The requested capability is carried in the envelope (§5.8). The node routes the request to that skill only, so
  the receiving agent cannot be talked into running a different skill under the same token.

### 5.3 Datalog vocabulary

**Token facts** are written by the issuer in the authority block (and the holder fact by holder blocks):

| Fact | Where | Meaning |
|---|---|---|
| `webway("capability/v0", $role)` | authority | `$role` is `"access"` or `"mandate"`. Exactly one. |
| `issuer($wwi)` | authority | The issuing key that signed the authority block. Exactly one. |
| `owner($did)` | authority | The issuing key's owner. Exactly one. |
| `issued($date)`, `expires($date)` | authority | Validity. Exactly one each. |
| `holder($wwa, $depth)` | authority (depth 0), holder blocks (depth ≥ 1) | The holder chain (§5.5). |
| `right($capability)` | authority of access tokens | A granted capability. One or more. |
| `principal($wwa)` | authority of mandates | The agent on whose behalf the holder acts. Exactly one. |
| `grant($did, $capability)` | authority of mandates | The holder may, for the principal, use `$capability` at resources of owner `$did`. One or more. |
| `origin_task($id)` | authority of mandates, optional | The principal's task this mandate serves (audit only). |

**Request facts** are added by the verifier's node code (the "authorizer facts"). The token cannot set them:

| Fact | Value |
|---|---|
| `time($date)` | The verifier's current time. |
| `presenter($wwa)` | The envelope's verified `from`. |
| `current_holder($wwa)` | The last holder, from the holder-chain walk (§5.5). |
| `resource_owner($did)` | The verifier's own owner (the owner of the recipient agent). |
| `node($wwn)`, `recipient($wwa)` | The verifier's node and the envelope's `to`. |
| `operation($name)`, `capability($c)` | The A2A method and the requested capability. |
| `task($id)`, `context($id)` | The A2A task and context IDs, when the request has them. |
| `arg($name, $value)` | One per scalar argument in the request (§5.8). |
| `calls($n)` | How many requests this token's authority block has already authorised at this verifier (§5.6). |
| `mandate_principal($wwa)`, `mandate_owner($did)`, `mandate_depth($n)` | Only when a mandate was verified (§7): its principal, the principal's owner, and its last holder depth. |

- [CAP-103] A verifier MUST reject as `CapabilityInvalid` a token in which any block has a fact, or a rule whose
  head, uses a request-fact predicate (`time`, `presenter`, `current_holder`, `resource_owner`, `node`,
  `recipient`, `operation`, `capability`, `task`, `context`, `arg`, `calls`, `mandate_principal`, `mandate_owner`,
  `mandate_depth`). Biscuit already keeps facts of later blocks away from the authority block and the verifier's
  policies, but the authority block's own facts are trusted, so without this rule an issuer bug could pre-set a
  request fact.
- [CAP-104] A verifier MUST reject as `CapabilityInvalid` a token whose authority block does not have exactly one
  each of `webway`, `issuer`, `owner`, `issued`, `expires` and `holder(_, 0)`, and the role's facts (at least one
  `right` for access, exactly one `principal` and at least one `grant` for a mandate), or in which `issuer` is not
  the key that signed the authority block.

### 5.4 Access tokens

An access token is minted by the resource owner's issuing key, usually on the node that hosts the resource:

```datalog
// authority block, signed by wwi:<C's issuing key>
webway("capability/v0", "access");
issuer("wwi:…C-issuer");
owner("did:key:z6Mk…C");
issued(2026-11-07T12:00:00Z);
expires(2026-11-07T13:00:00Z);
right("skill:run-tests");
holder("wwa:…B-agent", 0);
check if presenter($k), current_holder($k);
check if time($t), $t <= 2026-11-07T13:00:00Z;
```

- [CAP-110] A verifier MUST accept an access token only if its `owner` is the verifier's own owner and its issuing
  key has a valid issuer-cert of that owner whose `resource` scope covers every `right` (CAP-030). Otherwise
  `CapabilityInvalid`. A token from another owner never grants access here, whatever it says.
- [CAP-111] A verifier MUST reject as `CapabilityInvalid` a token with `expires − issued` above the role's limit
  (`MAX_ACCESS_TTL`, `MAX_MANDATE_TTL`) or with `issued > now + SKEW`, and as `CapabilityDenied` a token with
  `now > expires`. There is no tolerance on `expires`: access tokens are checked by the owner that issued them,
  so issuer and verifier share a clock source. Mandate issuers SHOULD leave a margin for skew.
- The two checks in the example are what an issuer SHOULD write. The verifier enforces the presenter binding and
  `expires` in code (§6) whether the checks are there or not, so a missing check cannot widen a token.

Allow policy the verifier runs for an access token (local owner policy goes before it, §5.9):

```datalog
allow if webway("capability/v0", "access"), right($c), capability($c);
deny if true;
```

### 5.5 Holder chain and re-delegation

- The authority block names the first holder: `holder("wwa:…B", 0)`.
- **Re-delegating** from the current holder H (depth n) to agent K means appending a **third-party block** whose
  external signature is made by H's agent key. It contains exactly one `holder("wwa:…K", n+1)` fact and any number
  of attenuating checks. In `biscuit-rust`: `token.third_party_request()`, then
  `request.create_block(&H_private, block)`, then `token.append_third_party(H_public, signed_block)`.
- **Attenuating without re-delegating** means appending an ordinary block (ephemeral key), with checks only.
  Anyone holding the bytes can do this, and it can only narrow the token.

The verifier walks the chain in node code, before any Datalog runs:

- [CAP-120] A verifier MUST compute the holder chain as follows, and reject as `CapabilityInvalid` on any
  failure: start with the depth-0 holder from the authority block. For each later block in order: if the block has
  an external key, that key MUST equal the key of the current holder, and the block MUST assert exactly one
  `holder` fact, whose depth is the current depth + 1 and whose agent is a valid `wwa:` identifier not already in
  the chain; that agent becomes the current holder. If the block has no external key, it MUST NOT assert any
  `holder` fact. The depth MUST NOT exceed `MAX_HOLDER_DEPTH`.
- [CAP-121] A verifier MUST reject as `CapabilityDenied` a token whose current holder (the last one in the chain)
  is not the envelope's verified `from`. Earlier holders cannot present the token, even though they once held it.
- In v0 every third-party block is a holder block. Gaps and forks inside one token cannot happen: depths are
  consecutive and each block extends the last holder. A holder MAY give out several tokens from the same prefix
  (to K1 and to K2); they are separate tokens that share a call counter (§5.6) and revocation IDs.
- Because Biscuit blocks only add checks, each hop's token is at most as wide as the one before. The checks a
  holder adds in its own block are signed by it, so an audit can tell which hop narrowed what.

### 5.6 Caveats

Attenuating checks use the request facts. Common ones:

```datalog
check if time($t), $t <= 2026-11-07T12:30:00Z;          // shorter TTL
check if calls($n), $n < 5;                              // at most 5 uses
check if task($id), $id == "0190f1c2-…";                 // one task only
check if arg("repo", $r), $r == "github.com/acme/app";   // argument constraint
check if arg("suite", $s), ["unit", "lint"].contains($s);
check if operation($op), $op == "SendMessage";           // no streaming
check if mandate_owner("did:key:z6Mk…A");               // only on behalf of owner A (§7)
```

- [CAP-130] The verifier MUST set `calls($n)` to the number of requests it has already allowed with a token
  sharing this authority block (same authority revocation ID), counted by the resource owner's node that runs the
  check, and MUST increase the count in the same atomic step as the allowed operation's effect (for example, the
  task creation). Retries and duplicates answered from the dedupe store (`envelope/v0`) do not count again. This is
  the `max_calls` of threat-model PEER-7. All tokens derived from one authority block share the counter, so a
  holder cannot multiply its budget by forking.
- Arguments are only what §5.8 exposes. A skill whose arguments are not scalars cannot be constrained by argument
  caveats in v0. Issuers SHOULD then grant narrower skills.

### 5.7 Readability

A token is not encrypted. Every later holder, and every node that relays it before `envelope/v0` sealing (T15),
can read every block: rights, caveats, holder keys, the mandate principal and `origin_task`.

- [CAP-140] Issuers and holders MUST NOT put secrets in tokens (facts, rules, checks or the Biscuit `context`
  field). Closes threat-model META-6.

### 5.8 Carrying tokens: the envelope `cap` member

`envelope/v0` signs the header member `cap`. This extension defines its content:

```json
"cap": {
  "capability": "skill:run-tests",
  "access": "<base64url Biscuit>",
  "mandate": {
    "token": "<base64url Biscuit>",
    "issuerCert": { "protected": "…", "payload": "…", "signature": "…" },
    "principalCert": { "protected": "…", "payload": "…", "signature": "…" }
  },
  "onward": [ { "token": "…", "issuerCert": { … }, "principalCert": { … } } ],
  "revocations": [ { "protected": "…", "payload": "…", "signature": "…" } ]
}
```

| Member | Meaning |
|---|---|
| `capability` | The capability the request uses. Required on requests that need authorisation. |
| `access` | The access token, rooted in the recipient's owner. |
| `mandate` | Optional. The mandate the presenter acts under, with the statements a verifier of another owner needs (§7). |
| `onward` | Optional. Mandates whose **current holder is the recipient**, given to it for sub-delegation (§7.2). The recipient does not verify them as authorisation for this request. |
| `revocations` | Optional. Revocation lists stapled by the sender (§9.4). |

Arguments: when a skill takes structured arguments, the request `Message` carries them in
`metadata["https://github.com/BVMrs/argent-webway/ext/capability/v0"].args`, a JSON object. The node makes one
`arg($name, $value)` fact per member whose value is a string, a boolean, or an integer within ±2^53, and passes
exactly this object to the agent as the skill input.

- [CAP-150] A node MUST pass to the receiving agent, as the skill input, exactly the `args` object the
  authorisation saw, and MUST NOT run the request under a skill other than the one named by `cap.capability`.
- [CAP-151] Tokens MUST NOT appear anywhere except in `cap` and in invites (§8). A node MUST NOT put a token, a
  mandate or an invite into message text, Parts or artefacts, and MUST NOT give one to an agent's model context.
  Tokens are handled by node code only (DD §4.7.2 "No in-band credentials", A2A §7.6.3).

### 5.9 Local owner policy

The owner of the verifying node can add Datalog that runs in the same authoriser, before the allow policy: checks
(must all pass) and `deny if` policies (match first). Examples:

```datalog
// Never from owner X.
deny if presenter($p), mandate_owner("did:key:z6Mk…X");
// skill:deploy only on behalf of our own owner (no foreign principal).
deny if capability("skill:deploy"), mandate_owner($o), $o != "did:key:z6Mk…C";
// Foreign-tainted tasks may not use side-effecting skills (provenance/v0 adds the taint fact).
```

Local policy is configuration, not wire format. Conformance vectors carry it as `verifier.policy`.

## 6. Authorisation algorithm

### 6.1 Inputs

A verified envelope (signature, freshness, `to`, dedupe: `envelope/v0`), so `from` (the presenter) and `cap` are
authentic. The request's operation, task and context IDs, and arguments. The verifier's time `now`, its owner,
node, pins, issuer-certs of its own owner, held revocation lists, call counters and local policy.

### 6.2 Steps

The steps run in this order, cheapest first (G15). The first failure decides the error.

0. **Follow-up.** If `cap.access` is absent and the request is a follow-up by the task's creator (§6.4), run
   only step 2 and step 6 (against the revocation IDs recorded with the task), then allow.
1. **Presence.** If the operation needs a token and `cap.access` is absent: `CapabilityMissing`.
2. **Presenter identity** (CAP-041): the `from` agent has a valid agent-cert of a pinned owner or of the
   verifier's own owner, else `CapabilityDenied`.
3. **Access token** (CAP-100, CAP-103, CAP-104, CAP-110, CAP-030): decode, check size, parse; read `issuer` and find
   that key's issuer-cert among the verifier owner's issuer-certs; verify the Biscuit signatures with it; check
   structure, role `access`, owner, scope. Then the TTL limits (CAP-111).
4. **Holder chain** (CAP-120).
5. **Expiry and presenter** (CAP-111, CAP-121).
6. **Revocation** (CAP-170, CAP-171), for the token's revocation IDs and its issuer-cert.
7. **Mandate**, if `cap.mandate` is present: §7.3, steps M1–M6. A mandate that is present and fails is an error
   for the whole request. It is never ignored.
8. **Operation** (CAP-102). For `invite:<id>#redeem`, an already consumed invite: `InviteConsumed` (CAP-203).
9. **Datalog** (CAP-101): one authoriser for the access token with the request facts (§5.3), including the mandate
   facts when step 7 verified a mandate, then the local policy, then the allow policy of §5.4. Any failed check
   or a matching deny policy: `CapabilityDenied`.
10. **Count** (CAP-130) and record (CAP-190).

- [CAP-160] A verifier MUST run all of these steps for every request that needs authorisation, in this order, and
  reject with the first failing step's error. It MUST deny by default: a request is allowed only if step 9
  reaches an `allow` policy.

### 6.3 Results

On allow, the node records the decision (CAP-190), binds the created task to the authorisation (§6.4), and runs
the request. On deny, the peer gets only the error name (§2.2).

### 6.4 Follow-up operations on a task

A task remembers the agent that created it and the authority revocation IDs of the access token (and mandate) that
created it.

- [CAP-161] A node MUST allow `GetTask`, `SubscribeToTask`, `CancelTask` and continuing `SendMessage` or
  `SendStreamingMessage` on a task to the agent that created it without a new token, as long as its agent-cert is
  still valid and none of the recorded revocation IDs has since been revoked (else `CapabilityRevoked`). Any other
  agent, and the creator on any other task, needs a token (`task:<id>#…` or the original skill capability) and
  goes through the full algorithm; without one the error is `CapabilityMissing`.

## 7. Mandates: acting on behalf of someone (S4)

### 7.1 The problem

A (owner OA) asks B (owner OB) to do a task. B needs C (owner OC) for part of it. B's access token at C says what B
may do at C. It says nothing about A. Without more, C cannot tell that B is acting for A, and B can use its own
rights at C for A's purposes (the confused deputy, threat-model DLG-1 to DLG-4). A **mandate** is A's side of the
story, rooted in OA, held by B:

```datalog
// mandate authority block, signed by wwi:<OA's issuing key on A's node>
webway("capability/v0", "mandate");
issuer("wwi:…A-issuer");
owner("did:key:z6Mk…OA");
issued(2026-11-07T12:00:00Z);
expires(2026-11-07T13:00:00Z);
principal("wwa:…A");
grant("did:key:z6Mk…OC", "skill:run-tests");
origin_task("0190f1c0-…");                 // A's task at B
holder("wwa:…B", 0);
check if presenter($k), current_holder($k);
check if calls($n), $n < 1;               // one use at C (DLG-2)
check if arg("repo", "github.com/acme/app");
```

C's request at the end carries two tokens, each bound to B by its holder chain:

- **access**: OC-rooted, `right("skill:run-tests")`, holder B.
- **mandate**: OA-rooted, `grant(OC, "skill:run-tests")`, holder B, principal A.

### 7.2 Handing mandates on

- A gives B the mandate in `cap.onward` of the request that creates A's task at B.
- If B needs to bring in C on its own, and C needs to call D for A's task, B re-delegates the mandate to C with a
  holder block (§5.5), possibly with narrower checks, and sends it to C in `cap.onward`. C presents it to D as
  `cap.mandate`. Each hop is identified by its signed holder block.

### 7.3 Verifying a mandate

Steps M1–M6 replace step 7 of §6.2. All failures are `CapabilityInvalid` unless stated.

- **M1.** `cap.mandate.issuerCert` verifies as `webway-issuer-cert+jws` of a **pinned owner** P (CAP-013, CAP-030),
  with a `mandate` scope. The token verifies with that issuing key, has role `mandate` and `owner` P (CAP-100,
  CAP-103, CAP-104).
- **M2.** `cap.mandate.principalCert` verifies as an agent-cert of P for the `principal` agent, on the issuer-cert's
  node (CAP-031).
- **M3.** The scope covers every `grant` and the TTL (CAP-030, CAP-111). Holder chain (CAP-120).
- **M4.** Expiry (`CapabilityDenied`), current holder = presenter = the access token's current holder
  (`CapabilityDenied`), revocation (`CapabilityRevoked` or `RevocationStatusUnavailable`).
- **M5.** A separate authoriser for the mandate with the same request facts (no mandate facts) and the allow
  policy below. Failure is `CapabilityDenied`.
- **M6.** Add `mandate_principal`, `mandate_owner` and `mandate_depth` to the access authoriser (§6.2 step 9).

```datalog
allow if webway("capability/v0", "mandate"), grant($o, $c), resource_owner($o), capability($c);
deny if true;
```

- [CAP-180] A verifier MUST verify a mandate present in `cap.mandate` with steps M1–M6 and reject the whole
  request if any step fails. It MUST NOT drop an invalid mandate and continue with the access token alone.
- [CAP-181] A verifier MUST NOT add `mandate_*` facts unless M1–M5 succeeded, and MUST NOT accept `cap.onward`
  tokens as authorisation for the request that carries them.
- [CAP-182] A verifier MUST require a mandate, and deny with `CapabilityDenied` if none is present, when its local
  policy says so for the capability, or when any block of the access token checks a `mandate_*` fact (this falls
  out of Datalog: the fact is missing, so the check fails).

**Requiring a mandate from C's side.** C's issuing key can mint B an access token usable *only on behalf of
owner A*, by adding `check if mandate_owner("did:key:z6Mk…OA")`. B then cannot use it for itself or for anyone
else. The token B uses for its own purposes has no such check. This is how C makes S4 explicit without global
policy.

### 7.4 What C has proven

When C allows the request, it has checked: B holds an OC-rooted right to the capability, B is the last holder of a
mandate rooted in OA's issuing key on the node that hosts A, the mandate names OC and the capability, every hop
between A and B is identified by its holder block, every hop only narrowed (by construction), and no block of
either token is revoked. C does not know that A's *model* intended the request; it knows that A's node authorised
it (threat-model DLG-8 stays partial).

## 8. Invites

An invite bootstraps a relationship between owners: who to pin, where to reach them, and the first capabilities
(M1 scenario step 1). It is a statement of type `webway-invite+jws`, signed by an issuing key with `invites: true`.

### 8.1 Claims

| Member | Meaning |
|---|---|
| `iss` | The issuing key (`wwi:`). |
| `owner` | The inviting owner's identifier, to pin. |
| `ownerKey` | Optional: the owner's latest owner-key event (§4.3), so the pin includes the pre-rotation commitment. |
| `issuerCert` | The issuer-cert of `iss`, signed by `owner`'s root key. |
| `id` | A UUIDv7. |
| `node` | The inviting node (`wwn:`). |
| `relays` | Relay URLs where the node can be reached (binding spec). |
| `agents` | Array of `{ "agent": "wwa:…", "cert": <agent-cert> }`. Cards are fetched later and checked (CAP-050). |
| `mode` | `"bound"` or `"redeem"` (§8.2). |
| `invitee` | `bound` mode only: the invitee's agent (`wwa:`), the first holder of every grant. |
| `inviteKey` | `redeem` mode only: the 32-byte Ed25519 private key seed of a fresh invite key, base64url. **Secret.** |
| `grants` | Array of base64url Biscuit access tokens, rooted in `iss`. |
| `deposit` | Optional: an initial mailbox deposit token and its key (threat-model G4). Format: `mailbox/v0`. |
| `iat`, `exp` | `exp − iat` at most `MAX_INVITE_TTL`. |

Transport form: the string `webway-invite:` followed by base64url of the JCS bytes of the JWS object. It fits in
a QR code when cards are left out. An invite is passed out of band (in person, a chat the two owners already
trust); that channel is what authenticates the inviting owner to the invitee.

### 8.2 Modes (G16, ID-4)

- **bound**: the invitee told the inviter its agent key beforehand. Every grant's depth-0 holder is `invitee`.
  An interceptor of the invite learns the grants but cannot present them.
- **redeem**: the inviter does not know the invitee's key yet (a QR code on a screen). `inviteKey` is a fresh key.
  `grants` holds exactly one token: `right("invite:<id>#redeem")` with holder the invite key, and no other right.
  The invitee re-delegates it to its own agent with a holder block signed by the invite key, then calls
  `InviteRedeem` (§8.4). The issuer answers with fresh grants bound to the invitee's agent.

- [CAP-200] An invite in `redeem` mode MUST have exactly one grant, whose only `right` is
  `invite:<id>#redeem` for the invite's own `id` and whose depth-0 holder is the public key of `inviteKey`. An
  invite in `bound` mode MUST NOT have `inviteKey`, and every grant's depth-0 holder MUST be `invitee`. An
  accepting node MUST reject an invite that breaks this (`InviteInvalid`), so an invite never carries a bearer
  capability for anything but its own redemption.

### 8.3 Accepting an invite

- [CAP-201] A node accepting an invite MUST: parse the transport form; verify the statement as
  `webway-invite+jws` (CAP-010 to CAP-012); verify `issuerCert` against `owner` as if `owner` were pinned, with
  `invites: true` and a validity that contains the invite's (else `InviteInvalid`); reject an invite past `exp`
  (`InviteExpired`); verify each agent-cert against the same chain; check that each grant verifies with `iss`, has
  role `access` and `owner` equal to the invite's `owner`, and satisfies CAP-200 (else `InviteInvalid`). In
  `bound` mode, the accepting agent MUST be `invitee` (else `InviteInvalid`).
- [CAP-202] A node MUST NOT pin `owner`, or store or use the invite's grants, before these checks pass and the
  local owner confirms (CAP-060). Then it pins `owner` (with `ownerKey` if present), stores the issuer-cert,
  agent-certs, relays and grants, and, in `redeem` mode, redeems. If `owner` is already pinned, the node MUST NOT
  replace the pinned owner-key state with an `ownerKey` whose `seq` is not higher (a rollback), and MUST treat a
  known petname offered for a different owner as a conflict for the owner to resolve, not as an update (CAP-061).

### 8.4 Redemption

`InviteRedeem` is a request to the inviting node's agent (any agent listed in `agents`), with
`cap.capability = "invite:<id>#redeem"` and `cap.access` = the redeem token re-delegated to the invitee's agent.
Its body carries the invitee's agent-cert and the issuer-cert that signs it, so the inviting node can pin the
invitee's owner after confirmation.

- [CAP-203] The inviting node MUST authorise `InviteRedeem` with the algorithm of §6 (the invitee's agent is the
  presenter, so its agent-cert is checked against the cert in the body, not a pin), and MUST allow each invite to
  be redeemed **once**: it records the invite `id` as consumed in the same atomic step as issuing the new grants,
  and answers any later redemption with `InviteConsumed`, unless it is a duplicate of the first redemption
  envelope, which gets the stored original response (`envelope/v0` dedupe).
- [CAP-204] If the inviting owner's policy asks for confirmation, the node MUST NOT issue grants before the owner
  confirms, after seeing the redeeming owner and agent. Confirmation is RECOMMENDED for invites shown in public
  places. An interceptor who redeems first gets the grants only if the owner confirms; the real invitee then gets
  `InviteConsumed` and knows the invite leaked.

## 9. Revocation

### 9.1 What can be revoked

- **Token blocks**, by Biscuit revocation ID (the block's signature, lowercase hex). Revoking a block revokes every
  token containing it: the authority block's ID revokes the token and everything derived from it; a holder block's
  ID revokes that delegation and what was derived from it after.
- **Statements**, by statement ID (`b3:…`): issuer-certs, agent-certs, node-certs, invites.

### 9.2 Revocation lists

A revocation list is a statement of type `webway-revocation+jws`:

```json
{
  "iss": "wwi:…", "owner": "did:key:z6Mk…",
  "seq": 42,
  "iat": "2026-11-07T12:00:00Z", "validUntil": "2026-11-08T12:00:00Z",
  "revoked": ["9f3c…(128 hex chars)", "b3:Qm9…"]
}
```

- `seq` increases with each new list from the same signer. A list is **complete**: it contains every revocation by
  that signer that has not yet expired. An entry may be dropped once everything it revokes has expired.
- A list signed by an issuing key may revoke tokens rooted in that key and statements that key signed.
  `validUntil − iat` is at most `MAX_LIST_VALIDITY`. The issuing node re-signs it at least daily, even when it does
  not change.
- A list signed by the owner's root key may revoke any token or statement of the owner, including issuer-certs.
  `validUntil − iat` is at most `MAX_ISSUER_CERT_TTL`. It is signed rarely (the key is offline).

- [CAP-170] A verifier MUST verify a revocation list as `webway-revocation+jws` (§4.2) and keep, per owner and
  signer, only the verified list with the highest `seq`. A list with a lower or equal `seq` than the one held
  MUST NOT replace it (rollback). A list signed by an issuing key MUST NOT revoke anything that key did not issue
  or sign; such entries are ignored.
- [CAP-171] A verifier MUST reject as `CapabilityRevoked` a token any of whose block revocation IDs, or whose
  issuer-cert's statement ID, appears in a list it holds from the token's issuing key or the token owner's root
  key, and MUST apply this to lists even after their `validUntil` (a stale list still proves what it lists).

### 9.3 Freshness (G11 (a))

- [CAP-172] For a token with `expires − issued > REVOCATION_EXEMPT_TTL`, a verifier MUST hold a list from the
  token's issuing key with `now ≤ validUntil` (a **fresh** list), and otherwise reject with
  `RevocationStatusUnavailable`. This applies to access tokens and mandates alike. Tokens at or under the exempt TTL
  are still checked against any lists held (CAP-171), but need no fresh one.
- Consequence: revoking a long-lived token takes effect at a verifier within `MAX_LIST_VALIDITY`, and within
  `REVOCATION_EXEMPT_TTL` for short tokens, which simply expire. A compromised issuing key is stopped by a
  root-signed list revoking its issuer-cert, or by the issuer-cert's expiry (at most 30 days).
- Issuers SHOULD keep tokens short (1 hour or less, the M1 invite uses 1 hour) and renew them, and SHOULD use long
  tokens only for standing relationships (S1) where the verifier is the issuer's own node.

### 9.4 Distribution

- The issuing node serves its current list to any peer that asks (a profile operation, T1), and owners publish
  their root-signed list with their owner directory (T17).
- **Stapling**: a sender MAY put the latest lists for its tokens' issuers in `cap.revocations`. For a mandate,
  the holder fetches the principal owner's list from A's node while A is online and staples it at C, so C can
  check a long-lived mandate while A is offline.
- [CAP-173] A verifier MUST process stapled lists like fetched ones (CAP-170), before step 6 of §6.2.

### 9.5 Effect

- [CAP-174] When a verifier learns of a revocation, it MUST deny every later operation authorised by a revoked
  block, including follow-ups on tasks it created (CAP-161), and SHOULD cancel running tasks created under it.
- Revocation does not un-share. Content already sent stays with the receiver (threat-model G18).

## 10. Obligations of issuers and senders

- [CAP-185] An issuing key MUST NOT mint a token outside its issuer-cert scope or after the issuer-cert expires.
  Node code, not an agent, decides what to mint, from owner policy and the skill requested. Foreign text cannot
  make a node mint or widen a token (DD §4.7.4 (4)).
- [CAP-186] When a node sends a request to an agent of another owner, and the request is caused by a task whose
  originator belongs to a third owner (B serving A calls C), the node MUST attach in `cap.mandate` a mandate for
  that task that covers the request, if it holds one in the task's `onward` set. If it holds none, it MUST NOT send
  the request unless its local owner policy explicitly allows acting as its own principal for that capability, and
  it MUST record that decision in the audit log. This is the profile rule of threat-model G10 (a). The node knows
  the cause from the task linkage and taint (`provenance/v0`).
- [CAP-187] A node MUST re-delegate (§5.5) only a token whose current holder is one of its own agents, with that
  agent's key, and only when its owner policy allows the delegation; it MUST add the caveats that policy, or the
  delegating agent's request, asks for (task, TTL, calls, arguments). An agent never sees the token: it asks its
  node to delegate a capability to a named agent, and the node decides (CAP-151, CAP-185).
- Issuers SHOULD mint tokens with `calls` limits and TTLs that match the sub-task, and mandates with `calls($n), $n
  < 1` when one task is expected (threat-model DLG-2).

### 10.1 Audit

- [CAP-190] A verifier MUST record in its audit log (`audit/v0`), for every authorisation decision: the decision
  and the error name, the detailed reason, the presenter, the capability and operation, the authority revocation
  IDs and holder chains of the access token and the mandate, the mandate principal and owner, and the IDs of the
  revocation lists used. An issuer MUST record every token, mandate, invite, certificate and revocation list it
  signs, with its ID.

## 11. Security and privacy considerations

- **Issuing-key compromise** (threat-model ID-7). An attacker on a node can mint access tokens inside the
  resource scope (no more than the node could already do) and, with a mandate scope, forge mandates for the
  agents certified to that node. A mandate grants nothing without an access token held by the presenter, so the
  damage is bounded by what the presenters already hold. Revocation of the issuer-cert by the root key (§9) and the
  30-day limit end it.
- **Root-key compromise** (ID-2). With pre-rotation the owner rotates to the committed next key with
  `compromised: true`, and the thief cannot rotate (CAP-020). Without it, the owner must re-pin out of band.
- **Privacy** (DLG-7, META-6). A mandate shows C who A is, A's agents and owner, and `origin_task`. Every holder
  sees the whole token. Do not put secrets in tokens (CAP-140). Before sealed envelopes (T15) relays and mailbox
  hosts of the sender's owner see them too.
- **Datalog cost** (PEER-5). Limits are in §2.1. Signatures are checked before Datalog runs, and tokens come only
  from pinned owners' issuing keys, so a stranger cannot make a verifier run expensive Datalog.
- **Trust on first use.** An invite authenticates the inviter only as well as the channel it came through.
  Redeem-mode invites are single-use and can require confirmation (CAP-203, CAP-204).
- **Time.** Verifiers need a clock within `SKEW` of real time (threat-model assumption 4). Token expiry has no
  tolerance (CAP-111).
- **Transferable proof.** Tokens and statements are signed and can be shown to third parties (G18).

## 12. Conformance

### 12.1 Vector kinds

The vector format is `webway-vectors/v0` ([`conformance/vectors/README.md`](../../conformance/vectors/README.md)).
All times are explicit, all keys are fixed test keys derived from names (`conformance/tools/capgen/src/keys.rs`),
and every token and statement in the vectors is a real one made with `biscuit-auth` 6.0 and `ed25519-dalek`.

| Kind | Input | Output on accept |
|---|---|---|
| `identity/id` | `{ "id": string }` | `{ "role": "owner" \| "issuer" \| "node" \| "agent", "key": base64url }` |
| `identity/statement` | `{ "now", "typ", "statement", "pins": [ { "owner", "events"? } ], "issuerCert"?, "revocations"? }` | the verified claims |
| `identity/owner-key` | `{ "pin": { "owner" }, "events": [statement, …] }` (events in `seq` order, from 0) | `{ "key": did, "next": string \| null, "seq": n }` |
| `capability/authorize` | `{ "now", "verifier", "request", "cap", "state" }`, see below | `{ "holders": [wwa], "mandateHolders"?: [wwa], "principal"?: wwa }`, or `{ "followUp": true }` |
| `capability/invite` | `{ "now", "invite": string, "acceptingAgent"?: wwa }` | `{ "owner", "node", "mode", "agents": [wwa], "grants": n }` |
| `capability/outbound` | `{ "now", "node": { "owner" }, "task"?: { "originatorOwner", "onward": [mandate] }, "request": { "targetOwner", "capability" }, "policy"?: { "selfPrincipal": [pattern] } }` | `{ "mandate": index \| null, "selfPrincipal"?: true }`; reject `MandateRequired` |

In `identity/statement`, `pins[].events` are owner-key events (§4.3); without them the pin's current root key is
the owner identifier itself.

`capability/authorize` input:

```json
{
  "now": "2026-11-07T12:00:00Z",
  "verifier": {
    "owner": "did:key:…", "node": "wwn:…", "recipient": "wwa:…",
    "pins": ["did:key:…"],
    "issuerCerts": [statement],
    "agentCerts": [statement],
    "policy": "optional Datalog, §5.9"
  },
  "request": {
    "presenter": "wwa:…", "operation": "SendMessage", "taskId": "…", "contextId": "…", "args": { }
  },
  "cap": { "capability": "…", "access": "…", "mandate": { … }, "onward": [ … ], "revocations": [statement] },
  "state": {
    "calls": { "access": 0, "mandate": 0 },
    "revocations": [statement],
    "consumedInvites": ["…"],
    "task": { "taskId": "…", "creator": "wwa:…", "authorizedBy": [ { "owner": "did:key:…", "issuer": "wwi:…", "ids": ["hex"] } ] }
  }
}
```

`verifier.agentCerts` holds the presenter's agent-cert (the envelope layer has already linked it to `from`), and
`issuerCerts` the issuer-certs of the verifier's own owner. A mandate brings its own issuer-cert. `state.calls`
gives the counters of the token's authority blocks, `state.task` the task a follow-up refers to (§6.4).

The generator and reference model is `conformance/tools/capgen` (Rust, `biscuit-auth` 6.0). `webway-capgen gen
conformance/vectors` writes the files deterministically, `webway-capgen check conformance/vectors` runs them
through the model, and `webway-capgen adapter` serves the model over the stdio adapter protocol. The generator
refuses to write a case whose model verdict differs from the verdict written in the case, so every vector is
checked once by construction.

### 12.2 Coverage

| Requirement | Covered by |
|---|---|
| CAP-001 | `identity/id` |
| CAP-002 | `identity/statement` (`sig-*`, `kid-small-order`) |
| CAP-010 … CAP-015 | `identity/statement` |
| CAP-020, CAP-021 | `identity/owner-key`, `identity/statement` (`rotated-*`) |
| CAP-030, CAP-031 | `capability/authorize` (`scope-*`, `issuer-cert-*`, `mandate-*`) |
| CAP-040 | `identity/statement` (`agent-cert-*`) |
| CAP-041 | `capability/authorize` (`presenter-*`) |
| CAP-100 … CAP-104, CAP-110, CAP-111, CAP-120, CAP-121, CAP-130 | `capability/authorize` |
| CAP-160 | `capability/authorize` (`order-*`, `over-attenuated-*`, `*-cannot-widen`) |
| CAP-161, CAP-174 | `capability/authorize` (`followup-*`); cancelling running tasks (CAP-174 SHOULD) in the harness |
| CAP-170 … CAP-173 | `capability/authorize` (`revoked-*`, `revocation-*`, `long-lived-*`) |
| CAP-180 … CAP-182 | `capability/authorize` (`mandate-*`, `on-behalf-*`, `onward-*`) |
| CAP-186 | `capability/outbound` |
| CAP-200, CAP-201 | `capability/invite` |
| CAP-203 | `capability/authorize` (`invite-redeem-*`); atomicity in the harness |
| CAP-003, CAP-050, CAP-060, CAP-061, CAP-140, CAP-150, CAP-151, CAP-185, CAP-187, CAP-190, CAP-202, CAP-204 | **pending**: harness scenarios (T4, T6, T17) |

The **pending** requirements are behaviour of a running node (key use, card handling, pinning UX, what reaches
an agent, what is logged), so no pure-function vector can test them. They need harness scenarios against a node
(T4, T6). Until those exist, `webway-conformance check` (CONV-004) reports these 12 IDs as untested; see §13.

## 13. Changes from the due diligence, and open questions

Changes, all from the threat model:

1. **Issuing keys (G19).** Tokens and Agent Cards are signed by a scoped, short-lived online issuing key certified
   by the owner root key, not by the root key itself (DD §4.2 said the owner key signs cards).
2. **Owner identifier = inception key.** The owner's `did:key` stays fixed across rotations; the current root key
   is found through owner-key events with pre-rotation (G11 (b)).
3. **Invite modes (G16, ID-4).** Invites never carry bearer capabilities: grants are bound to the invitee's key, or
   the only grant is a single-use redemption right. DD §4.2 mentioned a "one-time capability".
4. **Revocation freshness (G11 (a))** with `REVOCATION_EXEMPT_TTL` and fail-closed `RevocationStatusUnavailable`.
5. **Mandate attachment (G10 (a))** as a sender obligation (CAP-186), with an explicit owner-policy escape.
6. **`issuer` fact** instead of Biscuit `root_key_id`, and **`calls` counted per authority block** across forks.

Open questions for the owner or later tracks:

- **Q-CAP-1.** CAP-186 lets an owner policy allow B to act as its own principal for A's task. Should v0 forbid it
  outright (stricter, but B then cannot use its own paid resources for a foreign task)?
- **Q-CAP-2.** The holder chain works in `biscuit-rust` 6.0 (the reference model does it), so UCAN is not needed
  for mandates (Q4 fallback). The walk needs each block's facts. `biscuit-rust` has no public accessor, so the
  model prints each block's source and re-parses it. A small upstream API (block facts by index) would be cleaner.
- **Q-CAP-3.** Where agent-certs come from at verification time: in v0 the envelope layer is assumed to supply the
  sender's agent-cert (cached per peer, or in the envelope). `envelope/v0` must say which.
- **Q-CAP-4.** Argument caveats only see top-level scalars of `args`. Richer constraints (paths into nested
  objects) can come later without breaking v0 tokens.
- **Q-CAP-5.** CONV-004 has no way to mark a `MUST` as "tested by a harness scenario not written yet". The 12
  pending requirements of §12.2 will fail `webway-conformance check` until T4/T6 add scenarios. Options: a
  `pending` marker the checker reports as a warning, or keep the check red for `CAP` until then.
- **Q-CAP-6.** `arg` facts, `cap.capability` and `cap.onward` add members to the envelope and to the A2A message
  metadata. `envelope/v0` and the profile must take them over as written here, or this section moves there.

[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648
[RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
[RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785
[did:key]: https://w3c-ccg.github.io/did-method-key/
[Biscuit]: https://www.biscuitsec.org/
[biscuit-rust]: https://github.com/eclipse-biscuit/biscuit-rust
