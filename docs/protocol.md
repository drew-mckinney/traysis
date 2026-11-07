# traysis wire protocol

Status: draft, schema version 1. Framing and transport are not yet specified.

The wire format is protobuf (`proto/traysis/v1/`, package `traysis.v1`), the
public cross-language contract. The Rust crate `traysis-proto` keeps a
validated domain model (`crates/proto/src/inventory.rs`) and converts to and
from the generated types in one place (`crates/proto/src/convert.rs`). The
generated types are private to that crate. **Everything decoded from the wire
is untrusted until conversion succeeds.**

## Envelope

Every message is an `Envelope { uint64 id; oneof body }` where the body is one
of `SoftwareDelta`, `DeltaAck`, `Ping`, `Pong`. Body field numbers 2 to 5 are
in use. Numbers 6 to 15 are kept free for future hot-path messages, and
queries will start at 16.

### Ids

- `0` is invalid.
- A response echoes its request's id: `DeltaAck` echoes the `SoftwareDelta`,
  `Pong` echoes the `Ping`.
- Each side allocates the ids of the requests it originates, so ids never
  collide: **the agent uses odd ids (1, 3, 5, ...) and the server uses even ids
  (2, 4, 6, ...)**, each stepping by 2 from a per-connection counter
  (`IdAllocator`). A side whose counter is exhausted closes the connection
  instead of reusing an id.
- Conversion enforces only `id != 0`. The session layer enforces that a
  request's id has its sender's parity (`Role::owns`) and that a response
  matches a pending request.

### Unsupported messages

An `Envelope` with a nonzero id and no recognized body (the field is unset, or
it is a message kind from a newer peer, which decoding drops) is an
*unsupported-message* condition: `WireError::UnsupportedMessage { id }`. An
error-reply message is deferred to the server PR. Until then the session layer
decides whether to log and ignore it or close the connection.

## Conversion and validation

`Envelope::decode(&[u8])` is the only way to turn bytes into messages. It
applies, in order:

1. **Size cap.** Input larger than `MAX_ENVELOPE_BYTES` is rejected.
   `MAX_ENVELOPE_BYTES` is `MAX_DELTA_COST + 1 MiB`, enough for a full
   snapshot. **The transport's maximum frame length must use this constant.**
2. **Pre-scan.** A decoded list entry costs roughly 100 times its minimum
   encoded size (2 bytes), so a frame of empty entries would otherwise force
   gigabytes of allocation before validation. A non-allocating walk of the
   framing counts `upserted` and `removed` entries, summed across repeated
   `delta` occurrences (protobuf merges them), and rejects more than
   `MAX_ITEMS` of either. It also rejects malformed framing, including group
   wire types.
3. **Protobuf decode.** Truncation, wrong wire types, bad varints, and huge
   lengths are errors. Unknown fields are ignored and **dropped**.
4. **Conversion** to the domain model, then, for a delta,
   `SoftwareDelta::validate()`. A successfully converted `SoftwareDelta` is
   always valid.

| Rule | Error |
|---|---|
| bytes do not decode | `Decode` |
| larger than `MAX_ENVELOPE_BYTES` | `EnvelopeTooLarge` |
| malformed framing, found by the pre-scan | `Malformed` |
| envelope id 0 | `ZeroId` |
| no recognized body | `UnsupportedMessage` |
| any enum is `*_UNSPECIFIED` | `UnspecifiedEnum` |
| any enum number unknown to this build | `UnknownEnum` |
| `source` is `OTHER` with empty `other_source` | `OtherSourceEmpty` |
| `source` is not `OTHER` with nonempty `other_source` | `StraySourceName` |
| outcome `NEED_RESYNC` without a reason | `ResyncReasonMissing` |
| reason present with another outcome | `ResyncReasonUnexpected` |
| `state_digest` is not exactly 32 bytes | `BadDigestLength` |
| `schema_version` above 65535 | `SchemaVersionOutOfRange` |
| any domain invariant (`validate()`, including > `MAX_ITEMS`) | `Invalid` |

Error messages name fields and numbers only; they never echo payload contents.

### Field conventions

- `optional` marks every field where missing differs from empty: `arch`,
  `version_id`, `purl`, `vendor`, `SourcePackage.version`.
- `PackageSource` is an enum plus a separate `other_source` string.
- `AckOutcome` and `ResyncReason` are separate enums. The reason is set if
  and only if the outcome is `NEED_RESYNC`.
- `collected_at` is `uint64` milliseconds since the Unix epoch, matching
  `UnixMillis(u64)`. It is the agent's clock, untrusted and informational.

### Identity binding

`host_id` in a `SoftwareDelta` **must equal the authenticated transport
identity** (the mTLS identity the host enrolled with). The session layer
checks this, and a mismatch is rejected. Conversion cannot check it because it
does not know the connection.

### Signatures

Queries and commands are signed (see `CLAUDE.md`). Signatures are computed
over **the exact serialized bytes of a payload field**, never over a
re-encoded message. Protobuf encoding is not canonical (field order, varint
width, and packed or unpacked forms may vary), and decoding drops unknown
fields, so decode-then-encode does not reproduce what the sender signed.
Verifiers must keep the received bytes and check the signature against them
before or while decoding. `Envelope::encode_to_vec` output is not canonical
either: sign the bytes you send, not a re-encoding. No signed message exists
yet; this rule binds the query PR.

## Compatibility

- Never reuse a field number; use `reserved` for removed fields.
- Every enum has an `UNSPECIFIED = 0` value, rejected on receipt.
- New fields are ignored by older receivers. Anything that must not be ignored
  needs a new `schema_version`.
- `schema_version` is the inventory model's version, separate from protobuf
  evolution. This build accepts only 1.

## State digest

The digest is specified by the rustdoc on `state_digest` in
`crates/proto/src/inventory.rs` and pinned by the literal hex vectors in that
file's tests (produced by an independent implementation). A standalone
cross-language digest document does not exist yet. The digest is computed
from domain values, so unknown wire fields and the wire encoding never affect
it.

## Framing

TBD in the transport PR.

## Transport

TBD in the transport PR.
