# traysis server: delta apply and the SQLite store

Status: draft. This covers the storage and apply logic only; transport, mTLS
and sessions are later PRs. Code: `crates/server` (`apply`, `store`, `error`).

```rust
apply(store: &mut Store, authed_host: &HostId, delta: &SoftwareDelta, now: UnixMillis)
    -> Result<DeltaAck, ApplyError>
```

`authed_host` is the identity from the transport. `now` is the server's receive
time, stored per host; the delta's `collected_at` is ignored. The logic never
reads a clock, does no I/O except the database, and has no async code.

## Decision table

Checks run in this order. Only `Applied` commits; every other row leaves the
database untouched (the transaction is rolled back).

| # | Condition | Result |
|---|---|---|
| 1 | `delta.host_id != authed_host` | `Err(HostMismatch)` (protocol violation, no ack) |
| 2 | `validate()` fails (including NUL bytes) | `Err(Invalid)` |
| 3 | `full` and `epoch != 0` | `Err(SnapshotWithEpoch)` |
| 4 | receive time above `i64::MAX` ms | `Err(TimeOutOfRange)` |
| 5 | `full` (handshake, epoch 0, seq 0) | issue epoch = last issued for the host + 1, replace the inventory, apply as seq 0; see digest rule |
| 6 | incremental, host unknown | `NeedResync(StateUnknown)`, ack position `(0, 0)` |
| 7 | incremental, `epoch >` stored | `NeedResync(StateUnknown)` |
| 8 | incremental, `epoch <` stored | `NeedResync(EpochStale)` |
| 9 | same epoch, `seq <= stored seq` | `Duplicate` |
| 10 | same epoch, `seq > stored seq + 1` | `NeedResync(SeqGap)` |
| 11 | same epoch, `seq == stored seq + 1` | remove, then upsert, update seq and time (and OS if `host_os` is set); see digest rule |

**Digest rule.** After applying (rows 5 and 11) the server reads back the host's
whole item set, computes `state_digest` with the proto function, and compares
it with `delta.state_digest`. On mismatch the transaction rolls back (rows,
epoch, seq, OS, time and the epoch counter are all unchanged) and the result is
`NeedResync(DigestMismatch)`. A failed handshake therefore does not consume an
epoch.

**Ack contents.** `Applied` acks carry the epoch in force and the applied seq
(handshake: the new epoch, seq 0; incremental: the delta's epoch and seq), as
the agent's `commit` requires. `Duplicate` and `NeedResync` acks carry the
host's stored `(epoch, seq)`, or `(0, 0)` for an unknown host. The agent treats
them as informational and resyncs regardless.

**Epochs.** `host_epochs.last_issued` is per host, never deleted, and updated in
the same transaction as the handshake, so epochs are strictly increasing across
restarts and even after the host's `hosts` row (and so its inventory) is
deleted. Counter exhaustion (`i64::MAX`) is `Err(EpochExhausted)`; a seq that
cannot be stored is `Err(SeqExhausted)`. `u64` wire values above `i64::MAX` are
compared in Rust and classified (gap or unknown); they are never stored.

**Transactions.** One `IMMEDIATE` transaction per delta, so the read-check-write
sequence is serialised against other writers. Removals run before upserts.
Removing an absent key is a no-op (the digest decides whether the result is
right). Upserting an existing key replaces its non-key attributes. A dropped,
uncommitted transaction leaves the previous state (tested).

## Schema (`PRAGMA user_version = 1`)

```sql
CREATE TABLE host_epochs (            -- never deleted
  host_id TEXT PRIMARY KEY,
  last_issued INTEGER NOT NULL CHECK (last_issued > 0)
) WITHOUT ROWID;

CREATE TABLE hosts (                  -- current state per host
  host_id TEXT PRIMARY KEY,
  epoch INTEGER NOT NULL CHECK (epoch > 0),
  seq INTEGER NOT NULL CHECK (seq >= 0),
  os_id TEXT NOT NULL,
  os_version_id TEXT,
  os_arch TEXT NOT NULL,
  received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= 0)
) WITHOUT ROWID;

CREATE TABLE software (
  host_id TEXT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
  source TEXT NOT NULL,                 -- digest tag: dpkg|rpm|apk|pacman|brew|other:<s>
  name TEXT NOT NULL,
  arch_present INTEGER NOT NULL CHECK (arch_present IN (0, 1)),
  arch TEXT NOT NULL,                   -- '' when absent
  version TEXT NOT NULL,
  sp_present INTEGER NOT NULL CHECK (sp_present IN (0, 1)),
  sp_name TEXT NOT NULL,                -- '' when absent
  sp_version_present INTEGER NOT NULL CHECK (sp_version_present IN (0, 1)),
  sp_version TEXT NOT NULL,             -- '' when absent
  vendor TEXT,                          -- not key, not digested
  purl TEXT,                            -- not key, not digested
  PRIMARY KEY (host_id, source, name, arch_present, arch, version),
  CHECK (arch_present = 1 OR arch = ''),
  CHECK (sp_present = 1 OR (sp_name = '' AND sp_version_present = 0 AND sp_version = '')),
  CHECK (sp_version_present = 1 OR sp_version = '')
) WITHOUT ROWID;
```

**Absent versus empty.** The digest treats an absent `arch` and an empty one as
different values. SQLite treats NULLs as distinct in UNIQUE constraints, so a
nullable `arch` in the key would let duplicates in (and `NULL` in a
`WITHOUT ROWID` primary key is rejected). Every key column is therefore
`NOT NULL`, with presence in its own `*_present` column inside the primary key:
absent is `(0, '')`, empty is `(1, '')`. `CHECK`s keep the absent form
canonical. The same pattern holds for `source_package` (not part of the key).
`vendor` and `purl` are outside the key and the digest, so plain nullable
columns are fine. Tests round-trip both forms through the database and compare
digests.

**Source tag.** `source` stores the digest's tag, so `Other("dpkg")` is
`other:dpkg` and never collides with `Dpkg`.

## Strings and NUL

`SoftwareDelta::validate()` rejects a NUL byte in every string field
(`ValidationError::NulByte`). Consumers that truncate at NUL (C APIs, SQL
`length`/`LIKE`, log tools) would otherwise see `openssl\0evil` as `openssl`.
The server relies on this: all values are bound as parameters (never
interpolated), and NUL cannot reach the database; tests assert it. Quotes,
semicolons and Unicode round-trip unchanged.

## Database file

- Created `0600`; opened without URI interpretation and with `NOFOLLOW`.
- An existing path that is a symlink, not a regular file, or has any group or
  other permission bit is refused (`StoreError::Insecure`), never "fixed".
  SQLite gives `-wal` and `-shm` the main file's mode (tested).
- The parent directory's ownership and mode are the deployer's job.
- `Store::open` requires `PRAGMA journal_mode = WAL` to report `wal` and
  `foreign_keys` to read back 1, else it fails. `synchronous` is left at the
  default (FULL). `busy_timeout` is 5 s.
- `user_version`: 0 with no tables creates v1 in one transaction; 1 is
  accepted; higher is `UnsupportedSchema`; 0 with tables is `UnversionedSchema`.

## Scaling limit

**The digest is recomputed over the host's entire item set on every delta.**
That is O(N) in the host's item count (at most `MAX_ITEMS` = 50,000) even for a
one-item delta, and it is the scaling limit of this design. Removing it (an
incrementally maintained or hierarchical digest) changes what the server
verifies and so **requires a `schema_version` bump** in the protocol and a
store migration; it must not be done silently.

Measured (this PR, one run on a Linux dev machine, file DB, WAL, default
synchronous; includes `validate()` and the digest):

| Case | debug | release |
|---|---|---|
| 50,000-item handshake | 483 ms | 145 ms |
| 1-item incremental on a 50,000-item host | 241 ms | 54 ms |

## Not done yet (deliberately)

Transport, mTLS and authentication (identity is an input), enrollment, rate
limits and backpressure, per-host quotas, retention and pruning, a host
deletion API, CVE matching, `purl` computation, metrics and logging, encryption
at rest, migrations beyond v1, and multi-writer tuning beyond SQLite's locking.
