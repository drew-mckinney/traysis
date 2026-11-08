//! Delta-apply logic: the epoch handshake, duplicate and gap detection, and
//! digest verification. Pure of I/O apart from the [`Store`], and of clocks:
//! the caller passes `now`.
//!
//! Every delta is applied in one `IMMEDIATE` transaction. Only an `Applied`
//! result is committed; every other outcome (resync requests, duplicates,
//! errors) rolls back, so the stored epoch and sequence number change only
//! together with the inventory they describe.

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use traysis_proto::inventory::{
    AckOutcome, DeltaAck, Epoch, HostId, PackageSource, ResyncReason, SoftwareDelta, SoftwareItem,
    SourcePackage, UnixMillis, ValidationError, state_digest,
};

use crate::error::{ApplyError, StoreError};
use crate::store::Store;

const INSERT_SQL: &str = "INSERT INTO software (host_id, source, name, arch_present, arch, \
    version, sp_present, sp_name, sp_version_present, sp_version, vendor, purl) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

const UPSERT_SUFFIX: &str = " ON CONFLICT (host_id, source, name, arch_present, arch, version) \
    DO UPDATE SET sp_present = excluded.sp_present, sp_name = excluded.sp_name, \
    sp_version_present = excluded.sp_version_present, sp_version = excluded.sp_version, \
    vendor = excluded.vendor, purl = excluded.purl";

const DELETE_SQL: &str = "DELETE FROM software WHERE host_id = ?1 AND source = ?2 AND name = ?3 \
    AND arch_present = ?4 AND arch = ?5 AND version = ?6";

const DIGEST_COLUMNS: &str = "source, name, arch_present, arch, version, sp_present, sp_name, \
    sp_version_present, sp_version, NULL, NULL";
const FULL_COLUMNS: &str = "source, name, arch_present, arch, version, sp_present, sp_name, \
    sp_version_present, sp_version, vendor, purl";

/// What `apply_in_tx` wants done with its transaction.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Commit, then return the ack.
    Commit(DeltaAck),
    /// Roll back, then return the ack. Nothing was changed.
    Rollback(DeltaAck),
}

/// The epoch and sequence number currently stored for a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Position {
    epoch: u64,
    seq: u64,
}

impl Position {
    /// What an unknown host reports.
    const UNKNOWN: Self = Self { epoch: 0, seq: 0 };

    fn resync(self, reason: ResyncReason) -> Verdict {
        Verdict::Rollback(DeltaAck {
            epoch: Epoch(self.epoch),
            seq: self.seq,
            outcome: AckOutcome::NeedResync(reason),
        })
    }
}

/// Applies `delta` for `authed_host` and returns the ack to send.
///
/// `authed_host` is the identity established by the transport; `now` is the
/// server's receive time. The delta's own `collected_at` is ignored.
///
/// A returned `Ok` ack is final: for [`AckOutcome::Applied`] the inventory,
/// epoch and sequence number were committed together; for every other outcome
/// nothing was changed. The ack's `(epoch, seq)` on `Duplicate` and
/// `NeedResync` is the host's stored position, or `(0, 0)` if it has none;
/// agents treat it as informational.
///
/// # Errors
///
/// [`ApplyError::HostMismatch`] if `delta.host_id` is not `authed_host`;
/// [`ApplyError::Invalid`] if the delta fails validation (including NUL bytes);
/// [`ApplyError::SnapshotWithEpoch`] for a full snapshot with a nonzero epoch;
/// exhaustion and range errors; and [`ApplyError::Store`] for database
/// failures. On any error nothing is committed.
pub fn apply(
    store: &mut Store,
    authed_host: &HostId,
    delta: &SoftwareDelta,
    now: UnixMillis,
) -> Result<DeltaAck, ApplyError> {
    if delta.host_id != *authed_host {
        return Err(ApplyError::HostMismatch);
    }
    delta.validate().map_err(ApplyError::Invalid)?;
    if delta.full && !delta.epoch.is_unassigned() {
        return Err(ApplyError::SnapshotWithEpoch);
    }
    let now_ms = i64::try_from(now.0).map_err(|_| ApplyError::TimeOutOfRange)?;

    let tx = store
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    match apply_in_tx(&tx, delta, now_ms)? {
        Verdict::Commit(ack) => {
            tx.commit()?;
            Ok(ack)
        }
        Verdict::Rollback(ack) => {
            tx.rollback()?;
            Ok(ack)
        }
    }
}

/// Does all the work of [`apply`] inside `tx` without committing it.
/// The delta must already be validated and match the authenticated host.
pub(crate) fn apply_in_tx(
    tx: &Transaction<'_>,
    delta: &SoftwareDelta,
    now_ms: i64,
) -> Result<Verdict, ApplyError> {
    if delta.full {
        handshake(tx, delta, now_ms)
    } else {
        incremental(tx, delta, now_ms)
    }
}

fn handshake(
    tx: &Transaction<'_>,
    delta: &SoftwareDelta,
    now_ms: i64,
) -> Result<Verdict, ApplyError> {
    let host = delta.host_id.0.as_str();
    let prior = load_position(tx, host)?.unwrap_or(Position::UNKNOWN);

    let last_issued: i64 = tx
        .query_row(
            "SELECT last_issued FROM host_epochs WHERE host_id = ?1",
            [host],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let epoch = last_issued
        .checked_add(1)
        .ok_or(ApplyError::EpochExhausted)?;

    tx.execute("DELETE FROM software WHERE host_id = ?1", [host])?;
    tx.execute(
        "INSERT INTO host_epochs (host_id, last_issued) VALUES (?1, ?2) \
         ON CONFLICT (host_id) DO UPDATE SET last_issued = excluded.last_issued",
        params![host, epoch],
    )?;
    // The caller validated the delta, so a full snapshot has `host_os`.
    let os = delta
        .host_os
        .as_ref()
        .ok_or(ApplyError::Invalid(ValidationError::MissingHostOs))?;
    tx.execute(
        "INSERT INTO hosts (host_id, epoch, seq, os_id, os_version_id, os_arch, received_at_ms) \
         VALUES (?1, ?2, 0, ?3, ?4, ?5, ?6) \
         ON CONFLICT (host_id) DO UPDATE SET epoch = excluded.epoch, seq = 0, \
         os_id = excluded.os_id, os_version_id = excluded.os_version_id, \
         os_arch = excluded.os_arch, received_at_ms = excluded.received_at_ms",
        params![host, epoch, os.id, os.version_id, os.arch, now_ms],
    )?;

    // One prepared statement for the whole snapshot.
    let mut insert = tx.prepare(INSERT_SQL)?;
    for item in &delta.upserted {
        insert_item(&mut insert, host, item)?;
    }
    drop(insert);

    if !digest_matches(tx, host, &delta.state_digest)? {
        return Ok(prior.resync(ResyncReason::DigestMismatch));
    }
    Ok(Verdict::Commit(DeltaAck {
        epoch: Epoch(u64::try_from(epoch).map_err(|_| ApplyError::EpochExhausted)?),
        seq: 0,
        outcome: AckOutcome::Applied,
    }))
}

fn incremental(
    tx: &Transaction<'_>,
    delta: &SoftwareDelta,
    now_ms: i64,
) -> Result<Verdict, ApplyError> {
    let host = delta.host_id.0.as_str();
    let Some(stored) = load_position(tx, host)? else {
        return Ok(Position::UNKNOWN.resync(ResyncReason::StateUnknown));
    };
    if delta.epoch.0 > stored.epoch {
        return Ok(stored.resync(ResyncReason::StateUnknown));
    }
    if delta.epoch.0 < stored.epoch {
        return Ok(stored.resync(ResyncReason::EpochStale));
    }
    if delta.seq <= stored.seq {
        return Ok(Verdict::Rollback(DeltaAck {
            epoch: Epoch(stored.epoch),
            seq: stored.seq,
            outcome: AckOutcome::Duplicate,
        }));
    }
    // `stored.seq` came from an i64 column, so it is below `u64::MAX`.
    if delta.seq != stored.seq.saturating_add(1) {
        return Ok(stored.resync(ResyncReason::SeqGap));
    }
    let seq = i64::try_from(delta.seq).map_err(|_| ApplyError::SeqExhausted)?;

    // Removals first, then upserts.
    {
        let mut remove = tx.prepare(DELETE_SQL)?;
        for key in &delta.removed {
            let (source, arch_present, arch) = key_columns(&key.source, key.arch.as_ref())?;
            remove.execute(params![
                host,
                source,
                key.name,
                arch_present,
                arch,
                key.version
            ])?;
        }
    }
    {
        let mut upsert = tx.prepare(&format!("{INSERT_SQL}{UPSERT_SUFFIX}"))?;
        for item in &delta.upserted {
            insert_item(&mut upsert, host, item)?;
        }
    }
    tx.execute(
        "UPDATE hosts SET seq = ?2, received_at_ms = ?3 WHERE host_id = ?1",
        params![host, seq, now_ms],
    )?;
    if let Some(os) = &delta.host_os {
        tx.execute(
            "UPDATE hosts SET os_id = ?2, os_version_id = ?3, os_arch = ?4 WHERE host_id = ?1",
            params![host, os.id, os.version_id, os.arch],
        )?;
    }

    if !digest_matches(tx, host, &delta.state_digest)? {
        return Ok(stored.resync(ResyncReason::DigestMismatch));
    }
    Ok(Verdict::Commit(DeltaAck {
        epoch: delta.epoch,
        seq: delta.seq,
        outcome: AckOutcome::Applied,
    }))
}

/// Reads the host's stored epoch and sequence number.
fn load_position(tx: &Transaction<'_>, host: &str) -> Result<Option<Position>, ApplyError> {
    let row: Option<(i64, i64)> = tx
        .query_row(
            "SELECT epoch, seq FROM hosts WHERE host_id = ?1",
            [host],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(epoch, seq)| {
        Ok(Position {
            epoch: u64::try_from(epoch).map_err(|_| StoreError::Corrupt("negative epoch"))?,
            seq: u64::try_from(seq).map_err(|_| StoreError::Corrupt("negative seq"))?,
        })
    })
    .transpose()
}

/// Recomputes the digest over the host's whole post-apply item set.
fn digest_matches(
    tx: &Transaction<'_>,
    host: &str,
    expected: &[u8; 32],
) -> Result<bool, ApplyError> {
    let items = read_items(tx, host, false)?;
    let actual = state_digest(&items).map_err(|_| StoreError::Corrupt("duplicate stored key"))?;
    Ok(actual == *expected)
}

/// Storage form of a package source: the same tag the digest uses.
fn encode_source(source: &PackageSource) -> Result<String, StoreError> {
    Ok(match source {
        PackageSource::Dpkg => "dpkg".to_owned(),
        PackageSource::Rpm => "rpm".to_owned(),
        PackageSource::Apk => "apk".to_owned(),
        PackageSource::Pacman => "pacman".to_owned(),
        PackageSource::Brew => "brew".to_owned(),
        PackageSource::Other(s) => format!("other:{s}"),
        _ => return Err(StoreError::Corrupt("package source unknown to this build")),
    })
}

fn decode_source(tag: &str) -> Result<PackageSource, StoreError> {
    Ok(match tag {
        "dpkg" => PackageSource::Dpkg,
        "rpm" => PackageSource::Rpm,
        "apk" => PackageSource::Apk,
        "pacman" => PackageSource::Pacman,
        "brew" => PackageSource::Brew,
        other => match other.strip_prefix("other:") {
            Some(name) if !name.is_empty() => PackageSource::Other(name.to_owned()),
            _ => return Err(StoreError::Corrupt("unknown source tag")),
        },
    })
}

/// The `(source, arch_present, arch)` key columns; an absent arch is stored as
/// `(0, "")` and an empty one as `(1, "")`, so the two never collide.
fn key_columns<'a>(
    source: &PackageSource,
    arch: Option<&'a String>,
) -> Result<(String, i64, &'a str), StoreError> {
    Ok((
        encode_source(source)?,
        i64::from(arch.is_some()),
        arch.map_or("", String::as_str),
    ))
}

fn insert_item(
    stmt: &mut rusqlite::Statement<'_>,
    host: &str,
    item: &SoftwareItem,
) -> Result<(), ApplyError> {
    let (source, arch_present, arch) = key_columns(&item.source, item.arch.as_ref())?;
    let (sp_present, sp_name, sp_version_present, sp_version) = match &item.source_package {
        Some(sp) => (
            1_i64,
            sp.name.as_str(),
            i64::from(sp.version.is_some()),
            sp.version.as_deref().unwrap_or(""),
        ),
        None => (0, "", 0, ""),
    };
    stmt.execute(params![
        host,
        source,
        item.name,
        arch_present,
        arch,
        item.version,
        sp_present,
        sp_name,
        sp_version_present,
        sp_version,
        item.vendor,
        item.purl,
    ])?;
    Ok(())
}

/// Reads a host's items. With `extras == false`, `vendor` and `purl` are left
/// `None` (the digest ignores them and this saves memory on large hosts).
pub(crate) fn read_items(
    tx: &rusqlite::Connection,
    host: &str,
    extras: bool,
) -> Result<Vec<SoftwareItem>, StoreError> {
    let columns = if extras { FULL_COLUMNS } else { DIGEST_COLUMNS };
    let mut stmt = tx.prepare(&format!(
        "SELECT {columns} FROM software WHERE host_id = ?1"
    ))?;
    let mut rows = stmt.query([host])?;
    let mut items = Vec::new();
    while let Some(r) = rows.next()? {
        let source: String = r.get(0)?;
        let arch_present: i64 = r.get(2)?;
        let arch: String = r.get(3)?;
        let sp_present: i64 = r.get(5)?;
        let sp_version_present: i64 = r.get(7)?;
        let sp_name: String = r.get(6)?;
        let sp_version: String = r.get(8)?;
        items.push(SoftwareItem {
            source: decode_source(&source)?,
            name: r.get(1)?,
            arch: (arch_present == 1).then_some(arch),
            version: r.get(4)?,
            source_package: (sp_present == 1).then(|| SourcePackage {
                name: sp_name,
                version: (sp_version_present == 1).then_some(sp_version),
            }),
            vendor: r.get(9)?,
            purl: r.get(10)?,
        });
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use rusqlite::Connection;
    use rusqlite::types::Value;
    use traysis_proto::inventory::{HostOs, MAX_ITEMS, SCHEMA_VERSION, SoftwareKey};

    use super::*;
    use crate::testutil::TempDir;

    const NOW: UnixMillis = UnixMillis(1_700_000_000_000);

    fn host() -> HostId {
        HostId("host-1".to_owned())
    }

    fn item(name: &str, version: &str) -> SoftwareItem {
        SoftwareItem {
            name: name.to_owned(),
            version: version.to_owned(),
            arch: Some("amd64".to_owned()),
            source: PackageSource::Dpkg,
            source_package: None,
            vendor: None,
            purl: None,
        }
    }

    fn os(id: &str) -> HostOs {
        HostOs {
            id: id.to_owned(),
            version_id: Some("12".to_owned()),
            arch: "x86_64".to_owned(),
        }
    }

    fn digest(items: &[SoftwareItem]) -> [u8; 32] {
        state_digest(items).unwrap()
    }

    /// A handshake whose digest matches `items`.
    fn handshake(items: Vec<SoftwareItem>) -> SoftwareDelta {
        SoftwareDelta {
            schema_version: SCHEMA_VERSION,
            host_id: host(),
            epoch: Epoch::UNASSIGNED,
            seq: 0,
            full: true,
            host_os: Some(os("debian")),
            collected_at: UnixMillis(1),
            state_digest: digest(&items),
            upserted: items,
            removed: Vec::new(),
        }
    }

    /// An incremental delta; `after` is the full inventory it should produce.
    fn inc(
        epoch: u64,
        seq: u64,
        upserted: Vec<SoftwareItem>,
        removed: Vec<SoftwareKey>,
        after: &[SoftwareItem],
    ) -> SoftwareDelta {
        SoftwareDelta {
            schema_version: SCHEMA_VERSION,
            host_id: host(),
            epoch: Epoch(epoch),
            seq,
            full: false,
            host_os: None,
            collected_at: UnixMillis(1),
            upserted,
            removed,
            state_digest: digest(after),
        }
    }

    fn go(store: &mut Store, d: &SoftwareDelta) -> DeltaAck {
        apply(store, &host(), d, NOW).unwrap()
    }

    fn ack(epoch: u64, seq: u64, outcome: AckOutcome) -> DeltaAck {
        DeltaAck {
            epoch: Epoch(epoch),
            seq,
            outcome,
        }
    }

    fn resync(epoch: u64, seq: u64, reason: ResyncReason) -> DeltaAck {
        ack(epoch, seq, AckOutcome::NeedResync(reason))
    }

    /// Every row of every table, in a comparable form.
    fn dump(conn: &Connection) -> Vec<(String, Vec<Vec<Value>>)> {
        ["host_epochs", "hosts", "software"]
            .iter()
            .map(|t| {
                let mut stmt = conn.prepare(&format!("SELECT * FROM {t}")).unwrap();
                let n = stmt.column_count();
                let rows = stmt
                    .query_map([], |r| (0..n).map(|i| r.get::<_, Value>(i)).collect())
                    .unwrap()
                    .collect::<Result<Vec<Vec<Value>>, _>>()
                    .unwrap();
                ((*t).to_owned(), rows)
            })
            .collect()
    }

    fn stored(store: &Store) -> Vec<SoftwareItem> {
        let mut v = read_items(&store.conn, "host-1", true).unwrap();
        v.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        v
    }

    fn position(store: &Store) -> Option<(i64, i64, i64)> {
        store
            .conn
            .query_row(
                "SELECT epoch, seq, received_at_ms FROM hosts WHERE host_id = 'host-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .unwrap()
    }

    fn mem() -> Store {
        Store::open_in_memory().unwrap()
    }

    #[test]
    fn handshake_issues_epoch_one_then_two() {
        let mut s = mem();
        let a = vec![item("a", "1")];
        assert_eq!(
            go(&mut s, &handshake(a.clone())),
            ack(1, 0, AckOutcome::Applied)
        );
        assert_eq!(stored(&s), a);

        let b = vec![item("b", "2"), item("c", "3")];
        assert_eq!(
            go(&mut s, &handshake(b.clone())),
            ack(2, 0, AckOutcome::Applied)
        );
        assert_eq!(stored(&s), b, "second handshake replaces the inventory");
        assert_eq!(position(&s), Some((2, 0, 1_700_000_000_000)));
    }

    #[test]
    fn epoch_persists_across_reopening_a_file_db() {
        let tmp = TempDir::new();
        let path = tmp.path().join("inv.db");
        {
            let mut s = Store::open(&path).unwrap();
            assert_eq!(
                go(&mut s, &handshake(vec![item("a", "1")])),
                ack(1, 0, AckOutcome::Applied)
            );
        }
        let mut s = Store::open(&path).unwrap();
        assert_eq!(stored(&s), vec![item("a", "1")]);
        assert_eq!(
            go(&mut s, &handshake(vec![])),
            ack(2, 0, AckOutcome::Applied)
        );
    }

    #[test]
    fn epoch_stays_increasing_after_the_host_is_deleted() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("a", "1")]));
        go(&mut s, &handshake(vec![item("a", "1")]));
        s.conn.execute("DELETE FROM hosts", []).unwrap();
        let n: i64 = s
            .conn
            .query_row("SELECT count(*) FROM software", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "deleting the host cascades to its items");
        assert_eq!(
            go(&mut s, &inc(2, 1, vec![], vec![], &[])),
            resync(0, 0, ResyncReason::StateUnknown)
        );
        assert_eq!(
            go(&mut s, &handshake(vec![])),
            ack(3, 0, AckOutcome::Applied)
        );
    }

    #[test]
    fn incremental_applies_in_sequence() {
        let mut s = mem();
        let base = vec![item("a", "1")];
        go(&mut s, &handshake(base.clone()));
        let after = vec![item("a", "1"), item("b", "1")];
        let d = inc(1, 1, vec![item("b", "1")], vec![], &after);
        assert_eq!(go(&mut s, &d), ack(1, 1, AckOutcome::Applied));
        assert_eq!(stored(&s), after);
        assert_eq!(position(&s), Some((1, 1, 1_700_000_000_000)));

        let d = inc(1, 2, vec![], vec![item("a", "1").key()], &[item("b", "1")]);
        assert_eq!(go(&mut s, &d), ack(1, 2, AckOutcome::Applied));
        assert_eq!(stored(&s), vec![item("b", "1")]);
    }

    #[test]
    fn duplicate_returns_stored_position_and_writes_nothing() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("a", "1")]));
        let after = vec![item("a", "1"), item("b", "1")];
        let d = inc(1, 1, vec![item("b", "1")], vec![], &after);
        go(&mut s, &d);
        let before = dump(&s.conn);

        assert_eq!(go(&mut s, &d), ack(1, 1, AckOutcome::Duplicate));
        // An older seq is also a duplicate; the ack reports the stored seq.
        let old = inc(1, 0, vec![item("z", "9")], vec![], &[]);
        assert_eq!(go(&mut s, &old), ack(1, 1, AckOutcome::Duplicate));
        assert_eq!(dump(&s.conn), before);
    }

    #[test]
    fn gap_stale_unknown_and_newer_epoch_ask_for_resync() {
        let mut s = mem();
        let unknown = inc(1, 1, vec![], vec![], &[]);
        assert_eq!(
            go(&mut s, &unknown),
            resync(0, 0, ResyncReason::StateUnknown)
        );

        go(&mut s, &handshake(vec![item("a", "1")]));
        go(&mut s, &handshake(vec![item("a", "1")]));
        let before = dump(&s.conn);

        let gap = inc(2, 2, vec![], vec![], &[item("a", "1")]);
        assert_eq!(go(&mut s, &gap), resync(2, 0, ResyncReason::SeqGap));
        let stale = inc(1, 1, vec![], vec![], &[item("a", "1")]);
        assert_eq!(go(&mut s, &stale), resync(2, 0, ResyncReason::EpochStale));
        let newer = inc(3, 1, vec![], vec![], &[item("a", "1")]);
        assert_eq!(go(&mut s, &newer), resync(2, 0, ResyncReason::StateUnknown));
        assert_eq!(dump(&s.conn), before);
    }

    #[test]
    fn huge_epoch_and_seq_are_classified_without_being_stored() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("a", "1")]));
        let before = dump(&s.conn);
        let d = inc(u64::MAX, 1, vec![], vec![], &[item("a", "1")]);
        assert_eq!(go(&mut s, &d), resync(1, 0, ResyncReason::StateUnknown));
        let d = inc(1, u64::MAX, vec![], vec![], &[item("a", "1")]);
        assert_eq!(go(&mut s, &d), resync(1, 0, ResyncReason::SeqGap));
        let d = inc(u64::from(u32::MAX) << 33, 1, vec![], vec![], &[]);
        assert_eq!(go(&mut s, &d), resync(1, 0, ResyncReason::StateUnknown));
        assert_eq!(dump(&s.conn), before);
    }

    #[test]
    fn sequence_exhaustion_is_an_error_not_a_wrap() {
        let mut s = mem();
        go(&mut s, &handshake(vec![]));
        s.conn
            .execute("UPDATE hosts SET seq = ?1", [i64::MAX])
            .unwrap();
        let before = dump(&s.conn);
        let d = inc(1, u64::MAX / 2 + 1, vec![], vec![], &[]);
        assert!(matches!(
            apply(&mut s, &host(), &d, NOW),
            Err(ApplyError::SeqExhausted)
        ));
        assert_eq!(dump(&s.conn), before);
    }

    #[test]
    fn epoch_exhaustion_is_an_error_and_changes_nothing() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("a", "1")]));
        s.conn
            .execute("UPDATE host_epochs SET last_issued = ?1", [i64::MAX])
            .unwrap();
        let before = dump(&s.conn);
        assert!(matches!(
            apply(&mut s, &host(), &handshake(vec![]), NOW),
            Err(ApplyError::EpochExhausted)
        ));
        assert_eq!(dump(&s.conn), before);
    }

    #[test]
    fn receive_time_out_of_range_is_an_error() {
        let mut s = mem();
        let r = apply(&mut s, &host(), &handshake(vec![]), UnixMillis(u64::MAX));
        assert!(matches!(r, Err(ApplyError::TimeOutOfRange)));
        assert_eq!(position(&s), None);
    }

    #[test]
    fn digest_mismatch_on_incremental_rolls_back_completely() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("a", "1"), item("b", "1")]));
        let before = dump(&s.conn);

        let mut d = inc(
            1,
            1,
            vec![item("c", "1")],
            vec![item("a", "1").key()],
            &[item("b", "1"), item("c", "1")],
        );
        d.host_os = Some(os("ubuntu"));
        d.state_digest[0] ^= 1;
        assert_eq!(go(&mut s, &d), resync(1, 0, ResyncReason::DigestMismatch));
        assert_eq!(
            dump(&s.conn),
            before,
            "rows, epoch, seq, os, time unchanged"
        );
        assert_eq!(position(&s), Some((1, 0, 1_700_000_000_000)));

        // The same seq is still the next expected one.
        d.state_digest = digest(&[item("b", "1"), item("c", "1")]);
        assert_eq!(go(&mut s, &d), ack(1, 1, AckOutcome::Applied));
    }

    #[test]
    fn digest_mismatch_on_first_handshake_persists_nothing() {
        let mut s = mem();
        let mut d = handshake(vec![item("a", "1")]);
        d.state_digest = [7; 32];
        assert_eq!(go(&mut s, &d), resync(0, 0, ResyncReason::DigestMismatch));
        assert!(dump(&s.conn).iter().all(|(_, rows)| rows.is_empty()));
        // The failed handshake did not consume epoch 1.
        assert_eq!(
            go(&mut s, &handshake(vec![item("a", "1")])),
            ack(1, 0, AckOutcome::Applied)
        );
    }

    #[test]
    fn digest_mismatch_on_repeat_handshake_keeps_the_old_state() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("a", "1")]));
        go(
            &mut s,
            &inc(
                1,
                1,
                vec![item("b", "1")],
                vec![],
                &[item("a", "1"), item("b", "1")],
            ),
        );
        let before = dump(&s.conn);

        let mut d = handshake(vec![item("z", "9")]);
        d.state_digest = [0; 32];
        assert_eq!(go(&mut s, &d), resync(1, 1, ResyncReason::DigestMismatch));
        assert_eq!(dump(&s.conn), before);
    }

    #[test]
    fn upgrade_is_remove_plus_upsert_in_one_delta() {
        let mut s = mem();
        go(
            &mut s,
            &handshake(vec![item("openssl", "3.0.1"), item("curl", "8")]),
        );
        let after = vec![item("curl", "8"), item("openssl", "3.0.2")];
        let d = inc(
            1,
            1,
            vec![item("openssl", "3.0.2")],
            vec![item("openssl", "3.0.1").key()],
            &after,
        );
        assert_eq!(go(&mut s, &d), ack(1, 1, AckOutcome::Applied));
        assert_eq!(stored(&s), after);
    }

    #[test]
    fn removing_an_absent_key_is_tolerated_and_digest_decides() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("a", "1")]));
        let d = inc(
            1,
            1,
            vec![],
            vec![item("ghost", "1").key()],
            &[item("a", "1")],
        );
        assert_eq!(go(&mut s, &d), ack(1, 1, AckOutcome::Applied));
    }

    #[test]
    fn upsert_of_an_existing_key_replaces_its_attributes() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("a", "1")]));
        let mut changed = item("a", "1");
        changed.vendor = Some("Acme".to_owned());
        changed.purl = Some("pkg:deb/debian/a@1".to_owned());
        changed.source_package = Some(SourcePackage {
            name: "a-src".to_owned(),
            version: Some(String::new()),
        });
        let d = inc(
            1,
            1,
            vec![changed.clone()],
            vec![],
            std::slice::from_ref(&changed),
        );
        assert_eq!(go(&mut s, &d), ack(1, 1, AckOutcome::Applied));
        assert_eq!(stored(&s), vec![changed]);
    }

    #[test]
    fn host_os_on_an_incremental_updates_the_stored_os() {
        let mut s = mem();
        go(&mut s, &handshake(vec![]));
        assert_eq!(read_os(&s.conn, "host-1"), Some(os("debian")));
        let mut d = inc(1, 1, vec![], vec![], &[]);
        d.host_os = Some(HostOs {
            id: "ubuntu".to_owned(),
            version_id: None,
            arch: "aarch64".to_owned(),
        });
        go(&mut s, &d);
        assert_eq!(
            read_os(&s.conn, "host-1"),
            Some(HostOs {
                id: "ubuntu".to_owned(),
                version_id: None,
                arch: "aarch64".to_owned()
            })
        );
    }

    fn read_os(conn: &Connection, host: &str) -> Option<HostOs> {
        conn.query_row(
            "SELECT os_id, os_version_id, os_arch FROM hosts WHERE host_id = ?1",
            [host],
            |r| {
                Ok(HostOs {
                    id: r.get(0)?,
                    version_id: r.get(1)?,
                    arch: r.get(2)?,
                })
            },
        )
        .optional()
        .unwrap()
    }

    #[test]
    fn host_mismatch_is_an_error_and_changes_nothing() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("a", "1")]));
        let before = dump(&s.conn);
        let other = HostId("host-2".to_owned());
        let r = apply(&mut s, &other, &handshake(vec![]), NOW);
        assert!(matches!(r, Err(ApplyError::HostMismatch)));
        let mut d = handshake(vec![]);
        d.host_id = other;
        let r = apply(&mut s, &host(), &d, NOW);
        assert!(matches!(r, Err(ApplyError::HostMismatch)));
        assert_eq!(dump(&s.conn), before);
    }

    #[test]
    fn full_snapshot_with_an_epoch_is_a_protocol_violation() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("a", "1")]));
        let before = dump(&s.conn);
        let mut d = handshake(vec![]);
        d.epoch = Epoch(1);
        d.seq = 5;
        assert!(matches!(
            apply(&mut s, &host(), &d, NOW),
            Err(ApplyError::SnapshotWithEpoch)
        ));
        assert_eq!(dump(&s.conn), before);
    }

    #[test]
    fn invalid_delta_is_rejected_before_touching_the_db() {
        let mut s = mem();
        let mut d = handshake(vec![item("a", "1")]);
        d.schema_version = 99;
        assert!(matches!(
            apply(&mut s, &host(), &d, NOW),
            Err(ApplyError::Invalid(ValidationError::UnsupportedSchema(99)))
        ));
        let mut d = handshake(vec![item("a", "1")]);
        d.upserted.push(item("a", "1"));
        assert!(matches!(
            apply(&mut s, &host(), &d, NOW),
            Err(ApplyError::Invalid(ValidationError::DuplicateKey))
        ));
        assert!(dump(&s.conn).iter().all(|(_, rows)| rows.is_empty()));
    }

    #[test]
    fn nul_bytes_never_reach_the_database() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("openssl", "3")]));
        let before = dump(&s.conn);

        let evil = item("openssl\0evil", "3");
        let r = apply(&mut s, &host(), &handshake(vec![evil.clone()]), NOW);
        assert!(matches!(
            r,
            Err(ApplyError::Invalid(ValidationError::NulByte("name")))
        ));
        let d = inc(1, 1, vec![evil], vec![], &[]);
        assert!(matches!(
            apply(&mut s, &host(), &d, NOW),
            Err(ApplyError::Invalid(ValidationError::NulByte("name")))
        ));
        let mut d = handshake(vec![]);
        d.host_os = Some(HostOs {
            id: "deb\0ian".to_owned(),
            version_id: None,
            arch: "x".to_owned(),
        });
        assert!(matches!(
            apply(&mut s, &host(), &d, NOW),
            Err(ApplyError::Invalid(ValidationError::NulByte("host_os.id")))
        ));
        assert_eq!(dump(&s.conn), before);

        // And none of the stored text columns contains one after normal use.
        let nul_rows: i64 = s
            .conn
            .query_row(
                "SELECT count(*) FROM software WHERE instr(CAST(name AS BLOB), x'00') > 0 \
                 OR instr(CAST(version AS BLOB), x'00') > 0 \
                 OR instr(CAST(source AS BLOB), x'00') > 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(nul_rows, 0);
    }

    #[test]
    fn hostile_strings_round_trip_intact() {
        let nasty = [
            "it's",
            "say \"hi\"",
            "a;b; DROP TABLE software;--",
            "' OR '1'='1",
            "back\\slash %_ wildcards",
            "ünïcödé 日本語 😀",
            "tab\tnewline\n",
        ];
        let items: Vec<SoftwareItem> = nasty
            .iter()
            .map(|n| {
                let mut i = item(n, n);
                i.arch = Some((*n).to_owned());
                i.vendor = Some((*n).to_owned());
                i.purl = Some((*n).to_owned());
                i.source = PackageSource::Other((*n).to_owned());
                i.source_package = Some(SourcePackage {
                    name: (*n).to_owned(),
                    version: Some((*n).to_owned()),
                });
                i
            })
            .collect();
        let mut s = mem();
        assert_eq!(
            go(&mut s, &handshake(items.clone())),
            ack(1, 0, AckOutcome::Applied)
        );
        let mut want = items;
        want.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        assert_eq!(stored(&s), want);
        // The schema still exists.
        assert_eq!(dump(&s.conn).len(), 3);
    }

    #[test]
    fn absent_and_empty_options_are_distinct_and_digest_identically() {
        let mk = |arch: Option<&str>, sp: Option<(&str, Option<&str>)>| SoftwareItem {
            name: "pkg".to_owned(),
            version: "1".to_owned(),
            arch: arch.map(str::to_owned),
            source: PackageSource::Rpm,
            source_package: sp.map(|(n, v)| SourcePackage {
                name: n.to_owned(),
                version: v.map(str::to_owned),
            }),
            vendor: None,
            purl: None,
        };
        let items = vec![
            mk(None, None),
            mk(Some(""), None),
            mk(Some("x"), Some(("src", None))),
            mk(Some("y"), Some(("src", Some("")))),
            mk(Some("z"), Some(("s", Some("")))),
        ];
        // Distinct keys: all five coexist even though three share name+version
        // and differ only by None vs "".
        assert_eq!(items.len(), 5);
        let mut s = mem();
        // `Applied` already means the digest recomputed from the rows matched.
        assert_eq!(
            go(&mut s, &handshake(items.clone())),
            ack(1, 0, AckOutcome::Applied)
        );

        let read = read_items(&s.conn, "host-1", false).unwrap();
        assert_eq!(read.len(), 5);
        for it in &items {
            assert!(read.contains(it), "{it:?}");
        }
        assert_eq!(digest(&read), digest(&items));
        // None and "" really are different values to the digest.
        assert_ne!(digest(&items[..1]), digest(&items[1..2]));
        assert_ne!(digest(&items[2..3]), digest(&items[3..4]));

        // The primary key rejects a true duplicate but not None vs "".
        let dup = s.conn.execute(
            "INSERT INTO software (host_id, source, name, arch_present, arch, version, \
             sp_present, sp_name, sp_version_present, sp_version) \
             VALUES ('host-1', 'rpm', 'pkg', 0, '', '1', 0, '', 0, '')",
            [],
        );
        assert!(dup.is_err());
        // A NULL arch cannot be smuggled in.
        let null = s.conn.execute(
            "INSERT INTO software (host_id, source, name, arch_present, arch, version, \
             sp_present, sp_name, sp_version_present, sp_version) \
             VALUES ('host-1', 'rpm', 'pkg', 0, NULL, '2', 0, '', 0, '')",
            [],
        );
        assert!(null.is_err());
    }

    #[test]
    fn other_source_named_like_a_builtin_stays_distinct() {
        let mut other = item("a", "1");
        other.source = PackageSource::Other("dpkg".to_owned());
        let items = vec![item("a", "1"), other];
        let mut s = mem();
        assert_eq!(
            go(&mut s, &handshake(items.clone())),
            ack(1, 0, AckOutcome::Applied)
        );
        assert_eq!(stored(&s).len(), 2);
    }

    #[test]
    fn hosts_are_isolated_from_each_other() {
        let mut s = mem();
        go(&mut s, &handshake(vec![item("a", "1")]));
        let h2 = HostId("host-2".to_owned());
        let mut d = handshake(vec![item("a", "1"), item("b", "1")]);
        d.host_id = h2.clone();
        assert_eq!(
            apply(&mut s, &h2, &d, NOW).unwrap(),
            ack(1, 0, AckOutcome::Applied)
        );
        assert_eq!(stored(&s), vec![item("a", "1")]);
    }

    #[test]
    fn dropped_transaction_leaves_the_old_state() {
        let tmp = TempDir::new();
        let path = tmp.path().join("inv.db");
        let before;
        {
            let mut s = Store::open(&path).unwrap();
            go(&mut s, &handshake(vec![item("a", "1")]));
            before = dump(&s.conn);

            // Apply an incremental and a handshake inside transactions that are
            // dropped without commit, as a crash before COMMIT would.
            let d = inc(
                1,
                1,
                vec![item("b", "1")],
                vec![item("a", "1").key()],
                &[item("b", "1")],
            );
            {
                let tx = s
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                assert!(matches!(
                    apply_in_tx(&tx, &d, 5).unwrap(),
                    Verdict::Commit(_)
                ));
            }
            {
                let tx = s
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                let h = handshake(vec![item("z", "9")]);
                assert!(matches!(
                    apply_in_tx(&tx, &h, 5).unwrap(),
                    Verdict::Commit(_)
                ));
            }
            assert_eq!(dump(&s.conn), before);
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(dump(&s.conn), before);
    }

    #[test]
    fn handshake_of_50k_items() {
        let items: Vec<SoftwareItem> = (0..MAX_ITEMS)
            .map(|i| {
                let mut it = item(&format!("package-name-{i}"), "1.2.3-4ubuntu5");
                it.source_package = Some(SourcePackage {
                    name: format!("source-{}", i / 3),
                    version: Some("1.2.3-4ubuntu5".to_owned()),
                });
                it
            })
            .collect();
        let tmp = TempDir::new();
        let mut store = Store::open(&tmp.path().join("inv.db")).unwrap();

        let d = handshake(items.clone());
        let started = Instant::now();
        let first = apply(&mut store, &host(), &d, NOW).unwrap();
        let handshake_time = started.elapsed();
        assert_eq!(first, ack(1, 0, AckOutcome::Applied));
        let count: i64 = store
            .conn
            .query_row("SELECT count(*) FROM software", [], |r| r.get(0))
            .unwrap();
        assert_eq!(usize::try_from(count), Ok(MAX_ITEMS));

        // One small incremental on the full host: shows the cost of the O(N)
        // digest recompute per delta.
        let mut after = items;
        after.push(item("one-more", "1"));
        let d = inc(1, 1, vec![item("one-more", "1")], vec![], &after);
        let started = Instant::now();
        assert_eq!(
            apply(&mut store, &host(), &d, NOW).unwrap(),
            ack(1, 1, AckOutcome::Applied)
        );
        let incremental_time = started.elapsed();
        println!(
            "50k handshake: {handshake_time:?}; 1-item incremental on 50k host: {incremental_time:?}"
        );
    }
}
