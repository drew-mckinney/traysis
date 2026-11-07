//! The Differ: turns a collected snapshot into a [`SoftwareDelta`].
//!
//! Pure logic: no IO and no clock reads (the caller passes `now`).
//!
//! # Partial snapshots fail closed
//!
//! If the collector reported any malformed input ([`Snapshot::malformed`] `> 0`),
//! [`diff`] returns [`DiffError::PartialSnapshot`] and produces no delta. A
//! malformed stanza makes an installed package vanish from the snapshot, which
//! would be reported as a spurious removal (or, in a full snapshot, a missing
//! item that corrupts the server's baseline). A host with a persistently
//! malformed entry therefore sends nothing until it is fixed, so the caller
//! must alert on this error rather than retry silently.
//!
//! # Empty diffs
//!
//! An incremental diff with no changes has [`Diff::is_empty`] set. The caller
//! must drop it: do not send it and do not commit it ([`crate::state::commit`]
//! refuses). `seq` therefore does not advance, and the next real delta is
//! still `previous seq + 1`, so the server sees no gap.

use std::collections::{HashMap, HashSet};
use std::fmt;

use traysis_proto::inventory::{
    Epoch, HostId, HostOs, SCHEMA_VERSION, SoftwareDelta, SoftwareItem, SoftwareKey, UnixMillis,
    ValidationError, state_digest,
};

use crate::state::AckedState;

/// A collected inventory plus the quality counts from collecting it.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub items: Vec<SoftwareItem>,
    pub host_os: HostOs,
    /// Input that failed parsing. Nonzero makes the snapshot partial.
    pub malformed: usize,
    /// Valid entries deliberately left out (for example dpkg `config-files`).
    /// Expected on healthy hosts; informational.
    pub excluded: usize,
}

#[cfg(target_os = "linux")]
impl Snapshot {
    /// Builds a snapshot from `DpkgCollector::software_with_stats`, keeping
    /// its [`ParseStats`](crate::collector::linux::ParseStats).
    #[must_use]
    pub fn from_dpkg(
        items: Vec<SoftwareItem>,
        stats: crate::collector::linux::ParseStats,
        host_os: HostOs,
    ) -> Self {
        Self {
            items,
            host_os,
            malformed: stats.malformed,
            excluded: stats.excluded,
        }
    }
}

/// The result of diffing a snapshot against the acked state.
#[derive(Debug, Clone)]
pub struct Diff {
    /// Already passed [`SoftwareDelta::validate`].
    pub delta: SoftwareDelta,
    /// Incremental with nothing to report. Drop it: do not send, do not commit.
    pub is_empty: bool,
    /// Entries excluded from the snapshot; informational.
    pub excluded: usize,
    pub(crate) snapshot: Snapshot,
}

/// Why no delta could be produced.
#[derive(Debug)]
#[non_exhaustive]
pub enum DiffError {
    /// The snapshot is partial because the collector saw malformed input.
    /// Nothing is sent; the caller should alert.
    PartialSnapshot { malformed: usize, excluded: usize },
    /// The snapshot or resulting delta violates protocol limits or invariants.
    Invalid(ValidationError),
    /// `seq` cannot be incremented.
    SeqOverflow,
}

impl fmt::Display for DiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartialSnapshot {
                malformed,
                excluded,
            } => write!(
                f,
                "partial snapshot: {malformed} malformed entries ({excluded} excluded); nothing sent"
            ),
            Self::Invalid(e) => write!(f, "invalid snapshot: {e}"),
            Self::SeqOverflow => f.write_str("delta sequence number overflow"),
        }
    }
}

impl std::error::Error for DiffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(e) => Some(e),
            _ => None,
        }
    }
}

fn sort_items(items: &mut [SoftwareItem]) {
    items.sort_by_cached_key(|i| {
        (
            format!("{:?}", i.source),
            i.name.clone(),
            i.arch.clone(),
            i.version.clone(),
        )
    });
}

fn sort_keys(keys: &mut [SoftwareKey]) {
    keys.sort_by_cached_key(|k| {
        (
            format!("{:?}", k.source),
            k.name.clone(),
            k.arch.clone(),
            k.version.clone(),
        )
    });
}

/// Diffs `snap` against `prev`, the last acked state (`None` means send a
/// full snapshot with an unassigned epoch).
///
/// # Errors
///
/// [`DiffError::PartialSnapshot`] if `snap.malformed > 0`;
/// [`DiffError::Invalid`] for duplicate keys, over-cap snapshots, or any other
/// protocol violation (never truncated); [`DiffError::SeqOverflow`].
pub fn diff(
    host: &HostId,
    prev: Option<&AckedState>,
    snap: Snapshot,
    now: UnixMillis,
) -> Result<Diff, DiffError> {
    if snap.malformed > 0 {
        return Err(DiffError::PartialSnapshot {
            malformed: snap.malformed,
            excluded: snap.excluded,
        });
    }
    let digest = state_digest(&snap.items).map_err(DiffError::Invalid)?;

    let (epoch, seq, full, host_os, upserted, removed) = match prev {
        None => {
            let mut upserted = snap.items.clone();
            sort_items(&mut upserted);
            (
                Epoch::UNASSIGNED,
                0,
                true,
                Some(snap.host_os.clone()),
                upserted,
                Vec::new(),
            )
        }
        Some(p) => {
            let old: HashMap<SoftwareKey, &SoftwareItem> =
                p.items.iter().map(|i| (i.key(), i)).collect();
            let mut new_keys: HashSet<SoftwareKey> = HashSet::with_capacity(snap.items.len());
            let mut upserted = Vec::new();
            for item in &snap.items {
                let key = item.key();
                if old.get(&key).is_none_or(|o| *o != item) {
                    upserted.push(item.clone());
                }
                new_keys.insert(key);
            }
            let mut removed: Vec<SoftwareKey> = old
                .keys()
                .filter(|k| !new_keys.contains(*k))
                .cloned()
                .collect();
            sort_items(&mut upserted);
            sort_keys(&mut removed);
            let host_os = (p.host_os != snap.host_os).then(|| snap.host_os.clone());
            let seq = p.seq.checked_add(1).ok_or(DiffError::SeqOverflow)?;
            (p.epoch, seq, false, host_os, upserted, removed)
        }
    };

    let is_empty = !full && upserted.is_empty() && removed.is_empty() && host_os.is_none();
    let delta = SoftwareDelta {
        schema_version: SCHEMA_VERSION,
        host_id: host.clone(),
        epoch,
        seq,
        full,
        host_os,
        collected_at: now,
        upserted,
        removed,
        state_digest: digest,
    };
    delta.validate().map_err(DiffError::Invalid)?;
    Ok(Diff {
        delta,
        is_empty,
        excluded: snap.excluded,
        snapshot: snap,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use traysis_proto::inventory::{AckOutcome, DeltaAck};
    use traysis_proto::inventory::{MAX_ITEMS, PackageSource, SourcePackage};

    use super::*;
    #[cfg(target_os = "linux")]
    use crate::state::{StateError, StateStore, commit};
    #[cfg(target_os = "linux")]
    use crate::testutil::TempDir;

    // The first test: the real machine's inventory, collected twice, must
    // produce an empty delta the second time. It reads this machine's dpkg
    // database, so it is `#[ignore]`d; the CI twin below runs the same flow on
    // a fixture.

    /// Collect, diff, ack, persist, reload, collect again, diff again.
    #[cfg(target_os = "linux")]
    fn second_run_is_empty(collect: impl Fn() -> Snapshot) {
        let tmp = TempDir::new();
        let store = StateStore::at(tmp.path().join("state"));
        let host = HostId("test-host".to_owned());

        let first = diff(&host, None, collect(), UnixMillis(1))
            .expect("first snapshot must not be partial; see the error for counts");
        assert!(first.delta.full);
        assert!(!first.is_empty);
        assert_eq!(first.delta.epoch, Epoch::UNASSIGNED);
        assert_eq!(first.delta.seq, 0);
        assert_ne!(first.delta.upserted.len(), 0);
        eprintln!(
            "first snapshot: {} items, {} excluded",
            first.delta.upserted.len(),
            first.excluded
        );

        let applied = DeltaAck {
            epoch: Epoch(1),
            seq: 0,
            outcome: AckOutcome::Applied,
        };
        commit(&store, &first, &applied).expect("applied handshake must commit");
        let loaded = store
            .load()
            .expect("state dir is ours and private")
            .expect("state was just committed");

        let second = diff(&host, Some(&loaded), collect(), UnixMillis(2))
            .expect("second snapshot must not be partial");
        assert!(
            second.is_empty,
            "second run produced changes: {:?}",
            second.delta
        );
        assert_eq!(second.delta.upserted.len(), 0);
        assert_eq!(second.delta.removed.len(), 0);
        assert!(second.delta.host_os.is_none());
        assert_eq!(second.delta.seq, 1);
        assert_eq!(second.delta.state_digest, first.delta.state_digest);
        assert_eq!(second.excluded, first.excluded);

        // An empty diff is never committable, so seq does not advance.
        assert!(matches!(
            commit(
                &store,
                &second,
                &DeltaAck {
                    epoch: Epoch(1),
                    seq: 1,
                    outcome: AckOutcome::Applied
                }
            ),
            Err(StateError::EmptyDiff)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "reads this machine's /var/lib/dpkg/status"]
    fn real_machine_second_run_is_empty() {
        use crate::collector::Collector;
        use crate::collector::linux::{DpkgCollector, OsReleaseCollector};

        second_run_is_empty(|| {
            let (items, stats) = DpkgCollector::new()
                .software_with_stats()
                .expect("this machine's dpkg status must be readable");
            let os = OsReleaseCollector::new()
                .host_os()
                .expect("this machine's os-release must be readable");
            Snapshot::from_dpkg(items, stats, os)
        });
    }

    #[cfg(target_os = "linux")]
    mod fixture {
        use std::io::Cursor;

        use super::*;
        use crate::collector::linux::dpkg::collect_from_reader;

        pub fn stanza(name: &str, version: &str, status: &str, extra: &str) -> String {
            format!(
                "Package: {name}\nStatus: {status}\nArchitecture: amd64\nVersion: {version}\n{extra}\n"
            )
        }

        pub fn installed(name: &str, version: &str) -> String {
            stanza(name, version, "install ok installed", "")
        }

        pub fn snapshot(status_file: &str) -> Snapshot {
            let (items, stats) =
                collect_from_reader(Cursor::new(status_file.as_bytes())).expect("fixture parses");
            Snapshot::from_dpkg(items, stats, os())
        }

        pub fn healthy() -> String {
            let mut s = String::new();
            for (n, v) in [("bash", "5.2"), ("libc6", "2.36"), ("zlib1g", "1.2.13")] {
                s.push_str(&installed(n, v));
            }
            // Excluded, not malformed.
            s.push_str(&stanza("gone", "1", "deinstall ok config-files", ""));
            s
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fixture_second_run_is_empty() {
        let status = fixture::healthy();
        second_run_is_empty(|| fixture::snapshot(&status));
    }

    // Helpers for plain-snapshot tests.

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

    fn os() -> HostOs {
        HostOs {
            id: "debian".to_owned(),
            version_id: Some("12".to_owned()),
            arch: "x86_64".to_owned(),
        }
    }

    fn snap(items: Vec<SoftwareItem>) -> Snapshot {
        Snapshot {
            items,
            host_os: os(),
            malformed: 0,
            excluded: 0,
        }
    }

    fn host() -> HostId {
        HostId("host-1".to_owned())
    }

    fn acked(items: Vec<SoftwareItem>) -> AckedState {
        AckedState {
            version: crate::state::STATE_VERSION,
            epoch: Epoch(5),
            seq: 3,
            host_os: os(),
            state_digest: state_digest(&items).unwrap(),
            items,
        }
    }

    fn incremental(prev: &AckedState, items: Vec<SoftwareItem>) -> Diff {
        diff(&host(), Some(prev), snap(items), UnixMillis(9)).unwrap()
    }

    #[test]
    fn full_snapshot_has_unassigned_epoch_and_everything_upserted() {
        let d = diff(
            &host(),
            None,
            snap(vec![item("b", "1"), item("a", "1")]),
            UnixMillis(9),
        )
        .unwrap();
        assert!(d.delta.full && !d.is_empty);
        assert_eq!((d.delta.epoch, d.delta.seq), (Epoch::UNASSIGNED, 0));
        assert_eq!(d.delta.host_os, Some(os()));
        assert_eq!(d.delta.upserted, vec![item("a", "1"), item("b", "1")]);
        assert_eq!(d.delta.removed.len(), 0);
        assert_eq!(d.delta.collected_at, UnixMillis(9));
    }

    #[test]
    fn upgrade_is_remove_plus_upsert() {
        let prev = acked(vec![item("openssl", "3.0.1"), item("bash", "5")]);
        let d = incremental(&prev, vec![item("openssl", "3.0.2"), item("bash", "5")]);
        assert_eq!(d.delta.removed, vec![item("openssl", "3.0.1").key()]);
        assert_eq!(d.delta.upserted, vec![item("openssl", "3.0.2")]);
        assert_eq!((d.delta.epoch, d.delta.seq), (Epoch(5), 4));
        assert!(!d.delta.full && !d.is_empty);
    }

    #[test]
    fn two_kernel_versions_coexist() {
        let prev = acked(vec![item("kernel", "6.1.1")]);
        let d = incremental(
            &prev,
            vec![item("kernel", "6.1.1"), item("kernel", "6.1.2")],
        );
        assert_eq!(d.delta.upserted, vec![item("kernel", "6.1.2")]);
        assert_eq!(d.delta.removed.len(), 0);
    }

    #[test]
    fn non_key_change_is_an_upsert_without_removal() {
        let prev = acked(vec![item("a", "1")]);
        let mut changed = item("a", "1");
        changed.source_package = Some(SourcePackage {
            name: "a-src".to_owned(),
            version: None,
        });
        let d = incremental(&prev, vec![changed.clone()]);
        assert_eq!(d.delta.upserted, vec![changed]);
        assert_eq!(d.delta.removed.len(), 0);
    }

    #[test]
    fn input_order_is_irrelevant() {
        let prev = acked(vec![item("a", "1")]);
        let x = incremental(&prev, vec![item("a", "1"), item("b", "1"), item("c", "1")]);
        let y = incremental(&prev, vec![item("c", "1"), item("a", "1"), item("b", "1")]);
        assert_eq!(x.delta, y.delta);
    }

    #[test]
    fn delta_digest_covers_the_post_apply_set() {
        let prev = acked(vec![item("a", "1")]);
        let items = vec![item("a", "1"), item("b", "2")];
        let d = incremental(&prev, items.clone());
        assert_eq!(d.delta.state_digest, state_digest(&items).unwrap());
    }

    #[test]
    fn host_os_change_is_carried_only_when_different() {
        let prev = acked(vec![item("a", "1")]);
        assert!(
            incremental(&prev, vec![item("a", "1")])
                .delta
                .host_os
                .is_none()
        );

        let mut s = snap(vec![item("a", "1")]);
        s.host_os.version_id = Some("13".to_owned());
        let d = diff(&host(), Some(&prev), s, UnixMillis(9)).unwrap();
        assert_eq!(
            d.delta
                .host_os
                .as_ref()
                .and_then(|o| o.version_id.as_deref()),
            Some("13")
        );
        assert!(!d.is_empty, "an OS change alone is still worth sending");
    }

    #[test]
    fn duplicate_keys_and_over_cap_snapshots_are_invalid_not_truncated() {
        let dup = diff(
            &host(),
            None,
            snap(vec![item("a", "1"), item("a", "1")]),
            UnixMillis(9),
        );
        assert!(matches!(
            dup,
            Err(DiffError::Invalid(ValidationError::DuplicateKey))
        ));

        let many = (0..=MAX_ITEMS)
            .map(|i| item(&format!("p{i}"), "1"))
            .collect();
        assert!(matches!(
            diff(&host(), None, snap(many), UnixMillis(9)),
            Err(DiffError::Invalid(ValidationError::TooManyItems(
                "upserted"
            )))
        ));
    }

    #[test]
    fn seq_overflow_is_an_error() {
        let mut prev = acked(vec![]);
        prev.seq = u64::MAX;
        assert!(matches!(
            diff(&host(), Some(&prev), snap(vec![]), UnixMillis(9)),
            Err(DiffError::SeqOverflow)
        ));
    }

    #[test]
    fn partial_snapshot_fails_closed_on_both_paths() {
        let mut s = snap(vec![item("a", "1")]);
        s.malformed = 2;
        s.excluded = 7;

        let full = diff(&host(), None, s.clone(), UnixMillis(9));
        assert!(matches!(
            full,
            Err(DiffError::PartialSnapshot {
                malformed: 2,
                excluded: 7
            })
        ));

        let prev = acked(vec![item("a", "1"), item("b", "1")]);
        let inc = diff(&host(), Some(&prev), s, UnixMillis(9));
        assert!(matches!(
            inc,
            Err(DiffError::PartialSnapshot {
                malformed: 2,
                excluded: 7
            })
        ));
        let msg = inc.err().map(|e| e.to_string()).unwrap();
        assert!(
            msg.contains("2 malformed") && msg.contains("nothing sent"),
            "{msg}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_dpkg_stanza_surfaces_through_the_collector_stats() {
        let mut status = fixture::healthy();
        status.push_str("Package: broken\nthis line has no colon\n\n");
        let s = fixture::snapshot(&status);
        assert_eq!(s.malformed, 1);
        assert!(matches!(
            diff(&host(), None, s, UnixMillis(9)),
            Err(DiffError::PartialSnapshot {
                malformed: 1,
                excluded: 1
            })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn excluded_stanzas_alone_do_not_block_a_diff() {
        let s = fixture::snapshot(&fixture::healthy());
        assert_eq!((s.malformed, s.excluded), (0, 1));
        let d = diff(&host(), None, s, UnixMillis(9)).unwrap();
        assert_eq!(d.delta.upserted.len(), 3);
        assert_eq!(d.excluded, 1);
    }
}
