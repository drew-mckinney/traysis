//! Agent state persistence: the last server-acknowledged inventory.
//!
//! The state file is only ever written after an `Applied` ack (see
//! [`commit`]), so it describes what the server is known to hold. Anything
//! else (missing, empty, truncated, wrong version, wrong types, oversized, or
//! inconsistent with its own digest) loads as `None` and the caller sends a
//! full snapshot with [`Epoch::UNASSIGNED`].
//!
//! A state file or directory that is a symlink, or that is group- or
//! world-writable, is different: it may have been tampered with, so it is an
//! error ([`StateError::Insecure`]) and is never silently trusted or
//! overwritten. The owner (uid) is **not** verified, because that needs
//! `geteuid` (libc, rustix, or `unsafe`).
//!
//! # Delivery
//!
//! A delta that is sent but never acked leaves the on-disk state unchanged;
//! the next cycle recomputes a delta from the acked baseline, which may differ
//! from the lost one. That is safe only because [`AckOutcome::Duplicate`] and
//! [`AckOutcome::NeedResync`] both clear the state and force a handshake
//! instead of being confirmed. Persisting the in-flight delta for verbatim
//! retry is left to the daemon loop.
//!
//! An empty [`Diff`] is never committed, so `seq` does not advance for it.

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use traysis_proto::inventory::{AckOutcome, DeltaAck, Epoch, HostOs, SoftwareItem, state_digest};

use crate::differ::Diff;

/// Version of the on-disk format.
pub const STATE_VERSION: u32 = 1;
/// Largest state file read or written.
///
/// The worst valid snapshot is 32 MiB of strings (`MAX_DELTA_COST`) plus JSON
/// structure for 50,000 items (about 250 bytes each, about 12.5 MiB), roughly
/// 45 MiB; a typical 20,000-package host is 6 to 8 MiB. 64 MiB matches the
/// dpkg status cap. `save` refuses to write more, so state that cannot be
/// loaded back is never written.
pub const STATE_MAX_BYTES: u64 = 64 * 1024 * 1024;

const FILE_NAME: &str = "state.json";
const TMP_NAME: &str = "state.json.tmp";
#[cfg(target_os = "macos")]
const FALLBACK_DIR: &str = "/Library/Application Support/traysis";
#[cfg(not(target_os = "macos"))]
const FALLBACK_DIR: &str = "/var/lib/traysis";

/// The last server-acknowledged inventory. Package metadata only, no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckedState {
    pub version: u32,
    /// Server-assigned; never [`Epoch::UNASSIGNED`] in a valid state.
    pub epoch: Epoch,
    /// Sequence number of the last acked delta in this epoch.
    pub seq: u64,
    pub host_os: HostOs,
    pub items: Vec<SoftwareItem>,
    /// Canonical digest of `items`.
    pub state_digest: [u8; 32],
}

/// Why a state operation failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum StateError {
    Io(io::Error),
    /// The state file or directory is a symlink, not the expected type, or
    /// group- or world-writable.
    Insecure {
        path: PathBuf,
        reason: &'static str,
    },
    /// The ack does not match the delta it claims to acknowledge.
    AckMismatch,
    /// An empty diff must be dropped, never committed.
    EmptyDiff,
    /// The encoded state exceeds the size cap.
    TooLarge,
    Encode(serde_json::Error),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "state io error: {e}"),
            Self::Insecure { path, reason } => {
                write!(f, "insecure state path {}: {reason}", path.display())
            }
            Self::AckMismatch => f.write_str("ack does not match the delta"),
            Self::EmptyDiff => f.write_str("an empty diff must not be committed"),
            Self::TooLarge => f.write_str("state exceeds the size cap"),
            Self::Encode(e) => write!(f, "state encoding error: {e}"),
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Encode(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for StateError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Rejects symlinks, wrong file types, and group- or world-writable modes.
fn vet(path: &Path, meta: &Metadata, want_dir: bool) -> Result<(), StateError> {
    let insecure = |reason| StateError::Insecure {
        path: path.to_owned(),
        reason,
    };
    if meta.file_type().is_symlink() {
        return Err(insecure("is a symlink"));
    }
    if want_dir && !meta.is_dir() {
        return Err(insecure("is not a directory"));
    }
    if !want_dir && !meta.is_file() {
        return Err(insecure("is not a regular file"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(insecure("is group- or world-writable"));
    }
    Ok(())
}

/// Handle on the state directory.
#[derive(Debug, Clone)]
pub struct StateStore {
    dir: PathBuf,
}

impl StateStore {
    /// A store in `dir`. Tests use this to stay out of `/var/lib`.
    #[must_use]
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The platform location: `$STATE_DIRECTORY` if set, else the system default.
    #[must_use]
    pub fn default_location() -> Self {
        Self::at(location_from(
            std::env::var_os("STATE_DIRECTORY").as_deref(),
        ))
    }

    fn file_path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    /// Checks the directory, creating it `0700` if `create`. `Ok(false)` means
    /// it does not exist and was not created.
    fn check_dir(&self, create: bool) -> Result<bool, StateError> {
        let meta = match fs::symlink_metadata(&self.dir) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if !create {
                    return Ok(false);
                }
                DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&self.dir)?;
                fs::symlink_metadata(&self.dir)?
            }
            Err(e) => return Err(e.into()),
        };
        vet(&self.dir, &meta, true)?;
        Ok(true)
    }

    /// Loads the acked state.
    ///
    /// Returns `Ok(None)` when there is no usable state (missing, corrupt,
    /// wrong version, oversized, or failing its own digest), meaning the
    /// caller must resync.
    ///
    /// # Errors
    ///
    /// [`StateError::Insecure`] for a symlinked or group/world-writable
    /// directory or file; [`StateError::Io`] for other IO failures.
    pub fn load(&self) -> Result<Option<AckedState>, StateError> {
        self.load_with_cap(STATE_MAX_BYTES)
    }

    fn load_with_cap(&self, cap: u64) -> Result<Option<AckedState>, StateError> {
        if !self.check_dir(false)? {
            return Ok(None);
        }
        let path = self.file_path();
        let lmeta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        vet(&path, &lmeta, false)?;
        let file = File::open(&path)?;
        let fmeta = file.metadata()?;
        if (fmeta.dev(), fmeta.ino()) != (lmeta.dev(), lmeta.ino()) {
            return Err(StateError::Insecure {
                path,
                reason: "changed while being opened",
            });
        }
        let mut buf = Vec::new();
        file.take(cap.saturating_add(1)).read_to_end(&mut buf)?;
        if u64::try_from(buf.len()).unwrap_or(u64::MAX) > cap {
            return Ok(None);
        }
        Ok(parse_state(&buf))
    }

    /// Atomically replaces the state file.
    ///
    /// # Errors
    ///
    /// [`StateError::TooLarge`] if the encoding exceeds [`STATE_MAX_BYTES`]
    /// (the old state is left intact); [`StateError::Insecure`] for a bad
    /// directory; [`StateError::Io`] otherwise.
    pub fn save(&self, state: &AckedState) -> Result<(), StateError> {
        self.save_with_cap(state, STATE_MAX_BYTES)
    }

    fn save_with_cap(&self, state: &AckedState, cap: u64) -> Result<(), StateError> {
        let bytes = serde_json::to_vec(state).map_err(StateError::Encode)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > cap {
            return Err(StateError::TooLarge);
        }
        self.check_dir(true)?;

        let tmp = self.dir.join(TMP_NAME);
        // Remove a stale temp first (a symlink is removed, not followed), then
        // create_new so nothing that reappears can be reused or followed.
        match fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let written = (|| -> io::Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        if let Err(e) = fs::rename(&tmp, self.file_path()) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Deletes the state file so the next diff is a full snapshot.
    ///
    /// # Errors
    ///
    /// [`StateError::Insecure`] for a bad directory; [`StateError::Io`] otherwise.
    pub fn clear(&self) -> Result<(), StateError> {
        if !self.check_dir(false)? {
            return Ok(());
        }
        match fs::remove_file(self.file_path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// `$STATE_DIRECTORY` takes the first colon-separated entry (systemd may list several).
fn location_from(env: Option<&OsStr>) -> PathBuf {
    env.and_then(|v| std::env::split_paths(v).find(|p| !p.as_os_str().is_empty()))
        .unwrap_or_else(|| PathBuf::from(FALLBACK_DIR))
}

/// Parses and sanity-checks untrusted state bytes. Any problem is `None`.
fn parse_state(bytes: &[u8]) -> Option<AckedState> {
    let state: AckedState = serde_json::from_slice(bytes).ok()?;
    if state.version != STATE_VERSION || state.epoch.is_unassigned() {
        return None;
    }
    let digest = state_digest(&state.items).ok()?;
    (digest == state.state_digest).then_some(state)
}

/// Applies a server ack to the on-disk state.
///
/// - `Applied` persists the diff's snapshot. A handshake (epoch 0) ack must
///   carry a nonzero epoch and `seq == 0`; an incremental ack must echo the
///   delta's epoch and seq. Otherwise [`StateError::AckMismatch`] and the state
///   is untouched.
/// - `Duplicate`, `NeedResync`, and any outcome this version does not know
///   clear the state, so the next diff is a full handshake. A duplicate is not
///   confirmed because the delta recomputed from acked state can differ from
///   the one originally sent.
///
/// # Errors
///
/// [`StateError::EmptyDiff`] for an empty diff, [`StateError::AckMismatch`],
/// or any error from saving or clearing.
pub fn commit(store: &StateStore, diff: &Diff, ack: &DeltaAck) -> Result<(), StateError> {
    if diff.is_empty {
        return Err(StateError::EmptyDiff);
    }
    match ack.outcome {
        AckOutcome::Applied => {
            let delta = &diff.delta;
            let (epoch, seq) = if delta.epoch.is_unassigned() {
                if ack.epoch.is_unassigned() || ack.seq != 0 {
                    return Err(StateError::AckMismatch);
                }
                (ack.epoch, 0)
            } else {
                if ack.epoch != delta.epoch || ack.seq != delta.seq {
                    return Err(StateError::AckMismatch);
                }
                (delta.epoch, delta.seq)
            };
            store.save(&AckedState {
                version: STATE_VERSION,
                epoch,
                seq,
                host_os: diff.snapshot.host_os.clone(),
                items: diff.snapshot.items.clone(),
                state_digest: delta.state_digest,
            })
        }
        _ => store.clear(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use traysis_proto::inventory::{HostId, PackageSource, ResyncReason, UnixMillis};

    use super::*;
    use crate::differ::{Snapshot, diff};
    use crate::testutil::TempDir;

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

    fn state_of(items: Vec<SoftwareItem>) -> AckedState {
        AckedState {
            version: STATE_VERSION,
            epoch: Epoch(1),
            seq: 0,
            host_os: os(),
            state_digest: state_digest(&items).unwrap(),
            items,
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

    fn ack(epoch: u64, seq: u64, outcome: AckOutcome) -> DeltaAck {
        DeltaAck {
            epoch: Epoch(epoch),
            seq,
            outcome,
        }
    }

    fn store_in(tmp: &TempDir) -> StateStore {
        StateStore::at(tmp.path().join("state"))
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().mode() & 0o777
    }

    // Persistence and untrusted-content handling.

    #[test]
    fn round_trip_and_modes() {
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        let st = state_of(vec![item("a", "1"), item("b", "2")]);
        store.save(&st).unwrap();
        assert_eq!(store.load().unwrap(), Some(st));
        assert_eq!(mode(&store.dir), 0o700);
        assert_eq!(mode(&store.file_path()), 0o600);
        assert!(!store.dir.join(TMP_NAME).exists());
    }

    #[test]
    fn missing_dir_and_file_load_as_none() {
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        assert_eq!(store.load().unwrap(), None);
        fs::create_dir(&store.dir).unwrap();
        fs::set_permissions(&store.dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(store.load().unwrap(), None);
    }

    fn write_state_bytes(store: &StateStore, bytes: &[u8]) {
        store.save(&state_of(vec![])).unwrap();
        fs::write(store.file_path(), bytes).unwrap();
        fs::set_permissions(store.file_path(), fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn corrupt_content_loads_as_none() {
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        let good = serde_json::to_vec(&state_of(vec![item("a", "1")])).unwrap();
        let truncated = &good[..good.len() / 2];
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("truncated", truncated.to_vec()),
            ("garbage", vec![0xff, 0xfe, 0x00, 0x80, 0x12]),
            ("nul bytes", vec![0; 64]),
            ("not an object", b"[1,2,3]".to_vec()),
            (
                "wrong types",
                br#"{"version":"x","epoch":[],"seq":-1}"#.to_vec(),
            ),
            (
                "wrong version",
                String::from_utf8(good.clone())
                    .unwrap()
                    .replacen("\"version\":1", "\"version\":2", 1)
                    .into_bytes(),
            ),
            (
                "unassigned epoch",
                String::from_utf8(good.clone())
                    .unwrap()
                    .replacen("\"epoch\":1", "\"epoch\":0", 1)
                    .into_bytes(),
            ),
            (
                "digest mismatch",
                String::from_utf8(good.clone())
                    .unwrap()
                    .replacen("\"version\":\"1\"", "\"version\":\"9\"", 1)
                    .into_bytes(),
            ),
            ("deep nesting", "[".repeat(10_000).into_bytes()),
        ];
        for (name, bytes) in cases {
            write_state_bytes(&store, &bytes);
            assert_eq!(store.load().unwrap(), None, "{name}");
        }
    }

    #[test]
    fn the_good_fixture_is_actually_good() {
        // Guards the mutation cases above: each differs from this by one edit.
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        let st = state_of(vec![item("a", "1")]);
        write_state_bytes(&store, &serde_json::to_vec(&st).unwrap());
        assert_eq!(store.load().unwrap(), Some(st));
    }

    #[test]
    fn oversized_file_loads_as_none_and_save_refuses() {
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        let st = state_of(vec![item("a", "1")]);
        store.save(&st).unwrap();
        assert_eq!(store.load_with_cap(10).unwrap(), None);
        assert_eq!(store.load_with_cap(STATE_MAX_BYTES).unwrap(), Some(st));

        let bigger = state_of(vec![item("a", "1"), item("b", "2")]);
        assert!(matches!(
            store.save_with_cap(&bigger, 10),
            Err(StateError::TooLarge)
        ));
        // The old state survives a refused write.
        assert_eq!(store.load().unwrap(), Some(state_of(vec![item("a", "1")])));
    }

    // Hardening.

    #[test]
    fn symlinked_state_file_is_insecure() {
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        store.save(&state_of(vec![])).unwrap();
        let real = tmp.path().join("elsewhere.json");
        fs::copy(store.file_path(), &real).unwrap();
        fs::remove_file(store.file_path()).unwrap();
        symlink(&real, store.file_path()).unwrap();
        assert!(matches!(store.load(), Err(StateError::Insecure { .. })));
    }

    #[test]
    fn symlinked_state_dir_is_insecure() {
        let tmp = TempDir::new();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let store = store_in(&tmp);
        symlink(&real, &store.dir).unwrap();
        assert!(matches!(store.load(), Err(StateError::Insecure { .. })));
        assert!(matches!(
            store.save(&state_of(vec![])),
            Err(StateError::Insecure { .. })
        ));
        assert!(!real.join(FILE_NAME).exists());
    }

    #[test]
    fn group_writable_file_is_insecure() {
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        store.save(&state_of(vec![])).unwrap();
        fs::set_permissions(store.file_path(), fs::Permissions::from_mode(0o660)).unwrap();
        assert!(matches!(store.load(), Err(StateError::Insecure { .. })));
    }

    #[test]
    fn world_writable_dir_is_insecure() {
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        store.save(&state_of(vec![])).unwrap();
        fs::set_permissions(&store.dir, fs::Permissions::from_mode(0o757)).unwrap();
        assert!(matches!(store.load(), Err(StateError::Insecure { .. })));
        assert!(matches!(
            store.save(&state_of(vec![])),
            Err(StateError::Insecure { .. })
        ));
        assert!(matches!(store.clear(), Err(StateError::Insecure { .. })));
    }

    #[test]
    fn stale_temp_symlink_is_replaced_not_followed() {
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        store.save(&state_of(vec![])).unwrap();
        let victim = tmp.path().join("victim");
        fs::write(&victim, b"victim").unwrap();
        symlink(&victim, store.dir.join(TMP_NAME)).unwrap();

        let st = state_of(vec![item("a", "1")]);
        store.save(&st).unwrap();

        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert!(!store.dir.join(TMP_NAME).exists());
        let meta = fs::symlink_metadata(store.file_path()).unwrap();
        assert!(meta.is_file());
        assert_eq!(mode(&store.file_path()), 0o600);
        assert_eq!(store.load().unwrap(), Some(st));
    }

    #[test]
    fn stale_regular_temp_is_replaced() {
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        store.save(&state_of(vec![])).unwrap();
        let stale = store.dir.join(TMP_NAME);
        fs::write(&stale, b"junk from a crashed save").unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o666)).unwrap();

        let st = state_of(vec![item("a", "1")]);
        store.save(&st).unwrap();
        assert!(!stale.exists());
        assert_eq!(mode(&store.file_path()), 0o600);
        assert_eq!(store.load().unwrap(), Some(st));
    }

    #[test]
    fn clear_removes_state_and_tolerates_absence() {
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        store.clear().unwrap();
        store.save(&state_of(vec![])).unwrap();
        store.clear().unwrap();
        assert_eq!(store.load().unwrap(), None);
    }

    #[test]
    fn location_prefers_first_state_directory_entry() {
        assert_eq!(
            location_from(Some(OsStr::new("/run/a:/run/b"))),
            PathBuf::from("/run/a")
        );
        assert_eq!(
            location_from(Some(OsStr::new(""))),
            PathBuf::from(FALLBACK_DIR)
        );
        assert_eq!(location_from(None), PathBuf::from(FALLBACK_DIR));
    }

    // Commit and ack handling.

    /// Handshake-commits `items` at epoch 5 and returns the store.
    fn committed(tmp: &TempDir, items: Vec<SoftwareItem>) -> StateStore {
        let store = store_in(tmp);
        let first = diff(&host(), None, snap(items), UnixMillis(1)).unwrap();
        commit(&store, &first, &ack(5, 0, AckOutcome::Applied)).unwrap();
        store
    }

    #[test]
    fn applied_handshake_takes_epoch_from_ack() {
        let tmp = TempDir::new();
        let store = committed(&tmp, vec![item("a", "1")]);
        let st = store.load().unwrap().unwrap();
        assert_eq!((st.epoch, st.seq), (Epoch(5), 0));
        assert_eq!(st.items, vec![item("a", "1")]);
    }

    #[test]
    fn duplicate_clears_state_and_forces_handshake() {
        let tmp = TempDir::new();
        let store = committed(&tmp, vec![item("a", "1")]);
        let prev = store.load().unwrap().unwrap();
        let d = diff(
            &host(),
            Some(&prev),
            snap(vec![item("a", "1"), item("b", "1")]),
            UnixMillis(2),
        )
        .unwrap();
        commit(&store, &d, &ack(5, 1, AckOutcome::Duplicate)).unwrap();

        assert_eq!(store.load().unwrap(), None);
        let next = diff(&host(), None, snap(vec![item("a", "1")]), UnixMillis(3)).unwrap();
        assert!(next.delta.full);
        assert_eq!(next.delta.epoch, Epoch::UNASSIGNED);
    }

    #[test]
    fn need_resync_clears_state() {
        let tmp = TempDir::new();
        let store = committed(&tmp, vec![item("a", "1")]);
        let prev = store.load().unwrap().unwrap();
        let d = diff(&host(), Some(&prev), snap(vec![]), UnixMillis(2)).unwrap();
        let nack = ack(5, 1, AckOutcome::NeedResync(ResyncReason::SeqGap));
        commit(&store, &d, &nack).unwrap();
        assert_eq!(store.load().unwrap(), None);
    }

    #[test]
    fn handshake_ack_must_have_nonzero_epoch_and_seq_zero() {
        let tmp = TempDir::new();
        let store = store_in(&tmp);
        let first = diff(&host(), None, snap(vec![item("a", "1")]), UnixMillis(1)).unwrap();
        for bad in [
            ack(0, 0, AckOutcome::Applied),
            ack(5, 1, AckOutcome::Applied),
        ] {
            assert!(matches!(
                commit(&store, &first, &bad),
                Err(StateError::AckMismatch)
            ));
            assert_eq!(store.load().unwrap(), None);
        }
    }

    #[test]
    fn incremental_ack_must_echo_epoch_and_seq() {
        let tmp = TempDir::new();
        let store = committed(&tmp, vec![item("a", "1")]);
        let before = fs::read(store.file_path()).unwrap();
        let prev = store.load().unwrap().unwrap();
        let d = diff(&host(), Some(&prev), snap(vec![]), UnixMillis(2)).unwrap();
        for bad in [
            ack(6, 1, AckOutcome::Applied),
            ack(5, 2, AckOutcome::Applied),
            ack(5, 0, AckOutcome::Applied),
        ] {
            assert!(matches!(
                commit(&store, &d, &bad),
                Err(StateError::AckMismatch)
            ));
            assert_eq!(fs::read(store.file_path()).unwrap(), before);
        }
        commit(&store, &d, &ack(5, 1, AckOutcome::Applied)).unwrap();
        assert_eq!(store.load().unwrap().unwrap().seq, 1);
    }

    #[test]
    fn empty_diff_is_not_committable_and_seq_does_not_advance() {
        let tmp = TempDir::new();
        let store = committed(&tmp, vec![item("a", "1")]);
        let before = fs::read(store.file_path()).unwrap();
        let prev = store.load().unwrap().unwrap();

        let empty = diff(
            &host(),
            Some(&prev),
            snap(vec![item("a", "1")]),
            UnixMillis(2),
        )
        .unwrap();
        assert!(empty.is_empty);
        assert!(matches!(
            commit(&store, &empty, &ack(5, 1, AckOutcome::Applied)),
            Err(StateError::EmptyDiff)
        ));
        assert_eq!(fs::read(store.file_path()).unwrap(), before);

        let real = diff(&host(), Some(&prev), snap(vec![]), UnixMillis(3)).unwrap();
        assert_eq!(real.delta.seq, prev.seq + 1);
    }

    #[test]
    fn unacked_delta_leaves_state_untouched_and_is_recomputed() {
        let tmp = TempDir::new();
        let store = committed(&tmp, vec![item("a", "1")]);
        let before = fs::read(store.file_path()).unwrap();
        let prev = store.load().unwrap().unwrap();

        // Sent, never acked: nothing is committed.
        let lost = diff(
            &host(),
            Some(&prev),
            snap(vec![item("a", "1"), item("b", "1")]),
            UnixMillis(2),
        )
        .unwrap();
        assert_eq!(fs::read(store.file_path()).unwrap(), before);

        // The machine changed meanwhile; the recomputed delta is relative to
        // the acked baseline and may differ from the lost one.
        let retry = diff(
            &host(),
            Some(&prev),
            snap(vec![item("a", "1"), item("c", "1")]),
            UnixMillis(3),
        )
        .unwrap();
        assert_eq!(retry.delta.seq, lost.delta.seq);
        assert_ne!(retry.delta.upserted, lost.delta.upserted);
    }

    #[test]
    fn failed_save_leaves_old_state_intact() {
        let tmp = TempDir::new();
        let store = committed(&tmp, vec![item("a", "1")]);
        let before = fs::read(store.file_path()).unwrap();
        let bigger = state_of(vec![item("a", "1"), item("b", "2")]);
        assert!(store.save_with_cap(&bigger, 10).is_err());
        assert_eq!(fs::read(store.file_path()).unwrap(), before);
    }
}
