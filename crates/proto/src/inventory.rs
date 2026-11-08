//! Software inventory wire types.
//!
//! An agent pushes [`SoftwareDelta`]s to the server; the server answers each
//! with a [`DeltaAck`]. Everything here is platform-agnostic and is treated as
//! untrusted input on the receiving side: call [`SoftwareDelta::validate`]
//! before using a decoded delta.
//!
//! Deliberately absent: command lines, environment, user file paths, and
//! install-script output (see the redaction rule in `CLAUDE.md`).
//!
//! # Epoch rule
//!
//! The agent never mints or increments an [`Epoch`]; the server assigns it.
//! An agent with no valid epoch (first run, lost or corrupt state, or told to
//! resync) sends a full snapshot with [`Epoch::UNASSIGNED`]. The server issues
//! a new epoch strictly greater than any it previously issued to that host,
//! applies the snapshot as `seq = 0`, and returns the epoch in
//! [`DeltaAck::epoch`]. The agent persists an epoch only from an ack.
//!
//! # Limits
//!
//! Per-delta caps ([`MAX_ITEMS`], [`MAX_STRING_LEN`]) are sized to hold a full
//! snapshot. Version 1 does not chunk snapshots; an agent whose snapshot
//! exceeds the caps must fail loudly instead of truncating, since truncation
//! would corrupt the state digest. Chunking would be a [`SCHEMA_VERSION`] bump.
//! The proto crate has no encoded size to check (the byte encoding is chosen
//! later), so [`MAX_DELTA_COST`] bounds the sum of string lengths plus
//! [`PER_ITEM_OVERHEAD`] per entry instead. The transport layer enforces its
//! own frame limit.
//!
//! # Handshake `seq`
//!
//! The agent sends `seq = 0` with `epoch = 0`; [`SoftwareDelta::validate`]
//! rejects any other `seq` on an unassigned epoch. The server ignores the
//! agent's value and applies the snapshot as `seq = 0` of the epoch it issues.
//!
//! # NUL bytes
//!
//! [`SoftwareDelta::validate`] rejects a NUL byte in every string field
//! ([`ValidationError::NulByte`]). Downstream consumers (C APIs, SQL string
//! functions, log tooling) may truncate at NUL, so a name like
//! `openssl\0evil` would display or match as `openssl`.
//!
//! # Clocks
//!
//! `collected_at` is the agent's clock and is untrusted and informational
//! only. The server records its own receive time and uses that for staleness
//! and ordering decisions.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version carried in every [`SoftwareDelta`].
pub const SCHEMA_VERSION: u16 = 1;
/// Maximum entries in each of `upserted` and `removed`; large enough for a full snapshot.
pub const MAX_ITEMS: usize = 50_000;
/// Maximum length in bytes of any string field.
pub const MAX_STRING_LEN: usize = 4096;
/// Fixed cost charged per `upserted` or `removed` entry toward [`MAX_DELTA_COST`].
pub const PER_ITEM_OVERHEAD: usize = 64;
/// Maximum total cost of a delta: the sum of all string lengths plus
/// [`PER_ITEM_OVERHEAD`] per entry. Sized to hold a full snapshot.
pub const MAX_DELTA_COST: usize = 32 * 1024 * 1024;

/// Domain-separation prefix of the canonical state digest.
const DIGEST_PREFIX: &[u8] = b"traysis.software.v1\0";

/// Opaque host identifier issued at enrollment and bound to the mTLS identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HostId(pub String);

/// Server-assigned generation of a host's delta stream. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Epoch(pub u64);

impl Epoch {
    /// "No epoch yet"; valid only on full snapshots.
    pub const UNASSIGNED: Epoch = Epoch(0);

    /// Whether this is [`Epoch::UNASSIGNED`].
    #[must_use]
    pub fn is_unassigned(self) -> bool {
        self == Self::UNASSIGNED
    }
}

/// Milliseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnixMillis(pub u64);

/// Where a package came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PackageSource {
    Dpkg,
    Rpm,
    Apk,
    Pacman,
    Brew,
    Other(String),
}

impl PackageSource {
    /// Canonical lowercase tag used in the state digest.
    fn tag(&self) -> String {
        match self {
            Self::Dpkg => "dpkg".to_owned(),
            Self::Rpm => "rpm".to_owned(),
            Self::Apk => "apk".to_owned(),
            Self::Pacman => "pacman".to_owned(),
            Self::Brew => "brew".to_owned(),
            Self::Other(s) => format!("other:{s}"),
        }
    }
}

/// The source package a binary package was built from (dpkg `Source:`, rpm `SOURCERPM`).
///
/// Distro advisories key on source packages; the server matches on this when
/// present and falls back to the binary package name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourcePackage {
    pub name: String,
    pub version: Option<String>,
}

/// One installed software package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareItem {
    pub name: String,
    pub version: String,
    pub arch: Option<String>,
    pub source: PackageSource,
    pub source_package: Option<SourcePackage>,
    pub vendor: Option<String>,
    /// Package URL. Computed by the server from the host OS and this item.
    /// Collectors set it only when the ecosystem natively provides it; the
    /// server treats it as an untrusted hint. Not part of the state digest.
    pub purl: Option<String>,
}

impl SoftwareItem {
    /// The identity of this item.
    #[must_use]
    pub fn key(&self) -> SoftwareKey {
        SoftwareKey {
            source: self.source.clone(),
            name: self.name.clone(),
            arch: self.arch.clone(),
            version: self.version.clone(),
        }
    }
}

/// Identity of an installed package.
///
/// The version is part of the key for every source, so several installed
/// versions of one name (rpm installonly packages such as kernels) coexist
/// without special cases. An upgrade is a `removed` old key plus an
/// `upserted` new item in the same delta.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SoftwareKey {
    pub source: PackageSource,
    pub name: String,
    pub arch: Option<String>,
    pub version: String,
}

/// Host-level OS release, used for ecosystem and distro matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostOs {
    /// os-release `ID` (for example `debian`), or `macos`.
    pub id: String,
    /// os-release `VERSION_ID`, or the macOS product version.
    pub version_id: Option<String>,
    /// Machine architecture.
    pub arch: String,
}

/// An inventory update from one agent.
///
/// The server applies `removed` first, then `upserted`, atomically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwareDelta {
    pub schema_version: u16,
    pub host_id: HostId,
    pub epoch: Epoch,
    /// Monotonic within an epoch; a full snapshot that opens an epoch is `seq = 0`.
    pub seq: u64,
    /// A full snapshot replaces the server's state for the host.
    pub full: bool,
    /// Required when `full`; on an incremental delta it signals an OS change.
    pub host_os: Option<HostOs>,
    /// The agent's clock: untrusted and informational only. The server records
    /// its own receive time for staleness and ordering.
    pub collected_at: UnixMillis,
    pub upserted: Vec<SoftwareItem>,
    pub removed: Vec<SoftwareKey>,
    /// Digest of the post-apply inventory; see [`state_digest`].
    pub state_digest: [u8; 32],
}

/// Server response to a [`SoftwareDelta`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaAck {
    /// The epoch now in force; on a handshake this is the newly assigned one.
    pub epoch: Epoch,
    pub seq: u64,
    pub outcome: AckOutcome,
}

/// Result of applying a delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AckOutcome {
    Applied,
    /// Same epoch and `seq <= last applied`; safe to treat as success.
    Duplicate,
    /// Send a full snapshot with [`Epoch::UNASSIGNED`].
    NeedResync(ResyncReason),
}

/// Why the server wants a resync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ResyncReason {
    DigestMismatch,
    SeqGap,
    EpochStale,
    StateUnknown,
}

/// Why a decoded message was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    UnsupportedSchema(u16),
    EmptyField(&'static str),
    StringTooLong(&'static str),
    TooManyItems(&'static str),
    DeltaTooLarge,
    HandshakeSeqNotZero,
    DuplicateKey,
    KeyBothRemovedAndUpserted,
    UnassignedEpochOnIncremental,
    MissingHostOs,
    FullSnapshotWithRemovals,
    /// A string field contains a NUL byte.
    NulByte(&'static str),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema(v) => write!(f, "unsupported schema version {v}"),
            Self::EmptyField(n) => write!(f, "empty required field `{n}`"),
            Self::StringTooLong(n) => write!(f, "field `{n}` exceeds {MAX_STRING_LEN} bytes"),
            Self::TooManyItems(n) => write!(f, "`{n}` exceeds {MAX_ITEMS} entries"),
            Self::DeltaTooLarge => write!(f, "delta cost exceeds {MAX_DELTA_COST}"),
            Self::HandshakeSeqNotZero => f.write_str("unassigned epoch requires `seq = 0`"),
            Self::DuplicateKey => f.write_str("duplicate software key"),
            Self::KeyBothRemovedAndUpserted => {
                f.write_str("key appears in both `removed` and `upserted`")
            }
            Self::UnassignedEpochOnIncremental => {
                f.write_str("unassigned epoch is only valid on a full snapshot")
            }
            Self::MissingHostOs => f.write_str("full snapshot requires `host_os`"),
            Self::FullSnapshotWithRemovals => f.write_str("full snapshot must not carry `removed`"),
            Self::NulByte(n) => write!(f, "field `{n}` contains a NUL byte"),
        }
    }
}

impl std::error::Error for ValidationError {}

fn check_str(name: &'static str, s: &str, required: bool) -> Result<(), ValidationError> {
    if required && s.is_empty() {
        return Err(ValidationError::EmptyField(name));
    }
    if s.len() > MAX_STRING_LEN {
        return Err(ValidationError::StringTooLong(name));
    }
    if s.as_bytes().contains(&0) {
        return Err(ValidationError::NulByte(name));
    }
    Ok(())
}

fn check_opt(name: &'static str, s: Option<&String>) -> Result<(), ValidationError> {
    s.map_or(Ok(()), |s| check_str(name, s, false))
}

fn check_source(source: &PackageSource) -> Result<(), ValidationError> {
    if let PackageSource::Other(s) = source {
        check_str("source", s, true)?;
    }
    Ok(())
}

fn check_item(item: &SoftwareItem) -> Result<(), ValidationError> {
    check_source(&item.source)?;
    check_str("name", &item.name, true)?;
    check_str("version", &item.version, true)?;
    check_opt("arch", item.arch.as_ref())?;
    check_opt("vendor", item.vendor.as_ref())?;
    check_opt("purl", item.purl.as_ref())?;
    if let Some(sp) = &item.source_package {
        check_str("source_package.name", &sp.name, true)?;
        check_opt("source_package.version", sp.version.as_ref())?;
    }
    Ok(())
}

fn opt_len(s: Option<&String>) -> usize {
    s.map_or(0, String::len)
}

fn source_len(source: &PackageSource) -> usize {
    match source {
        PackageSource::Other(s) => s.len(),
        _ => 0,
    }
}

/// Cost of an item: overhead plus the lengths of all its strings.
fn item_cost(item: &SoftwareItem) -> usize {
    let sp = item
        .source_package
        .as_ref()
        .map_or(0, |sp| sp.name.len() + opt_len(sp.version.as_ref()));
    PER_ITEM_OVERHEAD
        + item.name.len()
        + item.version.len()
        + opt_len(item.arch.as_ref())
        + opt_len(item.vendor.as_ref())
        + opt_len(item.purl.as_ref())
        + source_len(&item.source)
        + sp
}

fn key_cost(key: &SoftwareKey) -> usize {
    PER_ITEM_OVERHEAD
        + key.name.len()
        + key.version.len()
        + opt_len(key.arch.as_ref())
        + source_len(&key.source)
}

fn check_key(key: &SoftwareKey) -> Result<(), ValidationError> {
    check_source(&key.source)?;
    check_str("name", &key.name, true)?;
    check_str("version", &key.version, true)?;
    check_opt("arch", key.arch.as_ref())
}

impl SoftwareDelta {
    /// Checks structural invariants of a decoded delta.
    ///
    /// # Errors
    ///
    /// Returns the first violated invariant: unsupported schema, empty or
    /// oversized fields, too many entries or total cost, duplicate keys, a key
    /// both removed and upserted, an unassigned epoch on an incremental delta
    /// or with `seq != 0`, a full snapshot without `host_os` or with
    /// removals, or a NUL byte in any string field.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchema(self.schema_version));
        }
        check_str("host_id", &self.host_id.0, true)?;
        if self.epoch.is_unassigned() && !self.full {
            return Err(ValidationError::UnassignedEpochOnIncremental);
        }
        if self.epoch.is_unassigned() && self.seq != 0 {
            return Err(ValidationError::HandshakeSeqNotZero);
        }
        if self.full {
            if self.host_os.is_none() {
                return Err(ValidationError::MissingHostOs);
            }
            if !self.removed.is_empty() {
                return Err(ValidationError::FullSnapshotWithRemovals);
            }
        }
        if let Some(os) = &self.host_os {
            check_str("host_os.id", &os.id, true)?;
            check_opt("host_os.version_id", os.version_id.as_ref())?;
            check_str("host_os.arch", &os.arch, true)?;
        }
        if self.upserted.len() > MAX_ITEMS {
            return Err(ValidationError::TooManyItems("upserted"));
        }
        if self.removed.len() > MAX_ITEMS {
            return Err(ValidationError::TooManyItems("removed"));
        }

        let mut cost = 0usize;
        let mut upserted = HashSet::with_capacity(self.upserted.len());
        for item in &self.upserted {
            check_item(item)?;
            cost = cost.saturating_add(item_cost(item));
            if !upserted.insert(item.key()) {
                return Err(ValidationError::DuplicateKey);
            }
        }
        let mut removed = HashSet::with_capacity(self.removed.len());
        for key in &self.removed {
            check_key(key)?;
            cost = cost.saturating_add(key_cost(key));
            if !removed.insert(key) {
                return Err(ValidationError::DuplicateKey);
            }
            if upserted.contains(key) {
                return Err(ValidationError::KeyBothRemovedAndUpserted);
            }
        }
        if cost > MAX_DELTA_COST {
            return Err(ValidationError::DeltaTooLarge);
        }
        Ok(())
    }
}

/// Appends a `u32` big-endian length followed by the bytes.
fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ValidationError> {
    let len = u32::try_from(bytes.len()).map_err(|_| ValidationError::StringTooLong("digest"))?;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
    Ok(())
}

/// Appends a presence byte, then the field if present.
fn put_opt(buf: &mut Vec<u8>, s: Option<&str>) -> Result<(), ValidationError> {
    if let Some(s) = s {
        buf.push(1);
        put_bytes(buf, s.as_bytes())
    } else {
        buf.push(0);
        Ok(())
    }
}

/// Canonical digest of an inventory, independent of the wire encoding.
///
/// SHA-256 over the item set, covering the identity key
/// `(source, name, arch, version)` plus `source_package`. `purl` (server
/// computed) and `vendor` (informational) are excluded.
///
/// Preimage: the ASCII prefix `traysis.software.v1\0`, the item count as
/// `u64` big-endian, then each item in ascending bytewise order of its encoded
/// key. Every string is a `u32` big-endian length followed by UTF-8 bytes; an
/// optional field is a `u8` presence byte (0 or 1) followed by the string only
/// if present. An item is its encoded key
/// `source_tag, name, arch?, version` followed by `source_package?` as
/// `name, version?`. The source tag is `dpkg`, `rpm`, `apk`, `pacman`, `brew`,
/// or `other:<s>`.
///
/// Input order does not matter.
///
/// # Errors
///
/// Returns [`ValidationError::DuplicateKey`] if two items share a key (the
/// ordering would not be total) and [`ValidationError::StringTooLong`] if a
/// string does not fit a `u32` length prefix.
pub fn state_digest(items: &[SoftwareItem]) -> Result<[u8; 32], ValidationError> {
    let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(items.len());
    for item in items {
        let mut key = Vec::new();
        put_bytes(&mut key, item.source.tag().as_bytes())?;
        put_bytes(&mut key, item.name.as_bytes())?;
        put_opt(&mut key, item.arch.as_deref())?;
        put_bytes(&mut key, item.version.as_bytes())?;

        let mut rest = Vec::new();
        match &item.source_package {
            Some(sp) => {
                rest.push(1);
                put_bytes(&mut rest, sp.name.as_bytes())?;
                put_opt(&mut rest, sp.version.as_deref())?;
            }
            None => rest.push(0),
        }
        encoded.push((key, rest));
    }
    encoded.sort_by(|a, b| a.0.cmp(&b.0));
    if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(ValidationError::DuplicateKey);
    }

    let mut hasher = Sha256::new();
    hasher.update(DIGEST_PREFIX);
    hasher.update((encoded.len() as u64).to_be_bytes());
    for (key, rest) in &encoded {
        hasher.update(key);
        hasher.update(rest);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Edit = fn(&mut SoftwareItem, String);
    type KeyEdit = fn(&mut SoftwareKey, String);

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

    fn full_delta(items: Vec<SoftwareItem>) -> SoftwareDelta {
        SoftwareDelta {
            schema_version: SCHEMA_VERSION,
            host_id: HostId("host-1".to_owned()),
            epoch: Epoch::UNASSIGNED,
            seq: 0,
            full: true,
            host_os: Some(os()),
            collected_at: UnixMillis(1),
            upserted: items,
            removed: Vec::new(),
            state_digest: [0; 32],
        }
    }

    fn incremental() -> SoftwareDelta {
        SoftwareDelta {
            epoch: Epoch(3),
            seq: 7,
            full: false,
            host_os: None,
            ..full_delta(Vec::new())
        }
    }

    #[test]
    fn valid_deltas_pass() {
        assert_eq!(full_delta(vec![item("a", "1")]).validate(), Ok(()));
        assert_eq!(incremental().validate(), Ok(()));
    }

    #[test]
    fn rejects_bad_schema_version() {
        let mut d = incremental();
        d.schema_version = 99;
        assert_eq!(d.validate(), Err(ValidationError::UnsupportedSchema(99)));
    }

    #[test]
    fn rejects_unassigned_epoch_on_incremental() {
        let mut d = incremental();
        d.epoch = Epoch::UNASSIGNED;
        assert_eq!(
            d.validate(),
            Err(ValidationError::UnassignedEpochOnIncremental)
        );
    }

    #[test]
    fn full_snapshot_requires_host_os() {
        let mut d = full_delta(vec![]);
        d.host_os = None;
        assert_eq!(d.validate(), Err(ValidationError::MissingHostOs));
    }

    #[test]
    fn full_snapshot_rejects_removals() {
        let mut d = full_delta(vec![]);
        d.removed.push(item("a", "1").key());
        assert_eq!(d.validate(), Err(ValidationError::FullSnapshotWithRemovals));
    }

    #[test]
    fn rejects_empty_and_oversized_fields() {
        let mut d = incremental();
        d.upserted.push(item("", "1"));
        assert_eq!(d.validate(), Err(ValidationError::EmptyField("name")));

        let mut d = incremental();
        d.upserted.push(item("a", &"v".repeat(MAX_STRING_LEN + 1)));
        assert_eq!(d.validate(), Err(ValidationError::StringTooLong("version")));

        let mut d = incremental();
        d.host_id = HostId(String::new());
        assert_eq!(d.validate(), Err(ValidationError::EmptyField("host_id")));
    }

    #[test]
    fn handshake_requires_seq_zero() {
        let mut d = full_delta(vec![]);
        d.seq = 1;
        assert_eq!(d.validate(), Err(ValidationError::HandshakeSeqNotZero));
    }

    #[test]
    fn rejects_delta_over_cost_cap() {
        // Each item is individually valid; together they exceed the cost cap.
        let big = "x".repeat(MAX_STRING_LEN);
        let items = (0..=MAX_DELTA_COST / MAX_STRING_LEN)
            .map(|i| item(&format!("{i}{big}")[..MAX_STRING_LEN], "1"))
            .collect();
        assert_eq!(
            full_delta(items).validate(),
            Err(ValidationError::DeltaTooLarge)
        );
    }

    #[test]
    fn rejects_too_many_items() {
        let mut d = incremental();
        d.removed = vec![item("a", "1").key(); MAX_ITEMS + 1];
        assert_eq!(d.validate(), Err(ValidationError::TooManyItems("removed")));
    }

    #[test]
    fn accepts_snapshot_at_the_cap() {
        let items = (0..MAX_ITEMS)
            .map(|i| item(&format!("p{i}"), "1"))
            .collect();
        assert_eq!(full_delta(items).validate(), Ok(()));
    }

    #[test]
    fn rejects_duplicate_keys() {
        let mut d = incremental();
        d.upserted = vec![item("a", "1"), item("a", "1")];
        assert_eq!(d.validate(), Err(ValidationError::DuplicateKey));

        let mut d = incremental();
        d.removed = vec![item("a", "1").key(), item("a", "1").key()];
        assert_eq!(d.validate(), Err(ValidationError::DuplicateKey));
    }

    #[test]
    fn rejects_key_both_removed_and_upserted() {
        let mut d = incremental();
        d.upserted = vec![item("a", "1")];
        d.removed = vec![item("a", "1").key()];
        assert_eq!(
            d.validate(),
            Err(ValidationError::KeyBothRemovedAndUpserted)
        );
    }

    #[test]
    fn rejects_nul_in_every_string_field() {
        let nul = |s: &str| format!("{s}\0x");
        let check = |d: SoftwareDelta, field: &'static str| {
            assert_eq!(
                d.validate(),
                Err(ValidationError::NulByte(field)),
                "{field}"
            );
        };

        let mut d = incremental();
        d.host_id = HostId(nul("h"));
        check(d, "host_id");

        // Full-snapshot cases: host_os fields.
        for (field, edit) in [
            ("host_os.id", 0),
            ("host_os.version_id", 1),
            ("host_os.arch", 2),
        ] {
            let mut d = full_delta(vec![]);
            if let Some(os) = d.host_os.as_mut() {
                match edit {
                    0 => os.id = nul("debian"),
                    1 => os.version_id = Some(nul("12")),
                    _ => os.arch = nul("x86_64"),
                }
            }
            check(d, field);
        }

        // Item fields (upserted).
        let item_cases: [(&'static str, Edit); 8] = [
            ("name", |i, v| i.name = v),
            ("version", |i, v| i.version = v),
            ("arch", |i, v| i.arch = Some(v)),
            ("vendor", |i, v| i.vendor = Some(v)),
            ("purl", |i, v| i.purl = Some(v)),
            ("source", |i, v| i.source = PackageSource::Other(v)),
            ("source_package.name", |i, v| {
                i.source_package = Some(SourcePackage {
                    name: v,
                    version: None,
                });
            }),
            ("source_package.version", |i, v| {
                i.source_package = Some(SourcePackage {
                    name: "s".to_owned(),
                    version: Some(v),
                });
            }),
        ];
        for (field, edit) in item_cases {
            let mut it = item("a", "1");
            edit(&mut it, nul("v"));
            let mut d = incremental();
            d.upserted = vec![it];
            check(d, field);
        }

        // Key fields (removed).
        let key_cases: [(&'static str, KeyEdit); 4] = [
            ("name", |k, v| k.name = v),
            ("version", |k, v| k.version = v),
            ("arch", |k, v| k.arch = Some(v)),
            ("source", |k, v| k.source = PackageSource::Other(v)),
        ];
        for (field, edit) in key_cases {
            let mut k = item("a", "1").key();
            edit(&mut k, nul("v"));
            let mut d = incremental();
            d.removed = vec![k];
            check(d, field);
        }
    }

    #[test]
    fn nul_error_does_not_echo_contents() {
        let mut d = incremental();
        d.upserted = vec![item("openssl\0evil", "1")];
        let msg = d.validate().map_err(|e| e.to_string());
        assert_eq!(msg, Err("field `name` contains a NUL byte".to_owned()));
    }

    #[test]
    fn digest_of_nul_free_inventory_unchanged_by_nul_rule() {
        // The existing hex vectors above still pass; this pins that a NUL-free
        // item set validates and digests as before.
        let d = full_delta(vec![item("ab", "1")]);
        assert_eq!(d.validate(), Ok(()));
        assert_eq!(
            hex(state_digest(&d.upserted).unwrap()),
            "aaafebc3fa54ac7f1d95c5cbdf26bde734ba323ffb8f7f35a1dc6529a1435dfc"
        );
    }

    #[test]
    fn two_kernel_versions_coexist() {
        let mut d = incremental();
        d.upserted = vec![item("kernel", "6.1.1"), item("kernel", "6.1.2")];
        assert_eq!(d.validate(), Ok(()));
    }

    #[test]
    fn upgrade_is_remove_plus_upsert() {
        let mut d = incremental();
        d.removed = vec![item("openssl", "3.0.1").key()];
        d.upserted = vec![item("openssl", "3.0.2")];
        assert_eq!(d.validate(), Ok(()));
    }

    #[test]
    fn same_name_different_arch_is_distinct() {
        let mut other = item("libc6", "2.36");
        other.arch = Some("i386".to_owned());
        let mut d = incremental();
        d.upserted = vec![item("libc6", "2.36"), other];
        assert_eq!(d.validate(), Ok(()));
    }

    #[test]
    fn digest_matches_hand_built_preimage() {
        let mut it = item("ab", "1");
        it.source_package = Some(SourcePackage {
            name: "src".to_owned(),
            version: None,
        });

        let mut pre = Vec::new();
        pre.extend_from_slice(b"traysis.software.v1\0");
        pre.extend_from_slice(&1u64.to_be_bytes());
        for s in ["dpkg", "ab"] {
            pre.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
            pre.extend_from_slice(s.as_bytes());
        }
        pre.push(1);
        pre.extend_from_slice(&5u32.to_be_bytes());
        pre.extend_from_slice(b"amd64");
        pre.extend_from_slice(&1u32.to_be_bytes());
        pre.extend_from_slice(b"1");
        pre.push(1);
        pre.extend_from_slice(&3u32.to_be_bytes());
        pre.extend_from_slice(b"src");
        pre.push(0);

        let expected: [u8; 32] = Sha256::digest(&pre).into();
        assert_eq!(state_digest(&[it]), Ok(expected));
    }

    fn hex(d: [u8; 32]) -> String {
        use std::fmt::Write as _;
        d.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    // The vectors below are literal hex, produced by an independent
    // implementation (Python), so a non-Rust agent or server can be checked
    // against the same bytes. They pin the layout and the sort order.

    #[test]
    fn vector_empty() {
        assert_eq!(
            hex(state_digest(&[]).unwrap()),
            "164a42d40ee8bb1ab506d8ee091d03f7003513de40d9ae0f49b7aedb613f5a47"
        );
    }

    #[test]
    fn vector_single_item() {
        assert_eq!(
            hex(state_digest(&[item("ab", "1")]).unwrap()),
            "aaafebc3fa54ac7f1d95c5cbdf26bde734ba323ffb8f7f35a1dc6529a1435dfc"
        );
    }

    #[test]
    fn vector_length_prefix_sorts_shorter_names_first() {
        // Bytewise order over length-prefixed fields puts "b" (len 1) before
        // "aa" (len 2) regardless of content.
        let expected = "63b69568ec14714ad8809e7048181735c86882971f60814fe6ea514789a76986";
        assert_eq!(
            hex(state_digest(&[item("aa", "1"), item("b", "1")]).unwrap()),
            expected
        );
        assert_eq!(
            hex(state_digest(&[item("b", "1"), item("aa", "1")]).unwrap()),
            expected
        );
    }

    #[test]
    fn vector_options_source_package_and_other_source() {
        let kernel = |version: &str, sp: Option<SourcePackage>| SoftwareItem {
            name: "kernel".to_owned(),
            version: version.to_owned(),
            arch: None,
            source: PackageSource::Rpm,
            source_package: sp,
            vendor: Some("ignored".to_owned()),
            purl: Some("pkg:ignored".to_owned()),
        };
        let firefox = SoftwareItem {
            name: "firefox".to_owned(),
            version: "130.0".to_owned(),
            arch: Some("arm64".to_owned()),
            source: PackageSource::Other("snap".to_owned()),
            source_package: Some(SourcePackage {
                name: "firefox".to_owned(),
                version: None,
            }),
            vendor: None,
            purl: None,
        };
        let items = [
            kernel(
                "6.1.1",
                Some(SourcePackage {
                    name: "kernel-src".to_owned(),
                    version: Some("6.1.1-1".to_owned()),
                }),
            ),
            firefox,
            kernel("6.1.2", None),
        ];
        assert_eq!(
            hex(state_digest(&items).unwrap()),
            "ceb505d361be5253ca9b82ba6c30753396e1c72505a407291c611a6b7d03b26b"
        );
    }

    #[test]
    fn digest_is_order_independent() {
        let a = [item("a", "1"), item("b", "2"), item("c", "3")];
        let b = [item("c", "3"), item("a", "1"), item("b", "2")];
        assert_eq!(state_digest(&a), state_digest(&b));
    }

    #[test]
    fn digest_field_boundaries_matter() {
        assert_ne!(
            state_digest(&[item("ab", "c")]),
            state_digest(&[item("a", "bc")])
        );
    }

    #[test]
    fn digest_ignores_purl_and_vendor_but_not_source_package() {
        let base = item("a", "1");
        let mut with_extras = base.clone();
        with_extras.purl = Some("pkg:deb/debian/a@1".to_owned());
        with_extras.vendor = Some("Acme".to_owned());
        assert_eq!(
            state_digest(std::slice::from_ref(&base)),
            state_digest(&[with_extras])
        );

        let mut with_src = base.clone();
        with_src.source_package = Some(SourcePackage {
            name: "a-src".to_owned(),
            version: None,
        });
        assert_ne!(state_digest(&[base]), state_digest(&[with_src]));
    }

    #[test]
    fn digest_distinguishes_missing_from_empty_option() {
        let mut none = item("a", "1");
        none.arch = None;
        let mut empty = item("a", "1");
        empty.arch = Some(String::new());
        assert_ne!(state_digest(&[none]), state_digest(&[empty]));
    }

    #[test]
    fn digest_rejects_duplicate_keys() {
        assert_eq!(
            state_digest(&[item("a", "1"), item("a", "1")]),
            Err(ValidationError::DuplicateKey)
        );
    }

    #[test]
    fn digest_of_empty_inventory_is_stable() {
        assert_eq!(state_digest(&[]), state_digest(&[]));
        assert_ne!(state_digest(&[]), state_digest(&[item("a", "1")]));
    }
}
