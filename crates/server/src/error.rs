//! Error types. `Display` never echoes inventory strings.

use std::fmt;
use std::io;
use std::path::PathBuf;

use traysis_proto::inventory::ValidationError;

/// Why opening or using the store failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// SQLite reported an error.
    Sqlite(rusqlite::Error),
    /// A filesystem operation on the database file failed.
    Io(io::Error),
    /// The database path is a symlink, not a regular file, or accessible to
    /// group or other.
    Insecure {
        /// The offending path.
        path: PathBuf,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The database was written by a newer schema version.
    UnsupportedSchema(i64),
    /// The database has tables but `user_version` is 0.
    UnversionedSchema,
    /// A required PRAGMA did not take effect.
    Pragma(&'static str),
    /// Stored data violates an invariant the server maintains.
    Corrupt(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite error: {e}"),
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::Insecure { path, reason } => {
                write!(f, "insecure database path {}: {reason}", path.display())
            }
            Self::UnsupportedSchema(v) => write!(f, "unsupported database schema version {v}"),
            Self::UnversionedSchema => f.write_str("database has tables but no schema version"),
            Self::Pragma(name) => write!(f, "PRAGMA {name} did not take effect"),
            Self::Corrupt(what) => write!(f, "corrupt store: {what}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Why a delta could not be applied. None of these is an ack: each is either
/// a protocol violation by the peer or a server-side failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApplyError {
    /// `delta.host_id` differs from the authenticated transport identity.
    HostMismatch,
    /// The delta failed [`traysis_proto::inventory::SoftwareDelta::validate`].
    Invalid(ValidationError),
    /// A full snapshot carried a nonzero epoch; only the handshake form
    /// (epoch 0) is defined.
    SnapshotWithEpoch,
    /// The host's epoch counter cannot be incremented.
    EpochExhausted,
    /// The host's sequence number cannot be incremented.
    SeqExhausted,
    /// The receive time does not fit the store's integer range.
    TimeOutOfRange,
    /// The store failed.
    Store(StoreError),
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostMismatch => f.write_str("delta host_id does not match authenticated host"),
            Self::Invalid(e) => write!(f, "invalid delta: {e}"),
            Self::SnapshotWithEpoch => f.write_str("full snapshot with a nonzero epoch"),
            Self::EpochExhausted => f.write_str("epoch counter exhausted"),
            Self::SeqExhausted => f.write_str("sequence counter exhausted"),
            Self::TimeOutOfRange => f.write_str("receive time out of range"),
            Self::Store(e) => write!(f, "store error: {e}"),
        }
    }
}

impl std::error::Error for ApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(e) => Some(e),
            Self::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreError> for ApplyError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<rusqlite::Error> for ApplyError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Store(StoreError::Sqlite(e))
    }
}
