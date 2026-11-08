//! The SQLite-backed inventory store: opening, pragmas, schema, file modes.
//!
//! The database file is created `0600`. An existing path that is a symlink,
//! not a regular file, or accessible to group or other is refused
//! ([`StoreError::Insecure`]) rather than trusted or silently fixed. The parent
//! directory is the deployer's responsibility.

use std::fs::{self, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, TransactionBehavior};

use crate::error::StoreError;

/// Current `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 1;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The version 1 schema. See `docs/server.md`.
const SCHEMA: &str = "
CREATE TABLE host_epochs (
  host_id TEXT PRIMARY KEY,
  last_issued INTEGER NOT NULL CHECK (last_issued > 0)
) WITHOUT ROWID;

CREATE TABLE hosts (
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
  source TEXT NOT NULL,
  name TEXT NOT NULL,
  arch_present INTEGER NOT NULL CHECK (arch_present IN (0, 1)),
  arch TEXT NOT NULL,
  version TEXT NOT NULL,
  sp_present INTEGER NOT NULL CHECK (sp_present IN (0, 1)),
  sp_name TEXT NOT NULL,
  sp_version_present INTEGER NOT NULL CHECK (sp_version_present IN (0, 1)),
  sp_version TEXT NOT NULL,
  vendor TEXT,
  purl TEXT,
  PRIMARY KEY (host_id, source, name, arch_present, arch, version),
  CHECK (arch_present = 1 OR arch = ''),
  CHECK (sp_present = 1 OR (sp_name = '' AND sp_version_present = 0 AND sp_version = '')),
  CHECK (sp_version_present = 1 OR sp_version = '')
) WITHOUT ROWID;
";

/// A handle to the inventory database. One writer at a time; SQLite's lock
/// serialises concurrent processes.
#[derive(Debug)]
pub struct Store {
    pub(crate) conn: Connection,
}

impl Store {
    /// Opens (creating if needed) the database file at `path`.
    ///
    /// # Errors
    ///
    /// Fails if the path is insecure, SQLite cannot open it, WAL mode or
    /// foreign keys cannot be enabled, or the schema version is unsupported.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        prepare_file(path)?;
        // No SQLITE_OPEN_URI: the path is never interpreted as a URI.
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)?;
        Self::init(conn, true)
    }

    /// Opens a private in-memory database (for tests).
    ///
    /// # Errors
    ///
    /// Fails if SQLite cannot initialise the connection or schema.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn, false)
    }

    fn init(mut conn: Connection, file: bool) -> Result<Self, StoreError> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.pragma_update(None, "trusted_schema", false)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        let fk: i64 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
        check_foreign_keys(fk)?;
        if file {
            let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
            check_journal_mode(&mode)?;
        }
        ensure_schema(&mut conn)?;
        Ok(Self { conn })
    }
}

fn check_foreign_keys(value: i64) -> Result<(), StoreError> {
    if value == 1 {
        Ok(())
    } else {
        Err(StoreError::Pragma("foreign_keys"))
    }
}

fn check_journal_mode(mode: &str) -> Result<(), StoreError> {
    if mode.eq_ignore_ascii_case("wal") {
        Ok(())
    } else {
        Err(StoreError::Pragma("journal_mode"))
    }
}

/// Creates the schema on a fresh database, or accepts the current version.
fn ensure_schema(conn: &mut Connection) -> Result<(), StoreError> {
    // Immediate, and the version is read inside it, so two processes opening
    // a fresh file cannot both create the schema.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    match version {
        0 => {
            let tables: i64 = tx.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |r| r.get(0),
            )?;
            if tables != 0 {
                return Err(StoreError::UnversionedSchema);
            }
            tx.execute_batch(SCHEMA)?;
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            tx.commit()?;
            Ok(())
        }
        SCHEMA_VERSION => Ok(()),
        other => Err(StoreError::UnsupportedSchema(other)),
    }
}

/// Creates the file `0600`, or vets an existing one.
fn prepare_file(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => vet(path, &meta),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // `create_new` fails if the path appears meanwhile (including as a
            // symlink), so we never open something we did not create.
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn vet(path: &Path, meta: &Metadata) -> Result<(), StoreError> {
    let insecure = |reason| StoreError::Insecure {
        path: path.to_path_buf(),
        reason,
    };
    if meta.file_type().is_symlink() {
        return Err(insecure("is a symlink"));
    }
    if !meta.is_file() {
        return Err(insecure("is not a regular file"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(insecure("is accessible to group or other"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;
    use crate::testutil::TempDir;

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().mode() & 0o777
    }

    fn user_version(store: &Store) -> i64 {
        store
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn fresh_file_is_0600_wal_fk_on_and_versioned() {
        let tmp = TempDir::new();
        let path = tmp.path().join("inv.db");
        let store = Store::open(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(user_version(&store), SCHEMA_VERSION);
        let jm: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(jm, "wal");
        let fk: i64 = store
            .conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[test]
    fn wal_and_shm_files_are_0600() {
        let tmp = TempDir::new();
        let path = tmp.path().join("inv.db");
        let store = Store::open(&path).unwrap();
        // A write makes sure the -wal file exists while the store is open.
        store
            .conn
            .execute("INSERT INTO host_epochs VALUES ('h', 1)", [])
            .unwrap();
        for suffix in ["-wal", "-shm"] {
            let mut name = path.clone().into_os_string();
            name.push(suffix);
            assert_eq!(mode(Path::new(&name)), 0o600, "{suffix}");
        }
    }

    #[test]
    fn reopen_keeps_schema_and_data() {
        let tmp = TempDir::new();
        let path = tmp.path().join("inv.db");
        {
            let store = Store::open(&path).unwrap();
            store
                .conn
                .execute("INSERT INTO host_epochs VALUES ('h', 7)", [])
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let n: i64 = store
            .conn
            .query_row("SELECT last_issued FROM host_epochs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 7);
    }

    #[test]
    fn refuses_group_or_world_accessible_file() {
        let tmp = TempDir::new();
        let path = tmp.path().join("inv.db");
        drop(Store::open(&path).unwrap());
        for bad in [0o640, 0o604, 0o644, 0o660] {
            fs::set_permissions(&path, fs::Permissions::from_mode(bad)).unwrap();
            assert!(
                matches!(Store::open(&path), Err(StoreError::Insecure { .. })),
                "{bad:o}"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Store::open(&path).is_ok());
    }

    #[test]
    fn refuses_symlinks_and_non_files() {
        let tmp = TempDir::new();
        let real = tmp.path().join("real.db");
        drop(Store::open(&real).unwrap());
        let link = tmp.path().join("link.db");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            Store::open(&link),
            Err(StoreError::Insecure { .. })
        ));

        let dangling = tmp.path().join("dangling.db");
        symlink(tmp.path().join("nowhere"), &dangling).unwrap();
        assert!(matches!(
            Store::open(&dangling),
            Err(StoreError::Insecure { .. })
        ));
        assert!(!tmp.path().join("nowhere").exists());

        assert!(matches!(
            Store::open(tmp.path()),
            Err(StoreError::Insecure { .. })
        ));
    }

    #[test]
    fn path_is_not_interpreted_as_a_uri() {
        let tmp = TempDir::new();
        let path = tmp.path().join("file:odd?mode=memory&cache=shared");
        let store = Store::open(&path).unwrap();
        drop(store);
        assert!(path.exists());
    }

    #[test]
    fn newer_schema_version_is_refused() {
        let tmp = TempDir::new();
        let path = tmp.path().join("inv.db");
        let store = Store::open(&path).unwrap();
        store.conn.pragma_update(None, "user_version", 99).unwrap();
        drop(store);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::UnsupportedSchema(99))
        ));
    }

    #[test]
    fn tables_without_a_version_are_refused() {
        let tmp = TempDir::new();
        let path = tmp.path().join("inv.db");
        let store = Store::open(&path).unwrap();
        store.conn.pragma_update(None, "user_version", 0).unwrap();
        drop(store);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::UnversionedSchema)
        ));
    }

    #[test]
    fn pragma_results_are_checked() {
        assert!(check_journal_mode("wal").is_ok());
        assert!(check_journal_mode("WAL").is_ok());
        for bad in ["delete", "memory", "truncate", ""] {
            assert!(
                matches!(
                    check_journal_mode(bad),
                    Err(StoreError::Pragma("journal_mode"))
                ),
                "{bad}"
            );
        }
        assert!(check_foreign_keys(1).is_ok());
        assert!(matches!(
            check_foreign_keys(0),
            Err(StoreError::Pragma("foreign_keys"))
        ));
    }

    #[test]
    fn in_memory_store_works() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(user_version(&store), SCHEMA_VERSION);
    }
}
