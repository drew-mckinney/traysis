//! The `Collector` trait: the only place platform-specific collection lives.
//!
//! Implementations go in `collector/linux/` and `collector/macos/` behind
//! `cfg(target_os)`. Protocol and server code stay platform-agnostic.
//!
//! Collectors are synchronous and blocking; the agent calls them via
//! `spawn_blocking`. They return full snapshots, never deltas: the Differ
//! (a later change) turns snapshots into [`SoftwareDelta`]s. Each real
//! collector should split IO from a pure `parse` function so that parsing of
//! untrusted text can be tested with malformed input.
//!
//! [`SoftwareDelta`]: traysis_proto::inventory::SoftwareDelta

use std::fmt;
use std::io;

use traysis_proto::inventory::{HostOs, SoftwareItem};

/// Why a collection attempt failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum CollectError {
    /// This collector does not provide the requested inventory domain.
    Unsupported,
    Io(io::Error),
    /// Source data was malformed. `detail` must not contain secrets or
    /// command lines.
    Parse {
        what: &'static str,
        detail: String,
    },
    /// The snapshot exceeds the protocol caps. Fail loudly instead of
    /// truncating, since truncation would corrupt the state digest.
    TooLarge,
}

impl fmt::Display for CollectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("collector does not support this domain"),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Parse { what, detail } => write!(f, "malformed {what}: {detail}"),
            Self::TooLarge => f.write_str("snapshot exceeds protocol limits"),
        }
    }
}

impl std::error::Error for CollectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CollectError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// A source of inventory data for one platform facility.
///
/// Each inventory domain is a method defaulting to
/// [`CollectError::Unsupported`], so adding a domain never breaks existing
/// implementors.
pub trait Collector: Send + Sync {
    /// Stable short identifier, for example `"dpkg"`.
    fn id(&self) -> &'static str;

    /// A full snapshot of installed software.
    ///
    /// # Errors
    ///
    /// [`CollectError::Unsupported`] by default; otherwise IO, parse, or size errors.
    fn software(&self) -> Result<Vec<SoftwareItem>, CollectError> {
        Err(CollectError::Unsupported)
    }

    /// The host OS release.
    ///
    /// # Errors
    ///
    /// [`CollectError::Unsupported`] by default; otherwise IO or parse errors.
    fn host_os(&self) -> Result<HostOs, CollectError> {
        Err(CollectError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use traysis_proto::inventory::PackageSource;

    /// Configurable stand-in for platform collectors.
    #[derive(Default)]
    struct FakeCollector {
        software: Option<Vec<SoftwareItem>>,
        host_os: Option<HostOs>,
        fail_too_large: bool,
    }

    impl Collector for FakeCollector {
        fn id(&self) -> &'static str {
            "fake"
        }

        fn software(&self) -> Result<Vec<SoftwareItem>, CollectError> {
            if self.fail_too_large {
                return Err(CollectError::TooLarge);
            }
            self.software.clone().ok_or(CollectError::Unsupported)
        }

        fn host_os(&self) -> Result<HostOs, CollectError> {
            self.host_os.clone().ok_or(CollectError::Unsupported)
        }
    }

    /// Implements only `id`; relies on the defaults.
    struct Bare;

    impl Collector for Bare {
        fn id(&self) -> &'static str {
            "bare"
        }
    }

    fn item() -> SoftwareItem {
        SoftwareItem {
            name: "a".to_owned(),
            version: "1".to_owned(),
            arch: None,
            source: PackageSource::Dpkg,
            source_package: None,
            vendor: None,
            purl: None,
        }
    }

    #[test]
    fn defaults_are_unsupported() {
        let c: Box<dyn Collector> = Box::new(Bare);
        assert!(matches!(c.software(), Err(CollectError::Unsupported)));
        assert!(matches!(c.host_os(), Err(CollectError::Unsupported)));
    }

    #[test]
    fn dyn_collector_returns_configured_data() {
        let os = HostOs {
            id: "debian".to_owned(),
            version_id: Some("12".to_owned()),
            arch: "x86_64".to_owned(),
        };
        let c: Box<dyn Collector> = Box::new(FakeCollector {
            software: Some(vec![item()]),
            host_os: Some(os.clone()),
            fail_too_large: false,
        });
        assert_eq!(c.id(), "fake");
        assert_eq!(c.software().ok(), Some(vec![item()]));
        assert_eq!(c.host_os().ok(), Some(os));
    }

    #[test]
    fn too_large_is_reported_not_truncated() {
        let c = FakeCollector {
            fail_too_large: true,
            ..FakeCollector::default()
        };
        assert!(matches!(c.software(), Err(CollectError::TooLarge)));
    }

    #[test]
    fn io_errors_convert_and_chain() {
        let e: CollectError = io::Error::from(io::ErrorKind::NotFound).into();
        assert!(matches!(e, CollectError::Io(_)));
        assert!(std::error::Error::source(&e).is_some());
        assert_eq!(e.to_string(), "io error: entity not found");
    }
}
