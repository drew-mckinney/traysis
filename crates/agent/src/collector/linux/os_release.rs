//! os-release collector: reads `/etc/os-release`, falling back to
//! `/usr/lib/os-release`. Provides only [`Collector::host_os`].
//!
//! `HostOs.arch` is `std::env::consts::ARCH`: Rust naming (`x86_64`,
//! `aarch64`) and the agent binary's **compile-time** architecture, not a
//! probe of the running kernel or of installed packages. dpkg item `arch`
//! uses dpkg names (`amd64`, `arm64`). The server must not compare the two
//! directly; any mapping is a server concern.
//!
//! Only `ID` and `VERSION_ID` are read. `ID_LIKE` is not collected yet.

use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

use traysis_proto::inventory::{HostOs, MAX_STRING_LEN};

use super::read_bounded;
use crate::collector::{CollectError, Collector};

/// Largest accepted os-release file.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Collects the host OS identity from os-release.
#[derive(Debug, Clone)]
pub struct OsReleaseCollector {
    paths: Vec<PathBuf>,
}

impl Default for OsReleaseCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl OsReleaseCollector {
    /// A collector trying `/etc/os-release`, then `/usr/lib/os-release`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            paths: vec![
                PathBuf::from("/etc/os-release"),
                PathBuf::from("/usr/lib/os-release"),
            ],
        }
    }
}

impl Collector for OsReleaseCollector {
    fn id(&self) -> &'static str {
        "os-release"
    }

    fn host_os(&self) -> Result<HostOs, CollectError> {
        host_os_from_paths(&self.paths)
    }
}

/// Uses the first path that opens; falls through only on `NotFound`.
fn host_os_from_paths(paths: &[PathBuf]) -> Result<HostOs, CollectError> {
    for path in paths {
        match File::open(path) {
            Ok(f) => return host_os_from_reader(f),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(io::Error::from(io::ErrorKind::NotFound).into())
}

/// Reads and parses an os-release file from `r`.
///
/// # Errors
///
/// IO errors, [`CollectError::TooLarge`] over [`MAX_FILE_BYTES`], or
/// [`CollectError::Parse`].
pub fn host_os_from_reader<R: Read>(r: R) -> Result<HostOs, CollectError> {
    let bytes = read_bounded(r, MAX_FILE_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| parse_err("not valid UTF-8"))?;
    parse(text)
}

fn parse_err(detail: &str) -> CollectError {
    CollectError::Parse {
        what: "os-release",
        detail: detail.to_owned(),
    }
}

/// Parses os-release text. Unknown keys and malformed lines are ignored; the
/// last assignment of a key wins.
///
/// # Errors
///
/// [`CollectError::Parse`] if `ID` is missing or either `ID` or `VERSION_ID`
/// is invalid.
pub fn parse(text: &str) -> Result<HostOs, CollectError> {
    let (mut id, mut version_id) = (None, None);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(value) = unquote(value.trim()) else {
            continue;
        };
        match key.trim() {
            "ID" => id = Some(value),
            "VERSION_ID" => version_id = Some(value),
            _ => {}
        }
    }

    let id = id
        .ok_or_else(|| parse_err("missing ID"))?
        .to_ascii_lowercase();
    if id.is_empty()
        || id.len() > MAX_STRING_LEN
        || !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err(parse_err("invalid ID"));
    }
    let version_id = match version_id {
        None => None,
        Some(v) if v.is_empty() => None,
        Some(v) => {
            if v.len() > MAX_STRING_LEN
                || !v
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '~'))
            {
                return Err(parse_err("invalid VERSION_ID"));
            }
            Some(v)
        }
    };
    Ok(HostOs {
        id,
        version_id,
        arch: std::env::consts::ARCH.to_owned(),
    })
}

/// Strips one level of matching quotes. `None` for an unterminated quote.
/// Shell escapes are not interpreted.
fn unquote(v: &str) -> Option<String> {
    for q in ['"', '\''] {
        if let Some(rest) = v.strip_prefix(q) {
            return rest.strip_suffix(q).map(str::to_owned);
        }
    }
    Some(v.to_owned())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn is_parse_err(r: &Result<HostOs, CollectError>) -> bool {
        matches!(r, Err(CollectError::Parse { .. }))
    }

    #[test]
    fn quoted_and_unquoted_values() {
        let os = parse("# comment\n\nNAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\n")
            .expect("valid");
        assert_eq!(os.id, "debian");
        assert_eq!(os.version_id.as_deref(), Some("12"));
        assert_eq!(os.arch, std::env::consts::ARCH);
        let os = parse("ID='ubuntu'\nVERSION_ID=24.04\n").expect("valid");
        assert_eq!(
            (os.id.as_str(), os.version_id.as_deref()),
            ("ubuntu", Some("24.04"))
        );
    }

    #[test]
    fn rolling_distro_has_no_version_id() {
        let os = parse("ID=arch\n").expect("valid");
        assert_eq!(os.version_id, None);
        assert_eq!(
            parse("ID=arch\nVERSION_ID=\n").expect("valid").version_id,
            None
        );
    }

    #[test]
    fn last_assignment_wins_and_id_is_lowercased() {
        let os = parse("ID=a\nID=Debian\n").expect("valid");
        assert_eq!(os.id, "debian");
    }

    #[test]
    fn missing_id_is_parse_error() {
        assert!(is_parse_err(&parse("NAME=x\nVERSION_ID=1\n")));
        assert!(is_parse_err(&parse("")));
    }

    #[test]
    fn garbage_lines_are_ignored() {
        let os = parse("%%%\n=\nnot a pair\n\"ID=x\nID=debian\n\u{0}\n").expect("valid");
        assert_eq!(os.id, "debian");
    }

    #[test]
    fn unterminated_quote_line_is_ignored() {
        assert!(is_parse_err(&parse("ID=\"debian\n")));
    }

    #[test]
    fn invalid_characters_are_rejected() {
        assert!(is_parse_err(&parse("ID=deb ian\n")));
        assert!(is_parse_err(&parse("ID=\"de/bian\"\n")));
        assert!(is_parse_err(&parse("ID=\"\"\n")));
        assert!(is_parse_err(&parse("ID=debian\nVERSION_ID=\"1 2\"\n")));
        assert!(is_parse_err(&parse(&format!(
            "ID={}\n",
            "a".repeat(MAX_STRING_LEN + 1)
        ))));
    }

    #[test]
    fn invalid_utf8_is_parse_error() {
        let r = host_os_from_reader(Cursor::new(b"ID=debian\n\xff\n".to_vec()));
        assert!(is_parse_err(&r));
    }

    #[test]
    fn size_cap_boundary() {
        let cap = usize::try_from(MAX_FILE_BYTES).expect("fits usize");
        let mut at_cap = b"ID=debian\n#".to_vec();
        at_cap.resize(cap, b'x');
        assert!(host_os_from_reader(Cursor::new(at_cap.clone())).is_ok());
        at_cap.push(b'x');
        assert!(matches!(
            host_os_from_reader(Cursor::new(at_cap)),
            Err(CollectError::TooLarge)
        ));
    }

    #[test]
    fn missing_files_yield_not_found() {
        let paths = [
            PathBuf::from("/nonexistent/a"),
            PathBuf::from("/nonexistent/b"),
        ];
        match host_os_from_paths(&paths) {
            Err(CollectError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            other => assert!(matches!(other, Err(CollectError::Io(_))), "{other:?}"),
        }
    }

    #[test]
    fn only_host_os_is_supported() {
        let c = OsReleaseCollector::new();
        assert_eq!(c.id(), "os-release");
        assert!(matches!(c.software(), Err(CollectError::Unsupported)));
    }
}
