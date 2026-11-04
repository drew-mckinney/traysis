//! dpkg collector: parses `/var/lib/dpkg/status` directly.
//!
//! No subprocess is spawned (no `dpkg-query`), so there is no PATH or
//! output-format dependency and the collector is read-only.
//!
//! The status file is untrusted input. [`parse`] works on bytes, validates
//! each stanza independently, and never lets one bad stanza affect another.
//! Stanzas that are dropped are counted in [`ParseStats`]:
//!
//! - `malformed`: failed parsing, a size cap, UTF-8 validation, or duplicated
//!   an earlier stanza's identity. These indicate a problem worth surfacing.
//! - `excluded`: valid stanzas whose `Status` state means the package is not
//!   installed (`not-installed`, `config-files`, `half-installed`). These are
//!   expected on healthy hosts.
//!
//! Item `arch` uses dpkg architecture names (`amd64`, `arm64`, `all`),
//! verbatim. These differ from the Rust names in `HostOs.arch`; see
//! [`OsReleaseCollector`](super::OsReleaseCollector).

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use traysis_proto::inventory::{
    MAX_ITEMS, MAX_STRING_LEN, PackageSource, SoftwareItem, SoftwareKey, SourcePackage,
};

use super::read_bounded;
use crate::collector::{CollectError, Collector};

/// Default location of the dpkg status database.
const STATUS_PATH: &str = "/var/lib/dpkg/status";
/// Largest status file accepted. Real files are typically 1 to 5 MiB.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Longest accepted line.
const MAX_LINE_BYTES: usize = 64 * 1024;
/// Largest accepted stanza.
const MAX_STANZA_BYTES: usize = 1024 * 1024;
/// Most lines accepted in one stanza.
const MAX_STANZA_LINES: usize = 4096;
/// Most distinct fields accepted in one stanza.
const MAX_FIELDS: usize = 256;

/// Counts of stanzas that did not become items.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseStats {
    /// Stanzas that failed parsing, caps, UTF-8 validation, or duplicated an
    /// earlier stanza's identity. Worth surfacing.
    pub malformed: usize,
    /// Valid stanzas dropped because `Status` says the package is not
    /// installed. Expected on healthy hosts.
    pub excluded: usize,
}

/// Collects installed packages from the dpkg status database.
#[derive(Debug, Clone)]
pub struct DpkgCollector {
    path: PathBuf,
}

impl Default for DpkgCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl DpkgCollector {
    /// A collector reading `/var/lib/dpkg/status`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            path: PathBuf::from(STATUS_PATH),
        }
    }

    /// A collector reading `path`. Intended for the `#[ignore]` real-file
    /// smoke test; other tests go through [`collect_from_reader`].
    #[must_use]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Installed packages plus counts of the stanzas that were dropped.
    ///
    /// Callers that care about data quality, notably the Differ, must use
    /// this rather than [`Collector::software`], which discards the stats.
    ///
    /// # Errors
    ///
    /// IO errors, or [`CollectError::TooLarge`] if the file or item count
    /// exceeds the caps.
    pub fn software_with_stats(&self) -> Result<(Vec<SoftwareItem>, ParseStats), CollectError> {
        collect_from_reader(File::open(&self.path)?)
    }
}

impl Collector for DpkgCollector {
    fn id(&self) -> &'static str {
        "dpkg"
    }

    /// Installed packages. **Discards the [`ParseStats`]**; use
    /// [`DpkgCollector::software_with_stats`] to keep them.
    fn software(&self) -> Result<Vec<SoftwareItem>, CollectError> {
        self.software_with_stats().map(|(items, _)| items)
    }
}

/// Reads a status database from `r` and parses it.
///
/// # Errors
///
/// IO errors, or [`CollectError::TooLarge`] if the input exceeds
/// [`MAX_FILE_BYTES`] or yields more than `MAX_ITEMS` items.
pub fn collect_from_reader<R: Read>(r: R) -> Result<(Vec<SoftwareItem>, ParseStats), CollectError> {
    collect_with_cap(r, MAX_FILE_BYTES)
}

fn collect_with_cap<R: Read>(
    r: R,
    cap: u64,
) -> Result<(Vec<SoftwareItem>, ParseStats), CollectError> {
    parse(&read_bounded(r, cap)?)
}

/// Parses a dpkg status database.
///
/// # Errors
///
/// [`CollectError::TooLarge`] if more than `MAX_ITEMS` items are found.
/// Malformed stanzas are counted, not errors.
pub fn parse(data: &[u8]) -> Result<(Vec<SoftwareItem>, ParseStats), CollectError> {
    let mut acc = Accumulator::default();
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut bytes = 0usize;
    let mut oversize = false;

    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() {
            acc.finish(&lines, oversize)?;
            lines.clear();
            bytes = 0;
            oversize = false;
            continue;
        }
        bytes = bytes.saturating_add(line.len() + 1);
        if line.len() > MAX_LINE_BYTES
            || bytes > MAX_STANZA_BYTES
            || lines.len() >= MAX_STANZA_LINES
        {
            oversize = true;
        }
        if !oversize {
            lines.push(line);
        }
    }
    acc.finish(&lines, oversize)?;
    Ok((acc.items, acc.stats))
}

#[derive(Default)]
struct Accumulator {
    items: Vec<SoftwareItem>,
    seen: HashSet<SoftwareKey>,
    stats: ParseStats,
}

impl Accumulator {
    fn finish(&mut self, lines: &[&[u8]], oversize: bool) -> Result<(), CollectError> {
        if lines.is_empty() && !oversize {
            return Ok(());
        }
        let stanza = if oversize {
            Stanza::Malformed
        } else {
            parse_stanza(lines)
        };
        match stanza {
            Stanza::Malformed => self.stats.malformed += 1,
            Stanza::Excluded => self.stats.excluded += 1,
            Stanza::Item(item) => {
                if !self.seen.insert(item.key()) {
                    // Keep the first; proto validation rejects duplicate keys.
                    self.stats.malformed += 1;
                } else if self.items.len() >= MAX_ITEMS {
                    return Err(CollectError::TooLarge);
                } else {
                    self.items.push(item);
                }
            }
        }
        Ok(())
    }
}

enum Stanza {
    Item(SoftwareItem),
    Excluded,
    Malformed,
}

enum State {
    Installed,
    Excluded,
}

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_STRING_LEN && s.chars().all(|c| c.is_ascii_graphic())
}

fn parse_stanza(lines: &[&[u8]]) -> Stanza {
    let mut keys: HashSet<String> = HashSet::new();
    let (mut package, mut version, mut arch, mut status, mut source) =
        (None, None, None, None, None);
    // None: no field yet. Some(true): the previous field's continuation lines
    // are ignorable. Some(false): it is a field we read, which must be one line.
    let mut prev_ignorable: Option<bool> = None;

    for line in lines {
        if line.contains(&0) {
            return Stanza::Malformed;
        }
        let Ok(text) = std::str::from_utf8(line) else {
            return Stanza::Malformed;
        };
        if text.starts_with([' ', '\t']) {
            if prev_ignorable == Some(true) {
                continue;
            }
            return Stanza::Malformed;
        }
        let Some((key, value)) = text.split_once(':') else {
            return Stanza::Malformed;
        };
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_graphic()) {
            return Stanza::Malformed;
        }
        let lower = key.to_ascii_lowercase();
        if keys.len() >= MAX_FIELDS || !keys.insert(lower.clone()) {
            return Stanza::Malformed;
        }
        let value = value.trim_matches([' ', '\t']);
        prev_ignorable = Some(match lower.as_str() {
            "package" => {
                package = Some(value);
                false
            }
            "version" => {
                version = Some(value);
                false
            }
            "architecture" => {
                arch = Some(value);
                false
            }
            "status" => {
                status = Some(value);
                false
            }
            "source" => {
                source = Some(value);
                false
            }
            _ => true,
        });
    }

    // Status first: purged or never-installed stanzas may lack Version.
    let Some(status) = status else {
        return Stanza::Malformed;
    };
    match parse_status(status) {
        Some(State::Installed) => {}
        Some(State::Excluded) => return Stanza::Excluded,
        None => return Stanza::Malformed,
    }

    let (Some(name), Some(version), Some(arch)) = (package, version, arch) else {
        return Stanza::Malformed;
    };
    if !is_token(name) || !is_token(version) || !is_token(arch) {
        return Stanza::Malformed;
    }
    let source_package = match source {
        None => None,
        Some(s) => match parse_source(s) {
            Some(sp) => Some(sp),
            None => return Stanza::Malformed,
        },
    };
    Stanza::Item(SoftwareItem {
        name: name.to_owned(),
        version: version.to_owned(),
        arch: Some(arch.to_owned()),
        source: PackageSource::Dpkg,
        source_package,
        vendor: None,
        purl: None,
    })
}

/// Parses `<want> <error-flag> <state>`: exactly three tokens.
///
/// `want` is ignored (`deinstall ok installed` is still installed).
fn parse_status(s: &str) -> Option<State> {
    let tokens: Vec<&str> = s.split_ascii_whitespace().collect();
    let [_want, flag, state] = tokens.as_slice() else {
        return None;
    };
    if !matches!(*flag, "ok" | "reinst-required") {
        return None;
    }
    match *state {
        "installed" | "unpacked" | "half-configured" | "triggers-awaited" | "triggers-pending" => {
            Some(State::Installed)
        }
        "not-installed" | "config-files" | "half-installed" => Some(State::Excluded),
        _ => None,
    }
}

/// Parses `name` or `name (version)`.
fn parse_source(s: &str) -> Option<SourcePackage> {
    let Some((name, rest)) = s.split_once('(') else {
        return is_token(s).then(|| SourcePackage {
            name: s.to_owned(),
            version: None,
        });
    };
    let name = name.trim_end();
    let version = rest.strip_suffix(')')?;
    if !is_token(name) || !is_token(version) || version.contains(['(', ')']) {
        return None;
    }
    Some(SourcePackage {
        name: name.to_owned(),
        version: Some(version.to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::io::Cursor;

    use super::*;

    fn stanza(pkg: &str, ver: &str, arch: &str, status: &str) -> String {
        format!(
            "Package: {pkg}\nStatus: {status}\nPriority: optional\nArchitecture: {arch}\nVersion: {ver}\nDescription: x\n continued\n\n"
        )
    }

    fn ok(data: &[u8]) -> (Vec<SoftwareItem>, ParseStats) {
        parse(data).expect("parse should not fail")
    }

    fn stats(malformed: usize, excluded: usize) -> ParseStats {
        ParseStats {
            malformed,
            excluded,
        }
    }

    #[test]
    fn happy_path_with_folded_description_and_sources() {
        let data = format!(
            "{}{}Package: libfoo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:2.0-1\nSource: foo (2.0-1)\n\nPackage: bar\nStatus: install ok installed\nArchitecture: all\nVersion: 3\nSource: barsrc\n\n",
            stanza("a", "1", "amd64", "install ok installed"),
            stanza("a", "1", "i386", "install ok installed"),
        );
        let (items, s) = ok(data.as_bytes());
        assert_eq!(s, ParseStats::default());
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].arch.as_deref(), Some("amd64"));
        assert_eq!(items[1].arch.as_deref(), Some("i386"));
        let sp = items[2].source_package.as_ref().expect("source present");
        assert_eq!(sp.name, "foo");
        assert_eq!(sp.version.as_deref(), Some("2.0-1"));
        let sp = items[3].source_package.as_ref().expect("source present");
        assert_eq!((sp.name.as_str(), sp.version.as_deref()), ("barsrc", None));
        assert!(items.iter().all(|i| i.source == PackageSource::Dpkg));
        let keys: HashSet<_> = items.iter().map(SoftwareItem::key).collect();
        assert_eq!(keys.len(), items.len());
    }

    #[test]
    fn architecture_all_is_kept() {
        let (items, s) = ok(stanza("d", "1", "all", "install ok installed").as_bytes());
        assert_eq!(s, ParseStats::default());
        assert_eq!(items[0].arch.as_deref(), Some("all"));
    }

    #[test]
    fn empty_input_is_empty() {
        assert_eq!(ok(b""), (vec![], ParseStats::default()));
        assert_eq!(ok(b"\n\n\n"), (vec![], ParseStats::default()));
    }

    #[test]
    fn truncated_final_stanza_is_malformed_others_survive() {
        let mut data = stanza("good", "1", "amd64", "install ok installed");
        data.push_str("Package: cut\nStatus: install ok installed\nArchitecture: am");
        let (items, s) = ok(data.as_bytes());
        assert_eq!(items.len(), 1);
        assert_eq!(s, stats(1, 0));
    }

    #[test]
    fn truncated_mid_field_without_colon_is_malformed() {
        let (items, s) = ok(b"Package: x\nStatus: install ok installed\nVers");
        assert_eq!(items.len(), 0);
        assert_eq!(s, stats(1, 0));
    }

    #[test]
    fn missing_required_fields_are_malformed() {
        for data in [
            "Status: install ok installed\nArchitecture: amd64\nVersion: 1\n\n",
            "Package: x\nStatus: install ok installed\nArchitecture: amd64\n\n",
            "Package: x\nStatus: install ok installed\nVersion: 1\n\n",
            "Package: x\nArchitecture: amd64\nVersion: 1\n\n",
        ] {
            let (items, s) = ok(data.as_bytes());
            assert!(items.is_empty(), "{data}");
            assert_eq!(s, stats(1, 0), "{data}");
        }
    }

    #[test]
    fn duplicate_field_in_stanza_is_malformed() {
        let data = "Package: x\nPackage: y\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n";
        let (items, s) = ok(data.as_bytes());
        assert_eq!(items.len(), 0);
        assert_eq!(s, stats(1, 0));
        let data = "Package: x\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\nDescription: a\nDescription: b\n\n";
        assert_eq!(ok(data.as_bytes()).1, stats(1, 0));
    }

    #[test]
    fn duplicate_package_across_stanzas_keeps_first() {
        let data = format!(
            "{}{}",
            stanza("x", "1", "amd64", "install ok installed"),
            stanza("x", "1", "amd64", "install ok installed"),
        );
        let (items, s) = ok(data.as_bytes());
        assert_eq!(items.len(), 1);
        assert_eq!(s, stats(1, 0));
    }

    #[test]
    fn giant_line_poisons_only_its_stanza() {
        let mut data = stanza("good", "1", "amd64", "install ok installed").into_bytes();
        data.extend_from_slice(b"Package: big\nStatus: install ok installed\nDescription: ");
        data.extend(std::iter::repeat_n(b'x', MAX_LINE_BYTES + 1));
        data.extend_from_slice(b"\nArchitecture: amd64\nVersion: 1\n\n");
        data.extend(stanza("after", "1", "amd64", "install ok installed").into_bytes());
        let (items, s) = ok(&data);
        assert_eq!(items.len(), 2);
        assert_eq!(s, stats(1, 0));
    }

    #[test]
    fn oversized_stanza_is_malformed() {
        let mut data =
            b"Package: big\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n"
                .to_vec();
        let filler = format!("X-Pad: {}\n", "y".repeat(1000));
        for _ in 0..(MAX_STANZA_BYTES / filler.len() + 2) {
            data.extend_from_slice(b" ");
            data.extend_from_slice(filler.as_bytes());
        }
        data.extend_from_slice(b"\n");
        assert_eq!(ok(&data), (vec![], stats(1, 0)));
    }

    #[test]
    fn overlong_value_is_malformed() {
        let data = stanza(
            &"p".repeat(MAX_STRING_LEN + 1),
            "1",
            "amd64",
            "install ok installed",
        );
        assert_eq!(ok(data.as_bytes()), (vec![], stats(1, 0)));
    }

    #[test]
    fn nul_byte_is_malformed() {
        let data =
            b"Package: x\0y\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n";
        assert_eq!(ok(data), (vec![], stats(1, 0)));
    }

    #[test]
    fn bad_utf8_is_malformed_only_and_neighbours_parse() {
        let mut data = stanza("before", "1", "amd64", "install ok installed").into_bytes();
        data.extend_from_slice(
            b"Package: bad\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\nDescription: \xff\xfe\n\n",
        );
        data.extend(stanza("after", "1", "amd64", "install ok installed").into_bytes());
        let (items, s) = ok(&data);
        assert_eq!(items.len(), 2);
        assert_eq!(s, stats(1, 0));
    }

    #[test]
    fn continuation_without_field_or_on_read_field_is_malformed() {
        let data = " orphan\nPackage: x\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n";
        assert_eq!(ok(data.as_bytes()).1, stats(1, 0));
        let data =
            "Package: x\n more\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n";
        assert_eq!(ok(data.as_bytes()).1, stats(1, 0));
    }

    #[test]
    fn status_with_two_or_four_tokens_is_malformed() {
        for status in [
            "ok installed",
            "install ok installed extra",
            "",
            "installed",
        ] {
            let data = stanza("x", "1", "amd64", status);
            assert_eq!(ok(data.as_bytes()), (vec![], stats(1, 0)), "{status:?}");
        }
    }

    #[test]
    fn missing_status_is_malformed() {
        let data = "Package: x\nArchitecture: amd64\nVersion: 1\n\n";
        assert_eq!(ok(data.as_bytes()), (vec![], stats(1, 0)));
    }

    #[test]
    fn installed_states_yield_items() {
        for state in [
            "installed",
            "unpacked",
            "half-configured",
            "triggers-awaited",
            "triggers-pending",
        ] {
            let data = stanza("x", "1", "amd64", &format!("install ok {state}"));
            let (items, s) = ok(data.as_bytes());
            assert_eq!(items.len(), 1, "{state}");
            assert_eq!(s, ParseStats::default(), "{state}");
        }
    }

    #[test]
    fn excluded_states_increment_excluded_only() {
        for state in ["not-installed", "config-files", "half-installed"] {
            let data = stanza("x", "1", "amd64", &format!("install ok {state}"));
            assert_eq!(ok(data.as_bytes()), (vec![], stats(0, 1)), "{state}");
        }
    }

    #[test]
    fn excluded_stanza_may_lack_version() {
        let data = "Package: gone\nStatus: purge ok not-installed\n\n";
        assert_eq!(ok(data.as_bytes()), (vec![], stats(0, 1)));
    }

    #[test]
    fn want_is_ignored_and_reinst_required_accepted() {
        let data = stanza("x", "1", "amd64", "deinstall ok installed");
        assert_eq!(ok(data.as_bytes()).0.len(), 1);
        let data = stanza("x", "1", "amd64", "install reinst-required installed");
        assert_eq!(ok(data.as_bytes()).0.len(), 1);
    }

    #[test]
    fn unknown_error_flag_or_state_is_malformed() {
        for status in ["install bogus installed", "install ok bogus"] {
            let data = stanza("x", "1", "amd64", status);
            assert_eq!(ok(data.as_bytes()), (vec![], stats(1, 0)), "{status}");
        }
    }

    #[test]
    fn malformed_source_is_malformed_stanza() {
        for source in [
            "foo (1.2",
            "foo (1.2) junk",
            "(1.2)",
            "foo ()",
            "foo (a(b))",
            "",
        ] {
            let data = format!(
                "Package: x\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\nSource: {source}\n\n"
            );
            assert_eq!(ok(data.as_bytes()), (vec![], stats(1, 0)), "{source:?}");
        }
    }

    #[test]
    fn counters_are_independent() {
        let mut data = stanza("ok", "1", "amd64", "install ok installed").into_bytes();
        data.extend(stanza("cfg", "1", "amd64", "deinstall ok config-files").into_bytes());
        data.extend_from_slice(b"Package: bad\nStatus: install ok installed\nVersion: \xff\n\n");
        assert_eq!(ok(&data).1, stats(1, 1));
    }

    #[test]
    fn too_many_items_is_too_large() {
        let mut data = String::new();
        for i in 0..=MAX_ITEMS {
            let _ = writeln!(
                data,
                "Package: p{i}\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n"
            );
        }
        assert!(matches!(
            parse(data.as_bytes()),
            Err(CollectError::TooLarge)
        ));
    }

    #[test]
    fn file_cap_boundary() {
        let data = stanza("x", "1", "amd64", "install ok installed").into_bytes();
        let cap = u64::try_from(data.len()).expect("len fits u64");
        assert!(collect_with_cap(Cursor::new(data.clone()), cap).is_ok());
        assert!(matches!(
            collect_with_cap(Cursor::new(data), cap - 1),
            Err(CollectError::TooLarge)
        ));
    }

    #[test]
    fn collector_id_and_missing_file() {
        let c = DpkgCollector::with_path("/nonexistent/traysis/status");
        assert_eq!(c.id(), "dpkg");
        assert!(matches!(c.software(), Err(CollectError::Io(_))));
    }

    /// Manual: `cargo test -p traysis-agent -- --ignored`. Never in CI.
    #[test]
    #[ignore = "reads this machine's /var/lib/dpkg/status"]
    fn real_status_file_smoke() {
        let (items, s) = DpkgCollector::new()
            .software_with_stats()
            .expect("real status file should parse");
        eprintln!("{} items, {s:?}", items.len());
        assert_ne!(items.len(), 0);
    }
}
