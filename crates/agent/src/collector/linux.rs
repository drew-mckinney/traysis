//! Linux collectors. Compiled only on Linux.

use std::io::Read;

use super::CollectError;

pub mod dpkg;
pub mod os_release;

pub use dpkg::{DpkgCollector, ParseStats};
pub use os_release::OsReleaseCollector;

/// Reads at most `max` bytes from `r`, failing with [`CollectError::TooLarge`]
/// if more are available.
///
/// Reads `max + 1` bytes so that an oversized input is detected; `take(max)`
/// alone would silently truncate it.
pub(crate) fn read_bounded<R: Read>(r: R, max: u64) -> Result<Vec<u8>, CollectError> {
    let mut buf = Vec::new();
    r.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max {
        return Err(CollectError::TooLarge);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn read_bounded_accepts_exactly_max() {
        let got = read_bounded(Cursor::new(vec![b'a'; 16]), 16);
        assert_eq!(got.ok().map(|v| v.len()), Some(16));
    }

    #[test]
    fn read_bounded_rejects_one_byte_over() {
        let got = read_bounded(Cursor::new(vec![b'a'; 17]), 16);
        assert!(matches!(got, Err(CollectError::TooLarge)));
    }
}
