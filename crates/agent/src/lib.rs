//! Endpoint agent library: platform-agnostic seams used by the daemon binary.

pub mod collector;
#[cfg(unix)]
pub mod differ;
#[cfg(unix)]
pub mod state;
#[cfg(test)]
mod testutil;
