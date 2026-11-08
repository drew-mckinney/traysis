//! Traysis server library: delta-apply logic over a SQLite inventory store.
//!
//! [`apply`] takes an authenticated host identity and a decoded
//! [`traysis_proto::inventory::SoftwareDelta`], atomically updates that host's
//! stored inventory, and returns the [`traysis_proto::inventory::DeltaAck`].
//! There is no network, async code, or clock access here: the transport layer
//! supplies the identity and the receive time. See `docs/server.md`.

#[cfg(unix)]
pub mod apply;
#[cfg(unix)]
pub mod error;
#[cfg(unix)]
pub mod store;
#[cfg(test)]
mod testutil;

#[cfg(unix)]
pub use apply::apply;
#[cfg(unix)]
pub use error::{ApplyError, StoreError};
#[cfg(unix)]
pub use store::Store;
