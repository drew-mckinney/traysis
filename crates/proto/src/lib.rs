//! Wire protocol shared by the agent and the server.
//!
//! [`inventory`] and [`envelope`] hold the validated domain model. The
//! protobuf encoding is private: use [`Envelope::decode`] and
//! [`Envelope::encode_to_vec`], which convert to and from the generated types
//! and validate everything that crosses the boundary. See `docs/protocol.md`.

pub mod envelope;
pub mod inventory;

mod convert;

pub use convert::WireError;
pub use envelope::{Body, Envelope, IdAllocator, MAX_ENVELOPE_BYTES, Ping, Pong, Role};

/// Generated protobuf types. Never used outside this crate's conversion layer.
#[allow(
    clippy::pedantic,
    clippy::all,
    unreachable_pub,
    missing_docs,
    unused_qualifications
)]
mod wire {
    include!(concat!(env!("OUT_DIR"), "/traysis.v1.rs"));
}
