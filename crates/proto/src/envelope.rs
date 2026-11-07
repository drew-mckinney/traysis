//! The message envelope and request-id allocation.
//!
//! Id rules (see `docs/protocol.md`): `0` is invalid; a response echoes its
//! request's id; the agent allocates odd ids and the server even ids, so the
//! two sides never collide. [`IdAllocator`] implements the allocation; checking
//! that an incoming id matches the peer's parity or a pending request is the
//! session layer's job.

use serde::{Deserialize, Serialize};

use crate::inventory::{DeltaAck, SoftwareDelta, ValidationError};

/// Maximum size in bytes of one encoded [`Envelope`].
///
/// Sized to hold a full-snapshot [`SoftwareDelta`]
/// ([`MAX_DELTA_COST`](crate::inventory::MAX_DELTA_COST), which bounds the
/// string bytes plus per-entry overhead that covers protobuf framing) plus
/// 1 MiB of headroom for the envelope, `host_os`, and digest.
///
/// **The transport's maximum frame length must use this value.**
/// [`Envelope::decode`] rejects anything larger.
pub const MAX_ENVELOPE_BYTES: usize = crate::inventory::MAX_DELTA_COST + 1024 * 1024;

/// Application-level keepalive request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping;

/// Response to a [`Ping`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pong;

/// The payload of an [`Envelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Body {
    /// Agent to server inventory update.
    Delta(SoftwareDelta),
    /// Server response to a delta.
    DeltaAck(DeltaAck),
    /// Keepalive request.
    Ping(Ping),
    /// Keepalive response.
    Pong(Pong),
}

/// One message on a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Request/response correlation id; never 0 on a valid message.
    pub id: u64,
    /// The payload.
    pub body: Body,
}

/// Which end of a connection a peer is; decides which request ids it owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The endpoint agent: odd ids.
    Agent,
    /// The server: even ids.
    Server,
}

impl Role {
    /// Whether a request originated by this role carries `id`: nonzero and of
    /// this role's parity.
    #[must_use]
    pub fn owns(self, id: u64) -> bool {
        id != 0 && (id % 2 == 1) == (self == Self::Agent)
    }
}

/// Allocates request ids for one connection: agent 1, 3, 5, …; server 2, 4, ….
#[derive(Debug, Clone)]
pub struct IdAllocator {
    next: Option<u64>,
}

impl IdAllocator {
    /// A fresh allocator for `role`. Use one per connection.
    #[must_use]
    pub fn new(role: Role) -> Self {
        Self {
            next: Some(match role {
                Role::Agent => 1,
                Role::Server => 2,
            }),
        }
    }

    /// The next id, or `None` once the id space is exhausted. On `None` the
    /// caller must close the connection rather than reuse an id.
    pub fn next_id(&mut self) -> Option<u64> {
        let id = self.next?;
        self.next = id.checked_add(2);
        Some(id)
    }
}

impl From<ValidationError> for crate::WireError {
    fn from(e: ValidationError) -> Self {
        Self::Invalid(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_ids_are_odd_and_server_ids_even() {
        let mut a = IdAllocator::new(Role::Agent);
        let mut s = IdAllocator::new(Role::Server);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let (x, y) = (a.next_id().unwrap(), s.next_id().unwrap());
            assert!(x % 2 == 1 && y % 2 == 0 && x != 0 && y != 0);
            assert!(Role::Agent.owns(x) && !Role::Server.owns(x));
            assert!(Role::Server.owns(y) && !Role::Agent.owns(y));
            assert!(seen.insert(x) && seen.insert(y));
        }
    }

    #[test]
    fn zero_is_owned_by_nobody() {
        assert!(!Role::Agent.owns(0));
        assert!(!Role::Server.owns(0));
    }

    #[test]
    fn allocator_exhausts_instead_of_wrapping() {
        let mut a = IdAllocator::new(Role::Agent);
        a.next = Some(u64::MAX);
        assert_eq!(a.next_id(), Some(u64::MAX));
        assert_eq!(a.next_id(), None);
        let mut s = IdAllocator::new(Role::Server);
        s.next = Some(u64::MAX - 1);
        assert_eq!(s.next_id(), Some(u64::MAX - 1));
        assert_eq!(s.next_id(), None);
    }
}
