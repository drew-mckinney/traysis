//! Conversion between the validated domain model and the protobuf wire types.
//!
//! `From<domain> for wire` is infallible. `TryFrom<wire> for domain` treats
//! the wire value as untrusted and returns a [`WireError`] for every
//! violation; a [`SoftwareDelta`] only comes out of it after
//! [`SoftwareDelta::validate`] has passed. The generated types stay private
//! to the crate: callers use [`Envelope::decode`] and
//! [`Envelope::encode_to_vec`].

use std::fmt;

use prost::Message as _;

use crate::envelope::{Body, Envelope, MAX_ENVELOPE_BYTES, Ping, Pong};
use crate::inventory::{
    AckOutcome, DeltaAck, Epoch, HostId, HostOs, MAX_ITEMS, PackageSource, ResyncReason,
    SoftwareDelta, SoftwareItem, SoftwareKey, SourcePackage, UnixMillis, ValidationError,
};
use crate::wire as w;

/// Why a wire message was rejected. `Display` never echoes payload contents,
/// only field names and numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// Protobuf decoding failed (truncation, bad wire type, bad varint, …).
    Decode(prost::DecodeError),
    /// The encoded envelope exceeds [`MAX_ENVELOPE_BYTES`].
    EnvelopeTooLarge(usize),
    /// The pre-decode structural scan found malformed framing.
    Malformed,
    /// The envelope id is 0.
    ZeroId,
    /// A nonzero id with no recognized body: either unset or a message kind
    /// from a newer peer. An unsupported-message condition; the id is kept so
    /// the session layer can log or answer it.
    UnsupportedMessage {
        /// The envelope id.
        id: u64,
    },
    /// An enum field holds `*_UNSPECIFIED`.
    UnspecifiedEnum(&'static str),
    /// An enum field holds a number this build does not know.
    UnknownEnum {
        /// The field name.
        field: &'static str,
        /// The received number.
        value: i32,
    },
    /// `source` is OTHER but `other_source` is empty.
    OtherSourceEmpty,
    /// `source` is not OTHER but `other_source` is nonempty.
    StraySourceName,
    /// The outcome is `NEED_RESYNC` but no reason was given.
    ResyncReasonMissing,
    /// A reason was given but the outcome is not `NEED_RESYNC`.
    ResyncReasonUnexpected,
    /// `state_digest` is not exactly 32 bytes; carries the received length.
    BadDigestLength(usize),
    /// `schema_version` does not fit in 16 bits.
    SchemaVersionOutOfRange(u32),
    /// The converted value violates a domain invariant.
    Invalid(ValidationError),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "protobuf decode error: {e}"),
            Self::EnvelopeTooLarge(n) => {
                write!(f, "envelope of {n} bytes exceeds {MAX_ENVELOPE_BYTES}")
            }
            Self::Malformed => f.write_str("malformed protobuf framing"),
            Self::ZeroId => f.write_str("envelope id 0 is invalid"),
            Self::UnsupportedMessage { id } => {
                write!(f, "envelope {id} has no recognized body")
            }
            Self::UnspecifiedEnum(n) => write!(f, "enum field `{n}` is UNSPECIFIED"),
            Self::UnknownEnum { field, value } => {
                write!(f, "enum field `{field}` has unknown value {value}")
            }
            Self::OtherSourceEmpty => f.write_str("source OTHER requires `other_source`"),
            Self::StraySourceName => f.write_str("`other_source` is only valid with source OTHER"),
            Self::ResyncReasonMissing => f.write_str("NEED_RESYNC requires a resync reason"),
            Self::ResyncReasonUnexpected => {
                f.write_str("resync reason is only valid with NEED_RESYNC")
            }
            Self::BadDigestLength(n) => write!(f, "state digest is {n} bytes, expected 32"),
            Self::SchemaVersionOutOfRange(v) => write!(f, "schema version {v} exceeds 65535"),
            Self::Invalid(e) => write!(f, "invalid message: {e}"),
        }
    }
}

impl std::error::Error for WireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            Self::Invalid(e) => Some(e),
            _ => None,
        }
    }
}

impl From<prost::DecodeError> for WireError {
    fn from(e: prost::DecodeError) -> Self {
        Self::Decode(e)
    }
}

// ---------------------------------------------------------------------------
// Enums

fn source_to_wire(source: PackageSource) -> (i32, String) {
    let (kind, other) = match source {
        PackageSource::Dpkg => (w::PackageSource::Dpkg, String::new()),
        PackageSource::Rpm => (w::PackageSource::Rpm, String::new()),
        PackageSource::Apk => (w::PackageSource::Apk, String::new()),
        PackageSource::Pacman => (w::PackageSource::Pacman, String::new()),
        PackageSource::Brew => (w::PackageSource::Brew, String::new()),
        PackageSource::Other(s) => (w::PackageSource::Other, s),
    };
    (i32::from(kind), other)
}

fn source_from_wire(kind: i32, other: String) -> Result<PackageSource, WireError> {
    let kind = w::PackageSource::try_from(kind).map_err(|_| WireError::UnknownEnum {
        field: "source",
        value: kind,
    })?;
    let named = match kind {
        w::PackageSource::Unspecified => return Err(WireError::UnspecifiedEnum("source")),
        w::PackageSource::Other => {
            return if other.is_empty() {
                Err(WireError::OtherSourceEmpty)
            } else {
                Ok(PackageSource::Other(other))
            };
        }
        w::PackageSource::Dpkg => PackageSource::Dpkg,
        w::PackageSource::Rpm => PackageSource::Rpm,
        w::PackageSource::Apk => PackageSource::Apk,
        w::PackageSource::Pacman => PackageSource::Pacman,
        w::PackageSource::Brew => PackageSource::Brew,
    };
    if other.is_empty() {
        Ok(named)
    } else {
        Err(WireError::StraySourceName)
    }
}

fn outcome_to_wire(outcome: AckOutcome) -> (i32, i32) {
    let (o, r) = match outcome {
        AckOutcome::Applied => (w::AckOutcome::Applied, w::ResyncReason::Unspecified),
        AckOutcome::Duplicate => (w::AckOutcome::Duplicate, w::ResyncReason::Unspecified),
        AckOutcome::NeedResync(reason) => (w::AckOutcome::NeedResync, reason.into()),
    };
    (i32::from(o), i32::from(r))
}

impl From<ResyncReason> for w::ResyncReason {
    fn from(r: ResyncReason) -> Self {
        match r {
            ResyncReason::DigestMismatch => Self::DigestMismatch,
            ResyncReason::SeqGap => Self::SeqGap,
            ResyncReason::EpochStale => Self::EpochStale,
            ResyncReason::StateUnknown => Self::StateUnknown,
        }
    }
}

fn outcome_from_wire(outcome: i32, reason: i32) -> Result<AckOutcome, WireError> {
    let outcome = w::AckOutcome::try_from(outcome).map_err(|_| WireError::UnknownEnum {
        field: "outcome",
        value: outcome,
    })?;
    let reason = w::ResyncReason::try_from(reason).map_err(|_| WireError::UnknownEnum {
        field: "resync_reason",
        value: reason,
    })?;
    match (outcome, reason) {
        (w::AckOutcome::Unspecified, _) => Err(WireError::UnspecifiedEnum("outcome")),
        (w::AckOutcome::NeedResync, w::ResyncReason::Unspecified) => {
            Err(WireError::ResyncReasonMissing)
        }
        (w::AckOutcome::NeedResync, r) => Ok(AckOutcome::NeedResync(match r {
            w::ResyncReason::DigestMismatch => ResyncReason::DigestMismatch,
            w::ResyncReason::SeqGap => ResyncReason::SeqGap,
            w::ResyncReason::EpochStale => ResyncReason::EpochStale,
            // The `Unspecified` arm above already returned.
            w::ResyncReason::StateUnknown | w::ResyncReason::Unspecified => {
                ResyncReason::StateUnknown
            }
        })),
        (_, w::ResyncReason::Unspecified) => Ok(match outcome {
            w::AckOutcome::Duplicate => AckOutcome::Duplicate,
            _ => AckOutcome::Applied,
        }),
        (_, _) => Err(WireError::ResyncReasonUnexpected),
    }
}

// ---------------------------------------------------------------------------
// Messages: domain -> wire

impl From<SourcePackage> for w::SourcePackage {
    fn from(sp: SourcePackage) -> Self {
        Self {
            name: sp.name,
            version: sp.version,
        }
    }
}

impl From<SoftwareItem> for w::SoftwareItem {
    fn from(item: SoftwareItem) -> Self {
        let (source, other_source) = source_to_wire(item.source);
        Self {
            name: item.name,
            version: item.version,
            arch: item.arch,
            source,
            other_source,
            source_package: item.source_package.map(Into::into),
            vendor: item.vendor,
            purl: item.purl,
        }
    }
}

impl From<SoftwareKey> for w::SoftwareKey {
    fn from(key: SoftwareKey) -> Self {
        let (source, other_source) = source_to_wire(key.source);
        Self {
            source,
            other_source,
            name: key.name,
            arch: key.arch,
            version: key.version,
        }
    }
}

impl From<HostOs> for w::HostOs {
    fn from(os: HostOs) -> Self {
        Self {
            id: os.id,
            version_id: os.version_id,
            arch: os.arch,
        }
    }
}

impl From<SoftwareDelta> for w::SoftwareDelta {
    fn from(d: SoftwareDelta) -> Self {
        Self {
            schema_version: u32::from(d.schema_version),
            host_id: d.host_id.0,
            epoch: d.epoch.0,
            seq: d.seq,
            full: d.full,
            host_os: d.host_os.map(Into::into),
            collected_at: d.collected_at.0,
            upserted: d.upserted.into_iter().map(Into::into).collect(),
            removed: d.removed.into_iter().map(Into::into).collect(),
            state_digest: d.state_digest.to_vec(),
        }
    }
}

impl From<DeltaAck> for w::DeltaAck {
    fn from(a: DeltaAck) -> Self {
        let (outcome, resync_reason) = outcome_to_wire(a.outcome);
        Self {
            epoch: a.epoch.0,
            seq: a.seq,
            outcome,
            resync_reason,
        }
    }
}

impl From<Envelope> for w::Envelope {
    fn from(e: Envelope) -> Self {
        let body = match e.body {
            Body::Delta(d) => w::envelope::Body::Delta(d.into()),
            Body::DeltaAck(a) => w::envelope::Body::DeltaAck(a.into()),
            Body::Ping(Ping) => w::envelope::Body::Ping(w::Ping {}),
            Body::Pong(Pong) => w::envelope::Body::Pong(w::Pong {}),
        };
        Self {
            id: e.id,
            body: Some(body),
        }
    }
}

// ---------------------------------------------------------------------------
// Messages: wire -> domain

impl TryFrom<w::SourcePackage> for SourcePackage {
    type Error = WireError;

    fn try_from(sp: w::SourcePackage) -> Result<Self, WireError> {
        Ok(Self {
            name: sp.name,
            version: sp.version,
        })
    }
}

impl TryFrom<w::SoftwareItem> for SoftwareItem {
    type Error = WireError;

    fn try_from(item: w::SoftwareItem) -> Result<Self, WireError> {
        Ok(Self {
            source: source_from_wire(item.source, item.other_source)?,
            name: item.name,
            version: item.version,
            arch: item.arch,
            source_package: item.source_package.map(TryInto::try_into).transpose()?,
            vendor: item.vendor,
            purl: item.purl,
        })
    }
}

impl TryFrom<w::SoftwareKey> for SoftwareKey {
    type Error = WireError;

    fn try_from(key: w::SoftwareKey) -> Result<Self, WireError> {
        Ok(Self {
            source: source_from_wire(key.source, key.other_source)?,
            name: key.name,
            arch: key.arch,
            version: key.version,
        })
    }
}

impl TryFrom<w::HostOs> for HostOs {
    type Error = WireError;

    fn try_from(os: w::HostOs) -> Result<Self, WireError> {
        Ok(Self {
            id: os.id,
            version_id: os.version_id,
            arch: os.arch,
        })
    }
}

impl TryFrom<w::SoftwareDelta> for SoftwareDelta {
    type Error = WireError;

    fn try_from(d: w::SoftwareDelta) -> Result<Self, WireError> {
        let schema_version = u16::try_from(d.schema_version)
            .map_err(|_| WireError::SchemaVersionOutOfRange(d.schema_version))?;
        let state_digest: [u8; 32] = d
            .state_digest
            .as_slice()
            .try_into()
            .map_err(|_| WireError::BadDigestLength(d.state_digest.len()))?;
        let delta = Self {
            schema_version,
            host_id: HostId(d.host_id),
            epoch: Epoch(d.epoch),
            seq: d.seq,
            full: d.full,
            host_os: d.host_os.map(TryInto::try_into).transpose()?,
            collected_at: UnixMillis(d.collected_at),
            upserted: d
                .upserted
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            removed: d
                .removed
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            state_digest,
        };
        delta.validate()?;
        Ok(delta)
    }
}

impl TryFrom<w::DeltaAck> for DeltaAck {
    type Error = WireError;

    fn try_from(a: w::DeltaAck) -> Result<Self, WireError> {
        Ok(Self {
            epoch: Epoch(a.epoch),
            seq: a.seq,
            outcome: outcome_from_wire(a.outcome, a.resync_reason)?,
        })
    }
}

impl TryFrom<w::Envelope> for Envelope {
    type Error = WireError;

    fn try_from(e: w::Envelope) -> Result<Self, WireError> {
        if e.id == 0 {
            return Err(WireError::ZeroId);
        }
        let body = match e.body {
            Some(w::envelope::Body::Delta(d)) => Body::Delta(d.try_into()?),
            Some(w::envelope::Body::DeltaAck(a)) => Body::DeltaAck(a.try_into()?),
            Some(w::envelope::Body::Ping(_)) => Body::Ping(Ping),
            Some(w::envelope::Body::Pong(_)) => Body::Pong(Pong),
            None => return Err(WireError::UnsupportedMessage { id: e.id }),
        };
        Ok(Self { id: e.id, body })
    }
}

// ---------------------------------------------------------------------------
// Bytes <-> Envelope

impl Envelope {
    /// Serializes this envelope to protobuf bytes.
    ///
    /// The bytes are not canonical: protobuf permits other encodings of the
    /// same message. Sign or hash the exact bytes you send, never a
    /// re-encoding.
    #[must_use]
    pub fn encode_to_vec(self) -> Vec<u8> {
        w::Envelope::from(self).encode_to_vec()
    }

    /// Decodes and validates one envelope.
    ///
    /// Untrusted input is checked in this order: total size against
    /// [`MAX_ENVELOPE_BYTES`], a structural pre-scan that bounds the entry
    /// counts of a delta before anything is allocated for them, protobuf
    /// decoding, then conversion to the domain model (ending in
    /// [`SoftwareDelta::validate`]). Unknown fields are ignored and dropped.
    ///
    /// # Errors
    ///
    /// Returns a [`WireError`] for any violation; never panics.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(WireError::EnvelopeTooLarge(bytes.len()));
        }
        prescan(bytes)?;
        w::Envelope::decode(bytes)?.try_into()
    }
}

// ---------------------------------------------------------------------------
// Pre-scan

/// Entry counts found by [`prescan`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct EntryCounts {
    upserted: usize,
    removed: usize,
}

/// Envelope field number of the `delta` body.
const ENVELOPE_DELTA_FIELD: u64 = 2;
/// `SoftwareDelta` field numbers of the two repeated lists.
const DELTA_UPSERTED_FIELD: u64 = 8;
const DELTA_REMOVED_FIELD: u64 = 9;

/// A decoded `SoftwareItem` costs on the order of 200 bytes of memory but
/// encodes in as little as 2, so a frame of empty entries would amplify
/// roughly 100x during decode. This scan walks the framing without
/// allocating, counts the entries of `upserted` and `removed` across every
/// occurrence of the `delta` field (protobuf merges repeated occurrences),
/// and rejects the input if either list exceeds [`MAX_ITEMS`].
///
/// It never undercounts: it counts every length-delimited occurrence of those
/// fields, which is all prost can decode into the lists. It is deliberately
/// stricter than prost about group wire types (3 and 4), which it rejects.
fn prescan(buf: &[u8]) -> Result<EntryCounts, WireError> {
    let mut counts = EntryCounts::default();
    let mut rest = buf;
    while !rest.is_empty() {
        let (field, wire_type) = read_key(&mut rest)?;
        if field == ENVELOPE_DELTA_FIELD && wire_type == 2 {
            let delta = read_len_delimited(&mut rest)?;
            scan_delta(delta, &mut counts)?;
        } else {
            skip_value(&mut rest, wire_type)?;
        }
    }
    Ok(counts)
}

fn scan_delta(mut buf: &[u8], counts: &mut EntryCounts) -> Result<(), WireError> {
    while !buf.is_empty() {
        let (field, wire_type) = read_key(&mut buf)?;
        if wire_type == 2 && (field == DELTA_UPSERTED_FIELD || field == DELTA_REMOVED_FIELD) {
            read_len_delimited(&mut buf)?;
            let (count, name) = if field == DELTA_UPSERTED_FIELD {
                (&mut counts.upserted, "upserted")
            } else {
                (&mut counts.removed, "removed")
            };
            *count += 1;
            if *count > MAX_ITEMS {
                return Err(ValidationError::TooManyItems(name).into());
            }
        } else {
            skip_value(&mut buf, wire_type)?;
        }
    }
    Ok(())
}

/// Reads a varint, rejecting more than 10 bytes or a 10th byte above 1, as
/// prost does.
fn read_varint(buf: &mut &[u8]) -> Result<u64, WireError> {
    let mut value = 0u64;
    for i in 0..10 {
        let (&byte, tail) = buf.split_first().ok_or(WireError::Malformed)?;
        *buf = tail;
        if i == 9 && byte > 1 {
            return Err(WireError::Malformed);
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(WireError::Malformed)
}

/// Reads a field key: field number (nonzero, below 2^29) and wire type.
fn read_key(buf: &mut &[u8]) -> Result<(u64, u8), WireError> {
    let key = read_varint(buf)?;
    let field = key >> 3;
    if field == 0 || field >= 1 << 29 {
        return Err(WireError::Malformed);
    }
    // `key & 7` is below 8, so the narrowing cannot truncate.
    Ok((
        field,
        u8::try_from(key & 7).map_err(|_| WireError::Malformed)?,
    ))
}

fn read_len_delimited<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], WireError> {
    let len = usize::try_from(read_varint(buf)?).map_err(|_| WireError::Malformed)?;
    if len > buf.len() {
        return Err(WireError::Malformed);
    }
    let (value, tail) = buf.split_at(len);
    *buf = tail;
    Ok(value)
}

fn skip_value(buf: &mut &[u8], wire_type: u8) -> Result<(), WireError> {
    match wire_type {
        0 => read_varint(buf).map(drop),
        1 => skip_fixed(buf, 8),
        2 => read_len_delimited(buf).map(drop),
        5 => skip_fixed(buf, 4),
        _ => Err(WireError::Malformed),
    }
}

fn skip_fixed(buf: &mut &[u8], n: usize) -> Result<(), WireError> {
    if n > buf.len() {
        return Err(WireError::Malformed);
    }
    *buf = &buf[n..];
    Ok(())
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{SCHEMA_VERSION, state_digest};

    // ----- fixtures -----

    /// The fixed delta whose encoding is checked in as the golden file.
    fn golden_delta() -> SoftwareDelta {
        SoftwareDelta {
            schema_version: SCHEMA_VERSION,
            host_id: HostId("host-1".to_owned()),
            epoch: Epoch(3),
            seq: 7,
            full: false,
            host_os: Some(HostOs {
                id: "debian".to_owned(),
                version_id: Some("12".to_owned()),
                arch: "x86_64".to_owned(),
            }),
            collected_at: UnixMillis(1_700_000_000_000),
            upserted: vec![
                SoftwareItem {
                    name: "openssl".to_owned(),
                    version: "3.0.11-1".to_owned(),
                    arch: Some("amd64".to_owned()),
                    source: PackageSource::Dpkg,
                    source_package: Some(SourcePackage {
                        name: "openssl".to_owned(),
                        version: None,
                    }),
                    vendor: Some("Debian".to_owned()),
                    purl: Some("pkg:deb/debian/openssl@3.0.11-1".to_owned()),
                },
                SoftwareItem {
                    name: "firefox".to_owned(),
                    version: "130.0".to_owned(),
                    arch: None,
                    source: PackageSource::Other("snap".to_owned()),
                    source_package: None,
                    vendor: None,
                    purl: None,
                },
            ],
            removed: vec![SoftwareKey {
                source: PackageSource::Rpm,
                name: "kernel".to_owned(),
                arch: Some(String::new()),
                version: "6.1.1".to_owned(),
            }],
            state_digest: std::array::from_fn(|i| u8::try_from(i).unwrap()),
        }
    }

    fn golden_envelope() -> Envelope {
        Envelope {
            id: 1,
            body: Body::Delta(golden_delta()),
        }
    }

    fn golden_bytes() -> Vec<u8> {
        let hex: String = include_str!("../tests/golden/software_delta_v1.hex")
            .split_whitespace()
            .collect();
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn valid_wire_delta() -> w::SoftwareDelta {
        golden_delta().into()
    }

    fn wire_item() -> w::SoftwareItem {
        golden_delta().upserted.remove(0).into()
    }

    fn round_trip(env: Envelope) {
        let bytes = env.clone().encode_to_vec();
        assert_eq!(Envelope::decode(&bytes), Ok(env));
    }

    // ----- varint/field builders for hand-made malformed input -----

    fn varint(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = u8::try_from(n & 0x7f).unwrap();
            n >>= 7;
            if n == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }

    fn field(num: u64, wire_type: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = varint(num << 3 | wire_type);
        out.extend_from_slice(payload);
        out
    }

    fn len_field(num: u64, payload: &[u8]) -> Vec<u8> {
        let mut body = varint(payload.len() as u64);
        body.extend_from_slice(payload);
        field(num, 2, &body)
    }

    fn envelope_with_delta(delta: &[u8]) -> Vec<u8> {
        let mut out = field(1, 0, &varint(1));
        out.extend(len_field(2, delta));
        out
    }

    fn err(bytes: &[u8]) -> WireError {
        Envelope::decode(bytes).unwrap_err()
    }

    // ----- round trips -----

    #[test]
    fn round_trips_every_message() {
        round_trip(golden_envelope());

        let mut full = golden_delta();
        full.epoch = Epoch::UNASSIGNED;
        full.seq = 0;
        full.full = true;
        full.removed.clear();
        round_trip(Envelope {
            id: 9,
            body: Body::Delta(full),
        });

        round_trip(Envelope {
            id: 2,
            body: Body::Ping(Ping),
        });
        round_trip(Envelope {
            id: 2,
            body: Body::Pong(Pong),
        });
    }

    #[test]
    fn round_trips_every_ack_outcome() {
        let outcomes = [
            AckOutcome::Applied,
            AckOutcome::Duplicate,
            AckOutcome::NeedResync(ResyncReason::DigestMismatch),
            AckOutcome::NeedResync(ResyncReason::SeqGap),
            AckOutcome::NeedResync(ResyncReason::EpochStale),
            AckOutcome::NeedResync(ResyncReason::StateUnknown),
        ];
        for outcome in outcomes {
            round_trip(Envelope {
                id: 4,
                body: Body::DeltaAck(DeltaAck {
                    epoch: Epoch(5),
                    seq: 6,
                    outcome,
                }),
            });
        }
    }

    #[test]
    fn round_trips_component_messages() {
        let d = golden_delta();
        for item in d.upserted.clone() {
            let back = SoftwareItem::try_from(w::SoftwareItem::from(item.clone()));
            assert_eq!(back, Ok(item));
        }
        for key in d.removed.clone() {
            let back = SoftwareKey::try_from(w::SoftwareKey::from(key.clone()));
            assert_eq!(back, Ok(key));
        }
        let os = d.host_os.clone().unwrap();
        assert_eq!(HostOs::try_from(w::HostOs::from(os.clone())), Ok(os));
        let sp = SourcePackage {
            name: "s".to_owned(),
            version: Some(String::new()),
        };
        assert_eq!(
            SourcePackage::try_from(w::SourcePackage::from(sp.clone())),
            Ok(sp)
        );
    }

    #[test]
    fn round_trips_every_package_source() {
        for source in [
            PackageSource::Dpkg,
            PackageSource::Rpm,
            PackageSource::Apk,
            PackageSource::Pacman,
            PackageSource::Brew,
            PackageSource::Other("snap".to_owned()),
        ] {
            let key = SoftwareKey {
                source,
                name: "n".to_owned(),
                arch: None,
                version: "1".to_owned(),
            };
            let back = SoftwareKey::try_from(w::SoftwareKey::from(key.clone()));
            assert_eq!(back, Ok(key));
        }
    }

    #[test]
    fn absent_and_empty_optionals_stay_distinct() {
        let mut d = golden_delta();
        d.upserted[1].arch = None;
        d.upserted[0].vendor = Some(String::new());
        let env = Envelope {
            id: 1,
            body: Body::Delta(d),
        };
        let back = Envelope::decode(&env.clone().encode_to_vec()).unwrap();
        assert_eq!(back, env);
    }

    // ----- golden -----

    #[test]
    fn golden_encoding_is_stable() {
        assert_eq!(golden_envelope().encode_to_vec(), golden_bytes());
    }

    #[test]
    fn golden_bytes_decode_to_the_fixed_delta() {
        assert_eq!(Envelope::decode(&golden_bytes()), Ok(golden_envelope()));
    }

    // ----- malformed input -----

    #[test]
    fn every_truncation_is_rejected() {
        let bytes = golden_bytes();
        for n in 0..bytes.len() {
            assert!(Envelope::decode(&bytes[..n]).is_err(), "prefix {n}");
        }
    }

    #[test]
    fn empty_input_is_rejected() {
        assert_eq!(err(&[]), WireError::ZeroId);
    }

    #[test]
    fn wrong_wire_types_are_rejected() {
        // `id` as length-delimited.
        assert!(matches!(err(&len_field(1, b"x")), WireError::Decode(_)));
        // `body` (delta) as varint.
        let mut b = field(1, 0, &varint(1));
        b.extend(field(2, 0, &varint(1)));
        assert!(matches!(err(&b), WireError::Decode(_)));
        // `state_digest` as varint.
        let mut d = field(1, 0, &varint(1));
        d.extend(field(10, 0, &varint(1)));
        assert!(matches!(
            err(&envelope_with_delta(&d)),
            WireError::Decode(_)
        ));
        // `host_id` as fixed32.
        let d = field(2, 5, &[0; 4]);
        assert!(matches!(
            err(&envelope_with_delta(&d)),
            WireError::Decode(_)
        ));
    }

    #[test]
    fn huge_and_overlong_length_varints_are_rejected() {
        for len in [u64::MAX, 1 << 32, 1 << 31, 0xffff_ffff_ffff] {
            let mut b = field(1, 0, &varint(1));
            b.extend(field(2, 2, &varint(len)));
            assert!(Envelope::decode(&b).is_err(), "len {len}");
        }
        // 11-byte varint and a 10th byte above 1.
        let mut b = field(1, 0, &[0xff; 11]);
        assert!(Envelope::decode(&b).is_err());
        b = field(
            2,
            2,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        );
        assert!(Envelope::decode(&b).is_err());
    }

    #[test]
    fn unknown_enum_values_are_rejected() {
        for value in [999, -1, 6, 98, 100] {
            let mut item = wire_item();
            item.source = value;
            assert_eq!(
                SoftwareItem::try_from(item),
                Err(WireError::UnknownEnum {
                    field: "source",
                    value
                })
            );
        }
        for (outcome, reason, field) in [(77, 0, "outcome"), (1, 77, "resync_reason")] {
            let ack = w::DeltaAck {
                epoch: 1,
                seq: 1,
                outcome,
                resync_reason: reason,
            };
            assert!(matches!(
                DeltaAck::try_from(ack),
                Err(WireError::UnknownEnum { field: f, .. }) if f == field
            ));
        }
    }

    #[test]
    fn unspecified_enums_are_rejected() {
        let mut item = wire_item();
        item.source = 0;
        assert_eq!(
            SoftwareItem::try_from(item),
            Err(WireError::UnspecifiedEnum("source"))
        );
        let mut key = w::SoftwareKey::from(golden_delta().removed.remove(0));
        key.source = 0;
        assert_eq!(
            SoftwareKey::try_from(key),
            Err(WireError::UnspecifiedEnum("source"))
        );
        let ack = w::DeltaAck {
            epoch: 1,
            seq: 1,
            outcome: 0,
            resync_reason: 0,
        };
        assert_eq!(
            DeltaAck::try_from(ack),
            Err(WireError::UnspecifiedEnum("outcome"))
        );
    }

    #[test]
    fn other_source_rules() {
        let mut item = wire_item();
        item.source = i32::from(w::PackageSource::Other);
        item.other_source = String::new();
        assert_eq!(
            SoftwareItem::try_from(item),
            Err(WireError::OtherSourceEmpty)
        );

        let mut item = wire_item();
        item.other_source = "snap".to_owned();
        assert_eq!(
            SoftwareItem::try_from(item),
            Err(WireError::StraySourceName)
        );

        let mut key = w::SoftwareKey::from(golden_delta().removed.remove(0));
        key.other_source = "x".to_owned();
        assert_eq!(SoftwareKey::try_from(key), Err(WireError::StraySourceName));
    }

    #[test]
    fn resync_reason_iff_need_resync() {
        let ack = |outcome: w::AckOutcome, reason: w::ResyncReason| w::DeltaAck {
            epoch: 1,
            seq: 1,
            outcome: outcome.into(),
            resync_reason: reason.into(),
        };
        assert_eq!(
            DeltaAck::try_from(ack(w::AckOutcome::NeedResync, w::ResyncReason::Unspecified)),
            Err(WireError::ResyncReasonMissing)
        );
        for outcome in [w::AckOutcome::Applied, w::AckOutcome::Duplicate] {
            assert_eq!(
                DeltaAck::try_from(ack(outcome, w::ResyncReason::SeqGap)),
                Err(WireError::ResyncReasonUnexpected)
            );
        }
    }

    #[test]
    fn digest_must_be_exactly_32_bytes() {
        for len in [0, 31, 33, 64] {
            let mut d = valid_wire_delta();
            d.state_digest = vec![0; len];
            assert_eq!(
                SoftwareDelta::try_from(d),
                Err(WireError::BadDigestLength(len))
            );
        }
        assert!(SoftwareDelta::try_from(valid_wire_delta()).is_ok());
    }

    #[test]
    fn schema_version_is_range_checked_then_validated() {
        for v in [65_536, u32::MAX] {
            let mut d = valid_wire_delta();
            d.schema_version = v;
            assert_eq!(
                SoftwareDelta::try_from(d),
                Err(WireError::SchemaVersionOutOfRange(v))
            );
        }
        let mut d = valid_wire_delta();
        d.schema_version = 65_535;
        assert_eq!(
            SoftwareDelta::try_from(d),
            Err(WireError::Invalid(ValidationError::UnsupportedSchema(
                65_535
            )))
        );
    }

    #[test]
    fn conversion_ends_in_validate() {
        let mut d = valid_wire_delta();
        d.host_id = String::new();
        assert_eq!(
            SoftwareDelta::try_from(d),
            Err(WireError::Invalid(ValidationError::EmptyField("host_id")))
        );

        let mut d = valid_wire_delta();
        d.upserted[0].name = "x".repeat(crate::inventory::MAX_STRING_LEN + 1);
        assert_eq!(
            SoftwareDelta::try_from(d),
            Err(WireError::Invalid(ValidationError::StringTooLong("name")))
        );

        let mut d = valid_wire_delta();
        d.upserted.push(d.upserted[0].clone());
        assert_eq!(
            SoftwareDelta::try_from(d),
            Err(WireError::Invalid(ValidationError::DuplicateKey))
        );

        let mut d = valid_wire_delta();
        d.upserted[0].name = "openssl\0evil".to_owned();
        assert_eq!(
            SoftwareDelta::try_from(d),
            Err(WireError::Invalid(ValidationError::NulByte("name")))
        );

        let mut d = valid_wire_delta();
        d.full = true;
        d.host_os = None;
        d.epoch = 0;
        d.seq = 0;
        d.removed.clear();
        assert_eq!(
            SoftwareDelta::try_from(d),
            Err(WireError::Invalid(ValidationError::MissingHostOs))
        );
    }

    #[test]
    fn envelope_id_and_body_rules() {
        let ping = |id| {
            Envelope::decode(
                &Envelope {
                    id,
                    body: Body::Ping(Ping),
                }
                .encode_to_vec(),
            )
        };
        assert_eq!(ping(0), Err(WireError::ZeroId));
        assert!(ping(1).is_ok());

        // Nonzero id, no body.
        assert_eq!(
            err(&field(1, 0, &varint(5))),
            WireError::UnsupportedMessage { id: 5 }
        );
        // Nonzero id, a body field from a "newer peer" (field 40).
        let mut b = field(1, 0, &varint(6));
        b.extend(len_field(40, b"future"));
        assert_eq!(err(&b), WireError::UnsupportedMessage { id: 6 });
    }

    #[test]
    fn error_display_does_not_echo_payload() {
        let mut d = valid_wire_delta();
        d.host_id = String::new();
        d.upserted[0].name = "SECRET-TOKEN".to_owned();
        d.upserted[0].version = String::new();
        let e = SoftwareDelta::try_from(d).unwrap_err();
        assert!(!e.to_string().contains("SECRET"));
    }

    #[test]
    fn byte_flip_sweep_never_panics() {
        let bytes = golden_bytes();
        for i in 0..bytes.len() {
            for mask in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff] {
                let mut b = bytes.clone();
                b[i] ^= mask;
                let _ = Envelope::decode(&b);
            }
        }
    }

    #[test]
    fn oversized_envelope_is_rejected_by_size() {
        let b = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        assert_eq!(err(&b), WireError::EnvelopeTooLarge(MAX_ENVELOPE_BYTES + 1));
    }

    #[test]
    fn a_full_snapshot_at_the_item_cap_fits_the_envelope_cap() {
        let mut d = golden_delta();
        d.epoch = Epoch::UNASSIGNED;
        d.seq = 0;
        d.full = true;
        d.removed.clear();
        d.upserted = (0..MAX_ITEMS)
            .map(|i| SoftwareItem {
                name: format!("package-{i}"),
                version: "1.0".to_owned(),
                arch: Some("amd64".to_owned()),
                source: PackageSource::Dpkg,
                source_package: None,
                vendor: None,
                purl: None,
            })
            .collect();
        let env = Envelope {
            id: 1,
            body: Body::Delta(d),
        };
        let bytes = env.clone().encode_to_vec();
        assert!(bytes.len() <= MAX_ENVELOPE_BYTES);
        assert_eq!(Envelope::decode(&bytes), Ok(env));
    }

    /// A full-snapshot envelope carrying `items`.
    fn snapshot_envelope(items: Vec<SoftwareItem>) -> Envelope {
        let mut d = golden_delta();
        d.epoch = Epoch::UNASSIGNED;
        d.seq = 0;
        d.full = true;
        d.removed.clear();
        d.upserted = items;
        Envelope {
            id: 1,
            body: Body::Delta(d),
        }
    }

    /// `prefix` padded with `x` to exactly `len` bytes (truncated if shorter).
    fn padded(prefix: &str, len: usize) -> String {
        let mut s = prefix.to_owned();
        s.truncate(len);
        s.extend(std::iter::repeat_n('x', len - s.len()));
        s
    }

    fn assert_fits_and_round_trips(env: Envelope) -> usize {
        let Body::Delta(delta) = &env.body else {
            panic!("expected a delta");
        };
        assert_eq!(delta.validate(), Ok(()));
        let bytes = env.clone().encode_to_vec();
        assert!(
            bytes.len() <= MAX_ENVELOPE_BYTES,
            "encoded {} bytes exceeds MAX_ENVELOPE_BYTES {MAX_ENVELOPE_BYTES}",
            bytes.len()
        );
        assert_eq!(Envelope::decode(&bytes), Ok(env));
        bytes.len()
    }

    #[test]
    fn a_maximal_cost_snapshot_fits_the_envelope_cap() {
        use crate::inventory::{MAX_DELTA_COST, MAX_STRING_LEN, PER_ITEM_OVERHEAD};

        // Seven strings per item, every optional populated.
        const STRINGS: usize = 7;
        let item = |name: String, lens: [usize; STRINGS - 1]| SoftwareItem {
            version: padded("v", lens[0]),
            arch: Some(padded("a", lens[1])),
            source: PackageSource::Dpkg,
            source_package: Some(SourcePackage {
                name: padded("s", lens[2]),
                version: Some(padded("sv", lens[3])),
            }),
            vendor: Some(padded("d", lens[4])),
            purl: Some(padded("p", lens[5])),
            name,
        };

        let full_cost = PER_ITEM_OVERHEAD + STRINGS * MAX_STRING_LEN;
        let count = MAX_DELTA_COST / full_cost;
        let mut items: Vec<SoftwareItem> = (0..count)
            .map(|i| {
                item(
                    padded(&format!("n{i}-"), MAX_STRING_LEN),
                    [MAX_STRING_LEN; 6],
                )
            })
            .collect();

        // One more item soaks up the remainder so the total cost is exactly
        // MAX_DELTA_COST. Strings fill in order (name, version, arch, ...).
        let mut budget = MAX_DELTA_COST - count * full_cost - PER_ITEM_OVERHEAD;
        let mut take = || {
            let n = budget.min(MAX_STRING_LEN);
            budget -= n;
            n
        };
        let name_len = take();
        let lens = [take(), take(), take(), take(), take(), take()];
        assert_eq!(budget, 0, "remainder must fit in one item");
        items.push(item(padded("last-", name_len), lens));

        let env = snapshot_envelope(items.clone());
        let len = assert_fits_and_round_trips(env);
        assert!(len > MAX_DELTA_COST / 2, "sanity: {len} bytes");

        // The snapshot is exactly at the cost cap: one more minimal item is
        // rejected.
        items.push(item("z".to_owned(), [1, 0, 1, 0, 0, 0]));
        let Body::Delta(over) = snapshot_envelope(items).body else {
            unreachable!("snapshot_envelope builds a delta");
        };
        assert_eq!(over.validate(), Err(ValidationError::DeltaTooLarge));
    }

    #[test]
    fn a_minimum_string_snapshot_at_the_item_cap_fits_the_envelope_cap() {
        // Shortest valid strings: required fields one character (names are
        // the decimal index, for unique keys), optionals present but empty.
        let items = (0..MAX_ITEMS)
            .map(|i| SoftwareItem {
                name: i.to_string(),
                version: "1".to_owned(),
                arch: Some(String::new()),
                source: PackageSource::Dpkg,
                source_package: Some(SourcePackage {
                    name: "s".to_owned(),
                    version: Some(String::new()),
                }),
                vendor: Some(String::new()),
                purl: Some(String::new()),
            })
            .collect();
        assert_fits_and_round_trips(snapshot_envelope(items));
    }

    // ----- unknown fields -----

    #[test]
    fn unknown_fields_are_tolerated_and_do_not_change_the_digest() {
        let d = golden_delta();
        let digest = state_digest(&d.upserted).unwrap();

        // Rebuild the golden bytes with unknown fields spliced into the
        // envelope, the delta, an item, and a key.
        let unknown = |tail: &mut Vec<u8>| {
            tail.extend(field(15, 0, &varint(12_345)));
            tail.extend(len_field(99, b"future"));
            tail.extend(field(1000, 5, &[1, 2, 3, 4]));
        };
        let mut item = Vec::new();
        item.extend(len_field(1, b"openssl"));
        item.extend(len_field(2, b"3.0.11-1"));
        item.extend(len_field(3, b"amd64"));
        item.extend(field(4, 0, &varint(1)));
        unknown(&mut item);
        let mut key = Vec::new();
        key.extend(field(1, 0, &varint(2)));
        key.extend(len_field(3, b"kernel"));
        key.extend(len_field(5, b"6.1.1"));
        unknown(&mut key);
        let mut delta = Vec::new();
        delta.extend(field(1, 0, &varint(1)));
        delta.extend(len_field(2, b"host-1"));
        delta.extend(field(3, 0, &varint(3)));
        delta.extend(field(4, 0, &varint(7)));
        delta.extend(len_field(8, &item));
        delta.extend(len_field(9, &key));
        delta.extend(len_field(10, &d.state_digest));
        unknown(&mut delta);
        let mut bytes = envelope_with_delta(&delta);
        unknown(&mut bytes);

        let Ok(Envelope {
            body: Body::Delta(got),
            ..
        }) = Envelope::decode(&bytes)
        else {
            panic!("unknown fields must be tolerated");
        };
        assert_eq!(got.upserted.len(), 1);
        assert_eq!(got.upserted[0].name, "openssl");

        // The digest of what was received equals the digest of the same
        // items sent without unknown fields.
        let clean = SoftwareItem {
            name: "openssl".to_owned(),
            version: "3.0.11-1".to_owned(),
            arch: Some("amd64".to_owned()),
            source: PackageSource::Dpkg,
            source_package: None,
            vendor: None,
            purl: None,
        };
        assert_eq!(
            state_digest(&got.upserted).unwrap(),
            state_digest(&[clean]).unwrap()
        );
        // And unknown fields added to the golden message change nothing.
        assert_eq!(state_digest(&d.upserted).unwrap(), digest);
    }

    #[test]
    fn unknown_fields_on_golden_bytes_leave_the_message_unchanged() {
        let mut bytes = golden_bytes();
        bytes.extend(len_field(77, b"x"));
        assert_eq!(Envelope::decode(&bytes), Ok(golden_envelope()));
    }

    // ----- pre-scan -----

    fn counts_of(bytes: &[u8]) -> EntryCounts {
        prescan(bytes).unwrap()
    }

    #[test]
    fn prescan_counts_golden_entries() {
        assert_eq!(
            counts_of(&golden_bytes()),
            EntryCounts {
                upserted: 2,
                removed: 1
            }
        );
    }

    #[test]
    fn prescan_sums_repeated_delta_occurrences() {
        let entry = len_field(8, b"");
        let one = envelope_with_delta(&entry);
        let mut two = one.clone();
        two.extend(len_field(2, &entry));
        assert_eq!(counts_of(&two).upserted, 2);
        // prost merges both occurrences into one list of two entries.
        let decoded = w::Envelope::decode(two.as_slice()).unwrap();
        let Some(w::envelope::Body::Delta(d)) = decoded.body else {
            panic!()
        };
        assert_eq!(d.upserted.len(), 2);
    }

    #[test]
    fn prescan_rejects_too_many_empty_entries_before_decoding() {
        let mut delta = Vec::new();
        for _ in 0..=MAX_ITEMS {
            delta.extend(len_field(8, b""));
        }
        assert_eq!(
            err(&envelope_with_delta(&delta)),
            WireError::Invalid(ValidationError::TooManyItems("upserted"))
        );

        let mut delta = Vec::new();
        for _ in 0..=MAX_ITEMS {
            delta.extend(len_field(9, b""));
        }
        assert_eq!(
            err(&envelope_with_delta(&delta)),
            WireError::Invalid(ValidationError::TooManyItems("removed"))
        );
    }

    #[test]
    fn prescan_accepts_the_cap_and_rejects_malformed_framing() {
        let mut delta = Vec::new();
        for _ in 0..MAX_ITEMS {
            delta.extend(len_field(8, b""));
        }
        assert_eq!(counts_of(&envelope_with_delta(&delta)).upserted, MAX_ITEMS);

        for bad in [
            vec![0x80],          // truncated varint
            vec![0x00],          // field number 0
            vec![0x0b],          // start-group wire type
            vec![0x12, 0x05, 1], // length past the end
            vec![0x0d, 1, 2],    // truncated fixed32
            vec![0x09, 1, 2, 3], // truncated fixed64
            vec![0x17],          // wire type 7
            [0xff; 11].to_vec(), // overlong varint
        ] {
            assert_eq!(prescan(&bad), Err(WireError::Malformed), "{bad:?}");
        }
    }

    /// Property: whenever prost decodes an input, the pre-scan accepts it and
    /// its counts are at least the decoded list lengths. Checked over a
    /// byte-flip sweep of the golden message, of a delta with many entries,
    /// and of a message with a repeated `delta` field.
    #[test]
    fn prescan_never_undercounts_prost() {
        let mut many = golden_delta();
        many.upserted = (0..6)
            .map(|i| SoftwareItem {
                name: format!("p{i}"),
                version: "1".to_owned(),
                arch: None,
                source: PackageSource::Apk,
                source_package: None,
                vendor: None,
                purl: None,
            })
            .collect();
        many.removed = (0..4)
            .map(|i| SoftwareKey {
                source: PackageSource::Brew,
                name: format!("r{i}"),
                arch: None,
                version: "1".to_owned(),
            })
            .collect();
        let mut merged = golden_bytes();
        merged.extend(len_field(2, &len_field(8, b"")));
        let corpus = [
            golden_bytes(),
            Envelope {
                id: 3,
                body: Body::Delta(many),
            }
            .encode_to_vec(),
            merged,
        ];

        let mut decoded_ok = 0usize;
        for seed in &corpus {
            for i in 0..seed.len() {
                for mask in [0x01, 0x02, 0x04, 0x07, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff] {
                    let mut b = seed.clone();
                    b[i] ^= mask;
                    let Ok(env) = w::Envelope::decode(b.as_slice()) else {
                        continue;
                    };
                    decoded_ok += 1;
                    let counts = prescan(&b)
                        .unwrap_or_else(|e| panic!("prescan rejected decodable input: {e}"));
                    if let Some(w::envelope::Body::Delta(d)) = env.body {
                        assert!(counts.upserted >= d.upserted.len(), "undercount at {i}");
                        assert!(counts.removed >= d.removed.len(), "undercount at {i}");
                    }
                }
            }
        }
        assert!(decoded_ok > 100, "sweep should exercise successful decodes");
    }
}
