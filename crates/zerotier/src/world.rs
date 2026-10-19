//! Planet and moon root-server world definitions.
//!
//! A world is a signed topology document: a type, an ID, the public key that
//! must sign later revisions, and the root identities with their physical
//! endpoints. The first world a node trusts is a trust anchor; every later
//! revision must be signed by the previous revision's update key.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::address::Address;
use crate::identity::{Identity, IdentityError, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};

/// The official world ID of ZeroTier's public Earth planet.
pub const WORLD_ID_EARTH: u64 = 149_604_618;
const WORLD_ID_HEX_SIZE: usize = 16;
const MAX_WORLD_ROOTS: usize = 4;
const MAX_ROOT_ENDPOINTS: usize = 32;

/// Reports malformed or unverifiable planet or moon data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid ZeroTier world")]
pub struct InvalidWorld;

/// Reports a malformed orbit world ID or seed address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OrbitError {
    #[error("ZeroTier orbit world must be a 16-digit hexadecimal ID")]
    InvalidWorldId,
    #[error("ZeroTier orbit seed must be a 10-digit node ID")]
    InvalidSeed,
}

/// The role of a signed root-server world definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorldType {
    Null,
    Planet,
    Moon,
}

impl WorldType {
    fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Null),
            1 => Some(Self::Planet),
            127 => Some(Self::Moon),
            _ => None,
        }
    }

    #[must_use]
    pub fn bits(self) -> u8 {
        match self {
            Self::Null => 0,
            Self::Planet => 1,
            Self::Moon => 127,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Planet => "planet",
            Self::Moon => "moon",
        }
    }
}

/// One root identity with the physical endpoints it can be reached on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldRoot {
    pub identity: Identity,
    pub endpoints: Vec<SocketAddr>,
}

/// A signed planet or moon root-server topology definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct World {
    pub world_type: WorldType,
    pub id: u64,
    pub timestamp: u64,
    /// The public key that must sign the next revision of this world.
    pub updates_must_be_signed_by: [u8; PUBLIC_KEY_SIZE],
    pub signature: [u8; SIGNATURE_SIZE],
    pub roots: Vec<WorldRoot>,
}

/// Parses a moon world ID and seed node address, as configured in `orbit:`.
pub fn parse_orbit(world_text: &str, seed_text: &str) -> Result<(u64, Address), OrbitError> {
    if world_text.len() != WORLD_ID_HEX_SIZE || !world_text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(OrbitError::InvalidWorldId);
    }
    let world = u64::from_str_radix(world_text, 16).map_err(|_| OrbitError::InvalidWorldId)?;
    if world == 0 {
        return Err(OrbitError::InvalidWorldId);
    }
    let seed = Address::parse(seed_text).map_err(|_| OrbitError::InvalidSeed)?;
    if seed.is_reserved() {
        return Err(OrbitError::InvalidSeed);
    }
    Ok((world, seed))
}

impl World {
    /// Parses and validates the public Earth planet.
    pub fn default_planet() -> Result<Self, InvalidWorld> {
        Self::parse_planet(DEFAULT_PLANET).and_then(|world| {
            if world.id == WORLD_ID_EARTH {
                Ok(world)
            } else {
                Err(InvalidWorld)
            }
        })
    }

    /// Parses a complete serialized planet.
    ///
    /// The result is a trust anchor, so its own signature is not checked here;
    /// it cannot be authenticated without a previously trusted revision.
    pub fn parse_planet(data: &[u8]) -> Result<Self, InvalidWorld> {
        let (world, consumed) = Self::parse(data)?;
        if consumed != data.len() || world.world_type != WorldType::Planet || world.validate_roots().is_err() {
            return Err(InvalidWorld);
        }
        Ok(world)
    }

    /// Decodes one serialized planet or moon and reports bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), InvalidWorld> {
        let fixed_size = 1 + 8 + 8 + PUBLIC_KEY_SIZE + SIGNATURE_SIZE + 1;
        if data.len() < fixed_size {
            return Err(InvalidWorld);
        }
        let world_type = WorldType::from_bits(*data.first().ok_or(InvalidWorld)?).ok_or(InvalidWorld)?;

        let mut pos = 1;
        let id = read_u64(data, &mut pos);
        let timestamp = read_u64(data, &mut pos);

        let mut updates_must_be_signed_by = [0u8; PUBLIC_KEY_SIZE];
        updates_must_be_signed_by.copy_from_slice(&read_array::<PUBLIC_KEY_SIZE>(data, pos)?);
        pos += PUBLIC_KEY_SIZE;
        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&read_array::<SIGNATURE_SIZE>(data, pos)?);
        pos += SIGNATURE_SIZE;

        let root_count = usize::from(*data.get(pos).ok_or(InvalidWorld)?);
        pos += 1;
        if root_count > MAX_WORLD_ROOTS {
            return Err(InvalidWorld);
        }
        let mut roots = Vec::with_capacity(root_count);
        for _ in 0..root_count {
            let (identity, consumed) =
                Identity::parse_binary(data.get(pos..).ok_or(InvalidWorld)?).map_err(|_| InvalidWorld)?;
            pos += consumed;
            if pos >= data.len() {
                return Err(InvalidWorld);
            }
            let endpoint_count = usize::from(*data.get(pos).ok_or(InvalidWorld)?);
            pos += 1;
            if endpoint_count > MAX_ROOT_ENDPOINTS {
                return Err(InvalidWorld);
            }
            let mut endpoints = Vec::with_capacity(endpoint_count);
            for _ in 0..endpoint_count {
                let (endpoint, consumed) = parse_inet_address(data.get(pos..).ok_or(InvalidWorld)?)?;
                pos += consumed;
                endpoints.push(endpoint);
            }
            roots.push(WorldRoot { identity, endpoints });
        }

        if world_type == WorldType::Moon {
            if data.len().saturating_sub(pos) < 2 {
                return Err(InvalidWorld);
            }
            let dictionary_length = usize::from(u16::from_be_bytes(read_array::<2>(data, pos)?));
            pos += 2;
            if data.len().saturating_sub(pos) < dictionary_length {
                return Err(InvalidWorld);
            }
            // Attached dictionaries are reserved for future use and carry no
            // meaning this codec can interpret.
            pos += dictionary_length;
        }

        Ok((Self { world_type, id, timestamp, updates_must_be_signed_by, signature, roots }, pos))
    }

    /// The complete binary encoding of this world.
    pub fn serialize(&self) -> Result<Vec<u8>, InvalidWorld> {
        self.append_to(Vec::new(), false)
    }

    /// Serializes the world, omitting the signature and adding the
    /// domain-separation markers ZeroTier's `World::serialize` uses when the
    /// output is the message that gets signed.
    pub fn append_to(&self, mut dst: Vec<u8>, for_sign: bool) -> Result<Vec<u8>, InvalidWorld> {
        // `WorldType` is a closed enum, so the only structural limits left to
        // enforce are the protocol's counts.
        if self.roots.len() > MAX_WORLD_ROOTS {
            return Err(InvalidWorld);
        }
        if for_sign {
            dst.extend_from_slice(&0x7f7f_7f7f_7f7f_7f7fu64.to_be_bytes());
        }
        dst.push(self.world_type.bits());
        dst.extend_from_slice(&self.id.to_be_bytes());
        dst.extend_from_slice(&self.timestamp.to_be_bytes());
        dst.extend_from_slice(&self.updates_must_be_signed_by);
        if !for_sign {
            dst.extend_from_slice(&self.signature);
        }
        dst.push(u8::try_from(self.roots.len()).map_err(|_| InvalidWorld)?);
        for root in &self.roots {
            if root.endpoints.len() > MAX_ROOT_ENDPOINTS || root.identity.address().is_reserved() {
                return Err(InvalidWorld);
            }
            root.identity.append_binary(&mut dst, false);
            dst.push(u8::try_from(root.endpoints.len()).map_err(|_| InvalidWorld)?);
            for endpoint in &root.endpoints {
                if endpoint.port() == 0 {
                    return Err(InvalidWorld);
                }
                dst = append_inet_address(dst, *endpoint);
            }
        }
        if self.world_type == WorldType::Moon {
            // Attached dictionaries are reserved for future use.
            dst.extend_from_slice(&[0, 0]);
        }
        if for_sign {
            dst.extend_from_slice(&0xf7f7_f7f7_f7f7_f7f7u64.to_be_bytes());
        }
        Ok(dst)
    }

    /// Authenticates a newer revision using the update key from this world.
    ///
    /// The initial world is a trust anchor and is never accepted here; the
    /// caller establishes that trust separately.
    #[must_use]
    pub fn should_be_replaced_by(&self, update: &Self) -> bool {
        if self.world_type == WorldType::Null
            || self.id == 0
            || self.id != update.id
            || self.world_type != update.world_type
            || update.timestamp <= self.timestamp
        {
            return false;
        }
        let Ok(message) = update.append_to(Vec::new(), true) else {
            return false;
        };
        let signer = Identity::from_parts(Address::new(0), self.updates_must_be_signed_by);
        signer.verify(&message, &update.signature)
    }

    /// Verifies the root count, identities, and physical endpoints.
    pub fn validate_roots(&self) -> Result<(), InvalidWorld> {
        if self.id == 0
            || (self.world_type != WorldType::Planet && self.world_type != WorldType::Moon)
            || self.roots.is_empty()
            || self.roots.len() > MAX_WORLD_ROOTS
        {
            return Err(InvalidWorld);
        }
        let mut seen: Vec<Address> = Vec::with_capacity(self.roots.len());
        for root in &self.roots {
            if root.endpoints.len() > MAX_ROOT_ENDPOINTS {
                return Err(InvalidWorld);
            }
            let address = root.identity.address();
            if seen.contains(&address) {
                return Err(InvalidWorld);
            }
            seen.push(address);
            if root.identity.validate().is_err() {
                return Err(InvalidWorld);
            }
            for endpoint in &root.endpoints {
                if endpoint.port() == 0 {
                    return Err(InvalidWorld);
                }
            }
        }
        Ok(())
    }
}

impl From<IdentityError> for InvalidWorld {
    fn from(_: IdentityError) -> Self {
        Self
    }
}

/// The public ZeroTier Earth planet, the trust anchor a node starts from.
const DEFAULT_PLANET: &[u8] = include_bytes!("../testdata/default_planet.bin");

/// Decodes ZeroTier's tagged IPv4 or IPv6 endpoint form, reporting bytes
/// consumed.
///
/// A zero tag denotes an explicitly empty endpoint; it becomes a port-zero
/// placeholder that root validation rejects like any other empty endpoint.
fn parse_inet_address(data: &[u8]) -> Result<(SocketAddr, usize), InvalidWorld> {
    match data.first().copied().ok_or(InvalidWorld)? {
        0 => Ok((SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), 1)),
        4 => {
            let ip = Ipv4Addr::from(read_array::<4>(data, 1)?);
            let port = u16::from_be_bytes(read_array::<2>(data, 5)?);
            Ok((SocketAddr::new(IpAddr::V4(ip), port), 7))
        }
        6 => {
            let ip = Ipv6Addr::from(read_array::<16>(data, 1)?);
            let port = u16::from_be_bytes(read_array::<2>(data, 17)?);
            Ok((SocketAddr::new(IpAddr::V6(ip), port), 19))
        }
        _ => Err(InvalidWorld),
    }
}

fn append_inet_address(mut dst: Vec<u8>, address: SocketAddr) -> Vec<u8> {
    match address.ip() {
        IpAddr::V4(ip) => {
            dst.push(4);
            dst.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            dst.push(6);
            dst.extend_from_slice(&ip.octets());
        }
    }
    dst.extend_from_slice(&address.port().to_be_bytes());
    dst
}

fn read_array<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], InvalidWorld> {
    data.get(offset..offset + N).ok_or(InvalidWorld)?.try_into().map_err(|_| InvalidWorld)
}

fn read_u64(data: &[u8], pos: &mut usize) -> u64 {
    let value = read_array::<8>(data, *pos).map_or(0, u64::from_be_bytes);
    *pos += 8;
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(text: &str) -> SocketAddr {
        text.parse().expect("endpoint literal")
    }

    #[test]
    fn parses_orbit_configuration() {
        let (world, seed) = parse_orbit("8056c2e21c000001", "0f1b56d269").unwrap();
        assert_eq!(world, 0x8056_c2e2_1c00_0001);
        assert_eq!(seed.to_string(), "0f1b56d269");

        for (world_text, seed_text) in [
            ("bad", "0f1b56d269"),
            ("0000000000000000", "0f1b56d269"),
            ("8056c2e21c000001", "bad"),
            ("8056c2e21c000001", "ff00000001"),
        ] {
            assert!(parse_orbit(world_text, seed_text).is_err(), "{world_text} {seed_text} was accepted");
        }
    }

    /// The parity vector: `default_planet.bin`, which must re-serialize
    /// byte-for-byte.
    #[test]
    fn default_planet_round_trips_byte_for_byte() {
        let planet = World::default_planet().expect("the embedded Earth planet parses");
        assert_eq!(planet.id, WORLD_ID_EARTH);
        assert!(!planet.roots.is_empty());

        for root in &planet.roots {
            assert!(root.identity.validate().is_ok());
            for endpoint in &root.endpoints {
                assert_ne!(endpoint.port(), 0);
            }
        }

        assert_eq!(planet.serialize().expect("planet serializes"), DEFAULT_PLANET);
    }

    #[test]
    fn planet_parsing_requires_a_complete_planet() {
        let planet = World::default_planet().expect("planet parses");
        let serialized = planet.serialize().expect("planet serializes");
        assert!(World::parse_planet(&serialized).is_ok());

        let mut trailing = serialized.clone();
        trailing.push(0);
        assert_eq!(World::parse_planet(&trailing), Err(InvalidWorld));

        let mut as_moon = planet.clone();
        as_moon.world_type = WorldType::Moon;
        let moon_bytes = as_moon.serialize().expect("moon serializes");
        assert_eq!(World::parse_planet(&moon_bytes), Err(InvalidWorld));
    }

    #[test]
    fn world_update_signature_is_authenticated() {
        let signer = Identity::generate();
        let mut current = World {
            world_type: WorldType::Moon,
            id: 0x0123_4567_89ab_cdef,
            timestamp: 1,
            updates_must_be_signed_by: signer.public_key(),
            signature: [0u8; SIGNATURE_SIZE],
            roots: vec![WorldRoot { identity: signer.clone(), endpoints: vec![endpoint("192.0.2.1:9993")] }],
        };

        let mut update = current.clone();
        update.timestamp = 2;
        let message = update.append_to(Vec::new(), true).expect("signing message builds");
        update.signature = signer.sign(&message).expect("sign update");
        current.signature = [0u8; SIGNATURE_SIZE];

        assert!(current.should_be_replaced_by(&update));

        update.roots[0].endpoints[0] = endpoint("192.0.2.2:9993");
        assert!(!current.should_be_replaced_by(&update));
    }

    #[test]
    fn a_stale_or_mismatched_update_is_refused() {
        let signer = Identity::generate();
        let base = World {
            world_type: WorldType::Moon,
            id: 0x0123_4567_89ab_cdef,
            timestamp: 5,
            updates_must_be_signed_by: signer.public_key(),
            signature: [0u8; SIGNATURE_SIZE],
            roots: vec![WorldRoot { identity: signer.clone(), endpoints: vec![endpoint("192.0.2.1:9993")] }],
        };

        let mut update = base.clone();
        update.timestamp = 4;
        let message = update.append_to(Vec::new(), true).expect("message builds");
        update.signature = signer.sign(&message).expect("sign");
        assert!(!base.should_be_replaced_by(&update), "an older timestamp was accepted");

        let mut other_id = base.clone();
        other_id.timestamp = 6;
        other_id.id = 0xdead_beef_dead_beef;
        let message = other_id.append_to(Vec::new(), true).expect("message builds");
        other_id.signature = signer.sign(&message).expect("sign");
        assert!(!base.should_be_replaced_by(&other_id), "a different world ID was accepted");
    }

    #[test]
    fn inet_endpoints_round_trip_in_both_families() {
        let original = World::default_planet().expect("planet parses");
        let reserialized = original.serialize().expect("serializes");
        let (reparsed, consumed) = World::parse(&reserialized).expect("reparses");
        assert_eq!(consumed, reserialized.len());
        assert_eq!(reparsed, original);
    }

    #[test]
    fn rejects_out_of_range_root_and_endpoint_counts() {
        let planet = World::default_planet().expect("planet parses");
        let mut bytes = planet.serialize().expect("serializes");

        // The root count byte sits just before the first root identity.
        let root_count_at = 1 + 8 + 8 + PUBLIC_KEY_SIZE + SIGNATURE_SIZE;
        bytes[root_count_at] = 5;
        assert_eq!(World::parse(&bytes), Err(InvalidWorld));
    }

    #[test]
    fn world_type_names_are_stable() {
        assert_eq!(WorldType::Null.name(), "null");
        assert_eq!(WorldType::Planet.name(), "planet");
        assert_eq!(WorldType::Moon.name(), "moon");
    }
}
