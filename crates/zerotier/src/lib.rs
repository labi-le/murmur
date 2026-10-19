//! The ZeroTier protocol implementation behind murmur's ZeroTier outbound.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::pedantic,
        clippy::nursery
    )
)]

pub mod address;
pub mod bonding;
pub mod capability;
pub mod dictionary;
pub mod frame;
pub mod identity;
pub mod mac;
pub mod managed_ip;
pub mod membership;
pub mod network_config;
pub mod node;
pub mod ownership;
pub mod packet;
pub mod revocation;
pub mod rules;
pub mod tag;
pub mod wire;
pub mod world;
pub mod ztcrypto;

pub use address::{Address, AddressError};
pub use bonding::{
    default_bonding_options, normalize_bonding_options, BondingError, BondingLink, BondingLinkMode,
    BondingLinkSelectMethod, BondingOptions, BondingOptionsInput, BondingPolicy, BondingQuality,
};
pub use frame::{ExtendedFrame, Frame, FrameDestination, FrameError, MulticastGroup};
pub use identity::{Identity, IdentityError};
pub use mac::Mac;
pub use managed_ip::{address_from_rfc4193, address_from_six_plane, rfc4193_address, six_plane_address};
pub use node::{
    BridgeRoute, ConfigAssembly, FileStore, MemoryStore, Network, NetworkAuthenticationInfo, NetworkStatus, Node,
    NodeError, NodeHost, PathKey, Peer, PeerPath, PeerPathConfig, PeerRole, PeerRoute, PeerStatus,
    PendingOutboundFrame, PendingRequest, PhysicalPathConfig, StateStore,
};
pub use rules::{parse_network_rules, FrameRuleContext, FrameRuleDecision, NetworkRule, RuleResult};
