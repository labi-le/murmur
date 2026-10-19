//! Hand-written `prost::Message` mirrors of the protobuf messages that cross the host↔guest ABI
//! (see `agent://EasyTier.ProtoAndConfigMap` §1).
//!
//! No `.proto` IDL is vendored (only generated output exists), so there is nothing for
//! `prost-build` to compile against; the field tags below were extracted directly from the
//! `protobuf:"...,N,..."` struct tags in the generated bindings at commit
//! `63519db2b5f2a6a1b9b7f20905f036dab54eb829` (matching [`artifact::COMMIT`]), not guessed from
//! field order. Only the messages actually reachable from murmur's `ListPeer`, `ListRoute` and
//! `ShowNodeInfo` calls are mirrored; the ~70-field network-config and
//! instance-config-patch surfaces are out of scope here.

pub mod common {
    #[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
    pub struct Uuid {
        #[prost(uint32, tag = "1")]
        pub part1: u32,
        #[prost(uint32, tag = "2")]
        pub part2: u32,
        #[prost(uint32, tag = "3")]
        pub part3: u32,
        #[prost(uint32, tag = "4")]
        pub part4: u32,
    }

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
    pub struct Ipv4Addr {
        #[prost(uint32, tag = "1")]
        pub addr: u32,
    }

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
    pub struct Ipv6Addr {
        #[prost(uint32, tag = "1")]
        pub part1: u32,
        #[prost(uint32, tag = "2")]
        pub part2: u32,
        #[prost(uint32, tag = "3")]
        pub part3: u32,
        #[prost(uint32, tag = "4")]
        pub part4: u32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct Ipv4Inet {
        #[prost(message, optional, tag = "1")]
        pub address: Option<Ipv4Addr>,
        #[prost(uint32, tag = "2")]
        pub network_length: u32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct Ipv6Inet {
        #[prost(message, optional, tag = "1")]
        pub address: Option<Ipv6Addr>,
        #[prost(uint32, tag = "2")]
        pub network_length: u32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct Url {
        #[prost(string, tag = "1")]
        pub url: String,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum NatType {
        Unknown = 0,
        OpenInternet = 1,
        NoPat = 2,
        FullCone = 3,
        Restricted = 4,
        PortRestricted = 5,
        Symmetric = 6,
        SymUdpFirewall = 7,
        SymmetricEasyInc = 8,
        SymmetricEasyDec = 9,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct StunInfo {
        #[prost(enumeration = "NatType", tag = "1")]
        pub udp_nat_type: i32,
        #[prost(enumeration = "NatType", tag = "2")]
        pub tcp_nat_type: i32,
        #[prost(int64, tag = "3")]
        pub last_update_time: i64,
        #[prost(string, repeated, tag = "4")]
        pub public_ip: Vec<String>,
        #[prost(uint32, tag = "5")]
        pub min_port: u32,
        #[prost(uint32, tag = "6")]
        pub max_port: u32,
    }

    #[expect(
        clippy::struct_excessive_bools,
        reason = "flat wire mirror of the PeerFeatureFlag message; one bool per field tag"
    )]
    #[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
    pub struct PeerFeatureFlag {
        #[prost(bool, tag = "1")]
        pub is_public_server: bool,
        #[prost(bool, tag = "2")]
        pub avoid_relay_data: bool,
        #[prost(bool, tag = "3")]
        pub kcp_input: bool,
        #[prost(bool, tag = "4")]
        pub no_relay_kcp: bool,
        #[prost(bool, tag = "5")]
        pub support_conn_list_sync: bool,
        #[prost(bool, tag = "6")]
        pub quic_input: bool,
        #[prost(bool, tag = "7")]
        pub no_relay_quic: bool,
        #[prost(bool, tag = "8")]
        pub is_credential_peer: bool,
        #[prost(bool, tag = "9")]
        pub need_p2p: bool,
        #[prost(bool, tag = "10")]
        pub disable_p2p: bool,
        #[prost(bool, tag = "11")]
        pub ipv6_public_addr_provider: bool,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct TunnelInfo {
        #[prost(string, tag = "1")]
        pub tunnel_type: String,
        #[prost(message, optional, tag = "2")]
        pub local_addr: Option<Url>,
        #[prost(message, optional, tag = "3")]
        pub remote_addr: Option<Url>,
        #[prost(message, optional, tag = "4")]
        pub resolved_remote_addr: Option<Url>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct DirectRpcRequest {
        #[prost(string, tag = "1")]
        pub full_method_name: String,
        #[prost(bytes = "vec", tag = "2")]
        pub request: Vec<u8>,
        #[prost(uint64, optional, tag = "3")]
        pub timeout_ms: Option<u64>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct RpcResponse {
        #[prost(bytes = "vec", tag = "1")]
        pub response: Vec<u8>,
        #[prost(message, optional, tag = "2")]
        pub error: Option<super::error::Error>,
        #[prost(uint64, tag = "3")]
        pub runtime_us: u64,
    }
}

pub mod error {
    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct OtherError {
        #[prost(string, tag = "1")]
        pub error_message: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct InvalidMethodIndex {
        #[prost(string, tag = "1")]
        pub service_name: String,
        #[prost(uint32, tag = "2")]
        pub method_index: u32,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct InvalidService {
        #[prost(string, tag = "1")]
        pub service_name: String,
    }

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
    pub struct ProstDecodeError {}

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
    pub struct ProstEncodeError {}

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct ExecuteError {
        #[prost(string, tag = "1")]
        pub error_message: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct MalformatRpcPacket {
        #[prost(string, tag = "1")]
        pub error_message: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct Timeout {
        #[prost(string, tag = "1")]
        pub error_message: String,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct Error {
        #[prost(oneof = "error::ErrorKind", tags = "1, 2, 3, 4, 5, 6, 7, 8")]
        pub error_kind: Option<error::ErrorKind>,
    }

    pub mod error {
        #[derive(Clone, PartialEq, Eq, prost::Oneof)]
        pub enum ErrorKind {
            #[prost(message, tag = "1")]
            OtherError(super::OtherError),
            #[prost(message, tag = "2")]
            InvalidMethodIndex(super::InvalidMethodIndex),
            #[prost(message, tag = "3")]
            InvalidService(super::InvalidService),
            #[prost(message, tag = "4")]
            ProstDecodeError(super::ProstDecodeError),
            #[prost(message, tag = "5")]
            ProstEncodeError(super::ProstEncodeError),
            #[prost(message, tag = "6")]
            ExecuteError(super::ExecuteError),
            #[prost(message, tag = "7")]
            MalformatRpcPacket(super::MalformatRpcPacket),
            #[prost(message, tag = "8")]
            Timeout(super::Timeout),
        }
    }
}

pub mod peer_rpc {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum SecureAuthLevel {
        None = 0,
        EncryptedUnauthenticated = 1,
        PeerVerified = 2,
        NetworkSecretConfirmed = 3,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum PeerIdentityType {
        Admin = 0,
        Credential = 1,
        SharedNode = 2,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct GetIpListResponse {
        #[prost(message, optional, tag = "1")]
        pub public_ipv4: Option<super::common::Ipv4Addr>,
        #[prost(message, repeated, tag = "2")]
        pub interface_ipv4s: Vec<super::common::Ipv4Addr>,
        #[prost(message, optional, tag = "3")]
        pub public_ipv6: Option<super::common::Ipv6Addr>,
        #[prost(message, repeated, tag = "4")]
        pub interface_ipv6s: Vec<super::common::Ipv6Addr>,
        #[prost(message, repeated, tag = "5")]
        pub listeners: Vec<super::common::Url>,
    }
}

pub mod apiinstance {
    use super::common;
    use super::peer_rpc;

    #[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
    pub struct PeerConnStats {
        #[prost(uint64, tag = "1")]
        pub rx_bytes: u64,
        #[prost(uint64, tag = "2")]
        pub tx_bytes: u64,
        #[prost(uint64, tag = "3")]
        pub rx_packets: u64,
        #[prost(uint64, tag = "4")]
        pub tx_packets: u64,
        #[prost(uint64, tag = "5")]
        pub latency_us: u64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PeerConnInfo {
        #[prost(string, tag = "1")]
        pub conn_id: String,
        #[prost(uint32, tag = "2")]
        pub my_peer_id: u32,
        #[prost(uint32, tag = "3")]
        pub peer_id: u32,
        #[prost(string, repeated, tag = "4")]
        pub features: Vec<String>,
        #[prost(message, optional, tag = "5")]
        pub tunnel: Option<common::TunnelInfo>,
        #[prost(message, optional, tag = "6")]
        pub stats: Option<PeerConnStats>,
        #[prost(float, tag = "7")]
        pub loss_rate: f32,
        #[prost(bool, tag = "8")]
        pub is_client: bool,
        #[prost(string, tag = "9")]
        pub network_name: String,
        #[prost(bool, tag = "10")]
        pub is_closed: bool,
        #[prost(bytes = "vec", tag = "11")]
        pub noise_local_static_pubkey: Vec<u8>,
        #[prost(bytes = "vec", tag = "12")]
        pub noise_remote_static_pubkey: Vec<u8>,
        #[prost(enumeration = "peer_rpc::SecureAuthLevel", tag = "13")]
        pub secure_auth_level: i32,
        #[prost(enumeration = "peer_rpc::PeerIdentityType", tag = "14")]
        pub peer_identity_type: i32,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct PeerInfo {
        #[prost(uint32, tag = "1")]
        pub peer_id: u32,
        #[prost(message, repeated, tag = "2")]
        pub conns: Vec<PeerConnInfo>,
        #[prost(message, optional, tag = "3")]
        pub default_conn_id: Option<common::Uuid>,
        #[prost(message, repeated, tag = "4")]
        pub directly_connected_conns: Vec<common::Uuid>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ListPeerResponse {
        #[prost(message, repeated, tag = "1")]
        pub peer_infos: Vec<PeerInfo>,
        #[prost(message, optional, tag = "2")]
        pub my_info: Option<NodeInfo>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct Route {
        #[prost(uint32, tag = "1")]
        pub peer_id: u32,
        #[prost(message, optional, tag = "2")]
        pub ipv4_addr: Option<common::Ipv4Inet>,
        #[prost(uint32, tag = "3")]
        pub next_hop_peer_id: u32,
        #[prost(int32, tag = "4")]
        pub cost: i32,
        #[prost(int32, tag = "11")]
        pub path_latency: i32,
        #[prost(string, repeated, tag = "5")]
        pub proxy_cidrs: Vec<String>,
        #[prost(string, tag = "6")]
        pub hostname: String,
        #[prost(message, optional, tag = "7")]
        pub stun_info: Option<common::StunInfo>,
        #[prost(string, tag = "8")]
        pub inst_id: String,
        #[prost(string, tag = "9")]
        pub version: String,
        #[prost(message, optional, tag = "10")]
        pub feature_flag: Option<common::PeerFeatureFlag>,
        #[prost(uint32, optional, tag = "12")]
        pub next_hop_peer_id_latency_first: Option<u32>,
        #[prost(int32, optional, tag = "13")]
        pub cost_latency_first: Option<i32>,
        #[prost(int32, optional, tag = "14")]
        pub path_latency_latency_first: Option<i32>,
        #[prost(message, optional, tag = "15")]
        pub ipv6_addr: Option<common::Ipv6Inet>,
        #[prost(message, optional, tag = "16")]
        pub public_ipv6_addr: Option<common::Ipv6Inet>,
        #[prost(message, optional, tag = "17")]
        pub ipv6_public_addr_prefix: Option<common::Ipv6Inet>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct ListRouteResponse {
        #[prost(message, repeated, tag = "1")]
        pub routes: Vec<Route>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct NodeInfo {
        #[prost(uint32, tag = "1")]
        pub peer_id: u32,
        #[prost(string, tag = "2")]
        pub ipv4_addr: String,
        #[prost(string, repeated, tag = "3")]
        pub proxy_cidrs: Vec<String>,
        #[prost(string, tag = "4")]
        pub hostname: String,
        #[prost(message, optional, tag = "5")]
        pub stun_info: Option<common::StunInfo>,
        #[prost(string, tag = "6")]
        pub inst_id: String,
        #[prost(string, repeated, tag = "7")]
        pub listeners: Vec<String>,
        #[prost(string, tag = "8")]
        pub config: String,
        #[prost(string, tag = "9")]
        pub version: String,
        #[prost(message, optional, tag = "10")]
        pub feature_flag: Option<common::PeerFeatureFlag>,
        #[prost(message, optional, tag = "11")]
        pub ip_list: Option<peer_rpc::GetIpListResponse>,
        #[prost(message, optional, tag = "12")]
        pub public_ipv6_addr: Option<common::Ipv6Inet>,
        #[prost(message, optional, tag = "13")]
        pub ipv6_public_addr_prefix: Option<common::Ipv6Inet>,
    }

    #[derive(Clone, PartialEq, Eq, prost::Message)]
    pub struct ShowNodeInfoResponse {
        #[prost(message, optional, tag = "1")]
        pub node_info: Option<NodeInfo>,
    }
}

pub use apiinstance::{
    ListPeerResponse, ListRouteResponse, NodeInfo, PeerConnInfo, PeerConnStats, PeerInfo, Route, ShowNodeInfoResponse,
};
pub use common::{DirectRpcRequest, RpcResponse, Uuid};
pub use error::Error;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn roundtrip<M: Message + Default + PartialEq + Clone + std::fmt::Debug>(msg: M) {
        let bytes = msg.encode_to_vec();
        let decoded = M::decode(bytes.as_slice()).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_direct_rpc_request() {
        roundtrip(DirectRpcRequest {
            full_method_name: "api.instance.PeerManageRpc.ListPeer".into(),
            request: vec![1, 2, 3],
            timeout_ms: Some(5000),
        });
        roundtrip(DirectRpcRequest { full_method_name: String::new(), request: vec![], timeout_ms: None });
    }

    #[test]
    fn roundtrip_rpc_response_success() {
        roundtrip(RpcResponse { response: vec![9, 9], error: None, runtime_us: 42 });
    }

    #[test]
    fn roundtrip_rpc_response_error_variants() {
        roundtrip(RpcResponse {
            response: vec![],
            error: Some(Error {
                error_kind: Some(error::error::ErrorKind::OtherError(error::OtherError {
                    error_message: "boom".into(),
                })),
            }),
            runtime_us: 0,
        });
        roundtrip(Error {
            error_kind: Some(error::error::ErrorKind::InvalidMethodIndex(error::InvalidMethodIndex {
                service_name: "svc".into(),
                method_index: 3,
            })),
        });
        roundtrip(Error {
            error_kind: Some(error::error::ErrorKind::InvalidService(error::InvalidService {
                service_name: "svc".into(),
            })),
        });
        roundtrip(Error { error_kind: Some(error::error::ErrorKind::ProstDecodeError(error::ProstDecodeError {})) });
        roundtrip(Error { error_kind: Some(error::error::ErrorKind::ProstEncodeError(error::ProstEncodeError {})) });
        roundtrip(Error {
            error_kind: Some(error::error::ErrorKind::ExecuteError(error::ExecuteError {
                error_message: "exec".into(),
            })),
        });
        roundtrip(Error {
            error_kind: Some(error::error::ErrorKind::MalformatRpcPacket(error::MalformatRpcPacket {
                error_message: "malformed".into(),
            })),
        });
        roundtrip(Error {
            error_kind: Some(error::error::ErrorKind::Timeout(error::Timeout { error_message: "timeout".into() })),
        });
    }

    #[test]
    fn roundtrip_common_types() {
        roundtrip(Uuid { part1: 1, part2: 2, part3: 3, part4: 4 });
        roundtrip(common::Ipv4Addr { addr: 0x0a00_0001 });
        roundtrip(common::Ipv6Addr { part1: 1, part2: 2, part3: 3, part4: 4 });
        roundtrip(common::Ipv4Inet { address: Some(common::Ipv4Addr { addr: 1 }), network_length: 24 });
        roundtrip(common::Ipv6Inet {
            address: Some(common::Ipv6Addr { part1: 1, part2: 2, part3: 3, part4: 4 }),
            network_length: 64,
        });
        roundtrip(common::Url { url: "tcp://1.2.3.4:5678".into() });
        roundtrip(common::StunInfo {
            udp_nat_type: common::NatType::FullCone as i32,
            tcp_nat_type: common::NatType::Symmetric as i32,
            last_update_time: 123,
            public_ip: vec!["1.2.3.4".into()],
            min_port: 1,
            max_port: 2,
        });
        roundtrip(common::PeerFeatureFlag {
            is_public_server: true,
            avoid_relay_data: false,
            kcp_input: true,
            no_relay_kcp: false,
            support_conn_list_sync: true,
            quic_input: false,
            no_relay_quic: true,
            is_credential_peer: false,
            need_p2p: true,
            disable_p2p: false,
            ipv6_public_addr_provider: true,
        });
        roundtrip(common::TunnelInfo {
            tunnel_type: "tcp".into(),
            local_addr: Some(common::Url { url: "tcp://a".into() }),
            remote_addr: Some(common::Url { url: "tcp://b".into() }),
            resolved_remote_addr: None,
        });
    }

    #[test]
    fn roundtrip_get_ip_list_response() {
        roundtrip(peer_rpc::GetIpListResponse {
            public_ipv4: Some(common::Ipv4Addr { addr: 1 }),
            interface_ipv4s: vec![common::Ipv4Addr { addr: 2 }],
            public_ipv6: Some(common::Ipv6Addr { part1: 1, part2: 2, part3: 3, part4: 4 }),
            interface_ipv6s: vec![common::Ipv6Addr { part1: 5, part2: 6, part3: 7, part4: 8 }],
            listeners: vec![common::Url { url: "udp://x".into() }],
        });
    }

    fn sample_peer_conn_info() -> PeerConnInfo {
        PeerConnInfo {
            conn_id: "conn-1".into(),
            my_peer_id: 1,
            peer_id: 2,
            features: vec!["kcp".into()],
            tunnel: Some(common::TunnelInfo {
                tunnel_type: "tcp".into(),
                local_addr: None,
                remote_addr: None,
                resolved_remote_addr: None,
            }),
            stats: Some(PeerConnStats { rx_bytes: 1, tx_bytes: 2, rx_packets: 3, tx_packets: 4, latency_us: 5 }),
            loss_rate: 0.5,
            is_client: true,
            network_name: "net".into(),
            is_closed: false,
            noise_local_static_pubkey: vec![1, 2],
            noise_remote_static_pubkey: vec![3, 4],
            secure_auth_level: peer_rpc::SecureAuthLevel::PeerVerified as i32,
            peer_identity_type: peer_rpc::PeerIdentityType::Credential as i32,
        }
    }

    #[test]
    fn roundtrip_peer_conn_info() {
        roundtrip(sample_peer_conn_info());
    }

    #[test]
    fn roundtrip_peer_info_and_list_peer_response() {
        let peer_info = PeerInfo {
            peer_id: 1,
            conns: vec![sample_peer_conn_info()],
            default_conn_id: Some(Uuid { part1: 1, part2: 2, part3: 3, part4: 4 }),
            directly_connected_conns: vec![Uuid { part1: 5, part2: 6, part3: 7, part4: 8 }],
        };
        roundtrip(peer_info.clone());
        roundtrip(ListPeerResponse { peer_infos: vec![peer_info], my_info: Some(sample_node_info()) });
    }

    fn sample_route() -> Route {
        Route {
            peer_id: 1,
            ipv4_addr: Some(common::Ipv4Inet { address: Some(common::Ipv4Addr { addr: 1 }), network_length: 24 }),
            next_hop_peer_id: 2,
            cost: 3,
            path_latency: 4,
            proxy_cidrs: vec!["10.0.0.0/8".into()],
            hostname: "host".into(),
            stun_info: Some(common::StunInfo {
                udp_nat_type: common::NatType::Unknown as i32,
                tcp_nat_type: common::NatType::Unknown as i32,
                last_update_time: 0,
                public_ip: vec![],
                min_port: 0,
                max_port: 0,
            }),
            inst_id: "inst".into(),
            version: "1.0".into(),
            feature_flag: Some(common::PeerFeatureFlag {
                is_public_server: false,
                avoid_relay_data: false,
                kcp_input: false,
                no_relay_kcp: false,
                support_conn_list_sync: false,
                quic_input: false,
                no_relay_quic: false,
                is_credential_peer: false,
                need_p2p: false,
                disable_p2p: false,
                ipv6_public_addr_provider: false,
            }),
            next_hop_peer_id_latency_first: Some(9),
            cost_latency_first: Some(10),
            path_latency_latency_first: Some(11),
            ipv6_addr: Some(common::Ipv6Inet {
                address: Some(common::Ipv6Addr { part1: 1, part2: 2, part3: 3, part4: 4 }),
                network_length: 64,
            }),
            public_ipv6_addr: None,
            ipv6_public_addr_prefix: None,
        }
    }

    #[test]
    fn roundtrip_route_and_list_route_response() {
        roundtrip(sample_route());
        roundtrip(ListRouteResponse { routes: vec![sample_route(), Route::default()] });
    }

    fn sample_node_info() -> NodeInfo {
        NodeInfo {
            peer_id: 1,
            ipv4_addr: "10.0.0.1".into(),
            proxy_cidrs: vec!["10.0.0.0/8".into()],
            hostname: "host".into(),
            stun_info: None,
            inst_id: "inst".into(),
            listeners: vec!["tcp://a".into()],
            config: "cfg".into(),
            version: "1.0".into(),
            feature_flag: None,
            ip_list: Some(peer_rpc::GetIpListResponse {
                public_ipv4: Some(common::Ipv4Addr { addr: 1 }),
                interface_ipv4s: vec![],
                public_ipv6: None,
                interface_ipv6s: vec![],
                listeners: vec![],
            }),
            public_ipv6_addr: Some(common::Ipv6Inet {
                address: Some(common::Ipv6Addr { part1: 1, part2: 2, part3: 3, part4: 4 }),
                network_length: 64,
            }),
            ipv6_public_addr_prefix: None,
        }
    }

    #[test]
    fn roundtrip_node_info_and_show_node_info_response() {
        roundtrip(sample_node_info());
        roundtrip(ShowNodeInfoResponse { node_info: Some(sample_node_info()) });
        roundtrip(ShowNodeInfoResponse { node_info: None });
    }

    #[test]
    fn direct_rpc_request_wire_bytes_match_hand_computed_encoding() {
        let msg = DirectRpcRequest {
            full_method_name: "api.instance.PeerManageRpc.ListPeer".into(),
            request: vec![],
            timeout_ms: None,
        };
        let encoded = msg.encode_to_vec();

        let field_name = "api.instance.PeerManageRpc.ListPeer";
        let mut expected = Vec::new();
        expected.push((1u8 << 3) | 2);
        expected.push(field_name.len() as u8);
        expected.extend_from_slice(field_name.as_bytes());

        assert_eq!(encoded, expected);
    }
}
