/// The no-IP-address / invalid-network-stack errors; callers match on these variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DialerError {
    #[error("no ip address")]
    NoIpAddress,
    #[error("invalided network stack")]
    InvalidedNetworkStack,
}

pub const ERROR_NO_IP_ADDRESS: DialerError = DialerError::NoIpAddress;

pub const ERROR_INVALIDED_NETWORK_STACK: DialerError = DialerError::InvalidedNetworkStack;
