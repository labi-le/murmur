use anyhow::Result;
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use tokio_util::sync::CancellationToken;

use super::resolver::DnsClient;

#[expect(
    clippy::panic,
    reason = "an unknown `rcode://` name is a fatal configuration error and the signature returns `RcodeClient`"
)]
pub(crate) fn new_rcode_client(addr: &str) -> RcodeClient {
    let rcode = match addr {
        "success" => ResponseCode::NoError,
        "format_error" => ResponseCode::FormErr,
        "server_failure" => ResponseCode::ServFail,
        "name_error" => ResponseCode::NXDomain,
        "not_implemented" => ResponseCode::NotImp,
        "refused" => ResponseCode::Refused,
        _ => panic!("unsupported RCode type: {addr}"),
    };

    RcodeClient { rcode, addr: format!("rcode://{addr}") }
}

pub(crate) struct RcodeClient {
    rcode: ResponseCode,
    addr: String,
}

#[async_trait]
impl DnsClient for RcodeClient {
    async fn exchange_context(&self, _ctx: &CancellationToken, m: &Message) -> Result<Message> {
        let mut m = m.clone();
        m.metadata.message_type = MessageType::Response;
        m.metadata.response_code = self.rcode;
        Ok(m)
    }

    fn address(&self) -> String {
        self.addr.clone()
    }

    fn reset_connection(&self) {}

    /// The identity check that tells this client apart in a batch exchange.
    fn is_rcode_client(&self) -> bool {
        true
    }
}
