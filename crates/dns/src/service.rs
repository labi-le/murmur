use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::{Edns, Message};
use tokio_util::sync::CancellationToken;

use murmur_component::resolver::resolver::SharedResolver;
use murmur_component::resolver::service::Service as ResolverService;
use murmur_context::dns::new_dns_context;

use super::enhancer::ResolverEnhancer;
use super::middleware::{new_handler, BoxHandler};

pub struct Service {
    handler: BoxHandler,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service").finish_non_exhaustive()
    }
}

#[async_trait]
impl ResolverService for Service {
    /// Implements `ResolverService`.
    async fn serve_msg(&self, ctx: &CancellationToken, msg: &Message) -> Result<Message> {
        if msg.queries.is_empty() {
            return Err(anyhow!("at least one question is required"));
        }

        let mut dns_ctx = new_dns_context(ctx);
        let mut r = self.handler.handle(&mut dns_ctx, msg).await?;
        echo_default_opt(msg, &mut r);

        Ok(r)
    }
}

/// When the handler answers without an OPT of its own (a
/// cache hit, whose cached message never carries one), add one that copies the request's DO bit.
fn echo_default_opt(msg: &Message, r: &mut Message) {
    if let Some(req_opt) = msg.edns.as_ref().filter(|_| r.edns.is_none()) {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(req_opt.flags().dnssec_ok);
        r.edns = Some(edns);
    }
}

impl Service {
    pub fn new(resolver: SharedResolver, mapper: &ResolverEnhancer) -> Self {
        Self { handler: new_handler(resolver, mapper) }
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{MessageType, OpCode};

    use super::*;

    fn message_with_edns(dnssec_ok: bool) -> Message {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(dnssec_ok);
        msg.edns = Some(edns);
        msg
    }

    #[test]
    fn echo_default_opt_copies_the_requests_do_bit_when_set() {
        let req = message_with_edns(true);
        let mut r = Message::new(0, MessageType::Response, OpCode::Query);

        echo_default_opt(&req, &mut r);

        let edns = r.edns.expect("opt added");
        assert!(edns.flags().dnssec_ok);
        assert_eq!(edns.max_payload(), 1232);
    }

    #[test]
    fn echo_default_opt_copies_the_requests_do_bit_when_unset() {
        let req = message_with_edns(false);
        let mut r = Message::new(0, MessageType::Response, OpCode::Query);

        echo_default_opt(&req, &mut r);

        assert!(!r.edns.expect("opt added").flags().dnssec_ok);
    }

    #[test]
    fn echo_default_opt_does_nothing_without_a_request_opt() {
        let req = Message::new(0, MessageType::Query, OpCode::Query);
        let mut r = Message::new(0, MessageType::Response, OpCode::Query);

        echo_default_opt(&req, &mut r);

        assert!(r.edns.is_none());
    }

    #[test]
    fn echo_default_opt_never_overwrites_an_answer_that_already_has_an_opt() {
        let req = message_with_edns(true);
        let mut r = Message::new(0, MessageType::Response, OpCode::Query);
        let mut answer_edns = Edns::new();
        answer_edns.set_dnssec_ok(false);
        r.edns = Some(answer_edns);

        echo_default_opt(&req, &mut r);

        assert!(!r.edns.expect("opt kept").flags().dnssec_ok);
    }
}
