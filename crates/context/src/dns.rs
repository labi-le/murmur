use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use murmur_common::utils::uuid::new_uuid_v4;
use murmur_constant::context::PlainContext;

pub const DNS_TYPE_HOST: &str = "host";
pub const DNS_TYPE_FAKE_IP: &str = "fakeip";
pub const DNS_TYPE_RAW: &str = "raw";

/// The DNS context, which carries its own cancellation token.
#[derive(Debug)]
pub struct DNSContext {
    ctx: CancellationToken,
    id: Uuid,
    tp: Option<&'static str>,
}

#[must_use]
pub fn new_dns_context(ctx: &CancellationToken) -> DNSContext {
    DNSContext { ctx: ctx.clone(), id: new_uuid_v4(), tp: None }
}

impl DNSContext {
    /// The embedded cancellation token.
    #[must_use]
    pub const fn ctx(&self) -> &CancellationToken {
        &self.ctx
    }

    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Sets the type of the response.
    pub fn set_type(&mut self, tp: &'static str) {
        self.tp = Some(tp);
    }

    /// Returns the type of the response.
    #[must_use]
    pub fn type_(&self) -> String {
        self.tp.unwrap_or_default().to_owned()
    }
}

impl PlainContext for DNSContext {
    fn id(&self) -> Uuid {
        self.id
    }
}
