//! There is no protobuf runtime here, so the message is declared as a `prost` message carrying
//! the same tags as the wire schema.
//!
//! The reflection tables and the protobuf runtime's message interface are not implemented here.

#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct Addons {
    #[prost(string, tag = "1")]
    pub flow: String,
    #[prost(bytes = "vec", tag = "2")]
    pub seed: Vec<u8>,
}

impl Addons {
    #[must_use]
    pub fn get_flow(&self) -> &str {
        &self.flow
    }

    #[must_use]
    pub fn get_seed(&self) -> &[u8] {
        &self.seed
    }
}
