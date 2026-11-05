use serde::{Deserialize, Serialize};

use murmur_transport_kcptun::common::Config as KcptunTransportConfig;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KcpTun {
    #[serde(rename = "enable")]
    pub enable: bool,
    #[serde(flatten)]
    pub config: KcptunTransportConfig,
}
