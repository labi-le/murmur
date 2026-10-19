use murmur_listener_sing::sing as lc_sing;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct MuxOption {
    pub padding: bool,
    pub brutal: BrutalOptions,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct BrutalOptions {
    pub enabled: bool,
    pub up: String,
    pub down: String,
}

impl MuxOption {
    #[must_use]
    pub fn build(&self) -> lc_sing::MuxOption {
        lc_sing::MuxOption {
            padding: self.padding,
            brutal: lc_sing::BrutalOptions {
                enabled: self.brutal.enabled,
                up: self.brutal.up.clone(),
                down: self.brutal.down.clone(),
            },
        }
    }
}
