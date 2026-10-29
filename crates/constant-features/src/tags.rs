use super::{CMFA, NO_EASY_TIER, NO_FAKE_TCP, NO_TAILSCALE, NO_ZERO_TIER, WITH_GVISOR, WITH_LOW_MEMORY};

#[must_use]
pub fn tags() -> Vec<String> {
    let mut tags = Vec::new();
    if CMFA {
        tags.push("cmfa".to_owned());
    }
    if WITH_LOW_MEMORY {
        tags.push("with_low_memory".to_owned());
    }
    if NO_FAKE_TCP {
        tags.push("no_fake_tcp".to_owned());
    }
    if NO_TAILSCALE {
        tags.push("no_tailscale".to_owned());
    }
    if NO_ZERO_TIER {
        tags.push("no_zerotier".to_owned());
    }
    if NO_EASY_TIER {
        tags.push("no_easytier".to_owned());
    }
    if WITH_GVISOR {
        tags.push("with_gvisor".to_owned());
    }
    tags
}
