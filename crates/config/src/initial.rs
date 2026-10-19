use anyhow::{anyhow, Result};

use murmur_constant::path::PATH;
use murmur_log::infoln;

/// Init prepare necessary files
pub fn init(dir: &str) -> Result<()> {
    if !std::path::Path::new(dir).exists() {
        std::fs::create_dir_all(dir).map_err(|err| anyhow!("can't create config directory {dir}: {err}"))?;
    }

    let config_path = PATH.config();
    if !std::path::Path::new(&config_path).exists() {
        infoln!("Can't find config, create a initial config file");
        std::fs::write(&config_path, b"mixed-port: 7890")
            .map_err(|err| anyhow!("can't create file {config_path}: {err}"))?;
    }

    Ok(())
}
