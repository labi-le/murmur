use std::io::Read;

use anyhow::{anyhow, Result};

use super::provider::{err_invalid_format, RuleStrategy};

/// `MrsMagicBytes` (`MRSv1`).
pub const MRS_MAGIC_BYTES: [u8; 4] = [b'M', b'R', b'S', 1];

pub(crate) fn rules_mrs_parse(buf: &[u8], mut strategy: Box<dyn RuleStrategy>) -> Result<Box<dyn RuleStrategy>> {
    if strategy.as_mrs_mut().is_none() {
        return Err(err_invalid_format());
    }

    let mut reader = zstd::Decoder::new(buf)?;

    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    if header != MRS_MAGIC_BYTES {
        return Err(anyhow!("invalid MrsMagic bytes"));
    }

    let mut behavior_byte = [0u8; 1];
    reader.read_exact(&mut behavior_byte)?;
    if behavior_byte[0] != strategy.behavior().byte() {
        return Err(anyhow!("invalid behavior"));
    }

    let mut count_bytes = [0u8; 8];
    reader.read_exact(&mut count_bytes)?;
    let count = i64::from_be_bytes(count_bytes);

    let mut length_bytes = [0u8; 8];
    reader.read_exact(&mut length_bytes)?;
    let length = i64::from_be_bytes(length_bytes);
    let extra_len = usize::try_from(length).map_err(|_| anyhow!("length is invalid"))?;
    if extra_len > 0 {
        let mut extra = vec![0u8; extra_len];
        reader.read_exact(&mut extra)?;
    }

    let Some(mrs) = strategy.as_mrs_mut() else {
        return Err(err_invalid_format());
    };
    mrs.load_mrs(&mut reader, count.try_into().unwrap_or(i32::MAX))?;
    Ok(strategy)
}
