//! Record script: a target record-length range plus a command telling the peer to pad, stay
//! silent, or answer with a given number of bytes.

use anyhow::{anyhow, Result};
use rand::Rng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Noop,
    Response(u8),
}

impl Command {
    #[must_use]
    pub fn to_bytes(self) -> [u8; 2] {
        match self {
            Self::Noop => [0x00, 0x00],
            Self::Response(v) => [0x01, v],
        }
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        match buf.first() {
            Some(0) => Ok(Self::Noop),
            Some(1) => Ok(Self::Response(*buf.get(1).ok_or_else(|| anyhow!("restls: short command"))?)),
            _ => Err(anyhow!("restls: unsupported restls command")),
        }
    }

    #[must_use]
    pub fn needs_interrupt(self) -> bool {
        matches!(self, Self::Response(v) if v > 0)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TargetLength(pub i16, pub i16);

impl TargetLength {
    #[expect(clippy::len_without_is_empty, reason = "randomized target length has no stable emptiness")]
    #[must_use]
    pub fn len(self) -> usize {
        let value = if self.1 != 0 {
            i32::from(self.0) + rand::rng().random_range(0..i32::from(self.1))
        } else {
            i32::from(self.0)
        };
        value.cast_unsigned() as usize
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Line {
    pub target_len: TargetLength,
    pub command: Command,
}

pub const DEFAULT_RESTLS_SCRIPT: &str = "250?100<1,350~100<1,600~100,300~200,300~100";

fn get_integer(s: &mut &[u8]) -> Result<i32> {
    let mut res: i32 = 0;
    let mut i = 0;
    while let Some(&b) = s.get(i) {
        if !b.is_ascii_digit() {
            break;
        }
        res = res * 10 + i32::from(b - b'0');
        if res > 32768 {
            return Err(anyhow!("target len > 32768"));
        }
        i += 1;
    }
    *s = s.get(i..).unwrap_or_default();
    Ok(res)
}

pub fn parse_record_script(script: &str) -> Result<Vec<Line>> {
    let cleaned: String = script.chars().filter(|c| !c.is_whitespace()).collect();
    let mut lines = Vec::new();
    for line_raw in cleaned.split(',') {
        if line_raw.is_empty() {
            continue;
        }
        let mut bytes = line_raw.as_bytes();
        let target = get_integer(&mut bytes).map_err(|err| anyhow!("invalid script {line_raw:?}: {err}"))?;
        if target > 32767 {
            return Err(anyhow!("invalid script {line_raw:?}: target len > 32767"));
        }
        let target = i16::try_from(target).map_err(|err| anyhow!("invalid script {line_raw:?}: {err}"))?;
        let mut target_len = TargetLength(target, 0);

        if bytes.is_empty() {
            lines.push(Line { target_len, command: Command::Noop });
            continue;
        }
        if let Some(&variant @ (b'~' | b'?')) = bytes.first() {
            bytes = bytes.get(1..).unwrap_or_default();
            let random_range = get_integer(&mut bytes).map_err(|err| anyhow!("invalid script {line_raw:?}: {err}"))?;
            if random_range > 32767 {
                return Err(anyhow!("invalid script {line_raw:?}: random target range > 32767"));
            }
            if random_range + i32::from(target) > 32768 {
                return Err(anyhow!("invalid script {line_raw:?}: random target len > 32768"));
            }
            target_len.1 = i16::try_from(random_range).map_err(|err| anyhow!("invalid script {line_raw:?}: {err}"))?;
            if variant == b'?' {
                let randomized = target_len.len();
                target_len = TargetLength(
                    i16::try_from(randomized).map_err(|err| anyhow!("invalid script {line_raw:?}: {err}"))?,
                    0,
                );
            }
        }

        if bytes.is_empty() {
            lines.push(Line { target_len, command: Command::Noop });
            continue;
        }
        if bytes.first() == Some(&b'<') {
            bytes = bytes.get(1..).unwrap_or_default();
            let num_response = get_integer(&mut bytes).map_err(|err| anyhow!("invalid script {line_raw:?}: {err}"))?;
            if !bytes.is_empty() {
                return Err(anyhow!(
                    "invalid script {line_raw:?}: unexpected content {:?}",
                    String::from_utf8_lossy(bytes)
                ));
            }
            if num_response >= 255 {
                return Err(anyhow!(
                    "invalid script {line_raw:?}: too many response in restls script, expect < 255, actual {num_response}"
                ));
            }
            let response = u8::try_from(num_response).map_err(|err| anyhow!("invalid script {line_raw:?}: {err}"))?;
            lines.push(Line { target_len, command: Command::Response(response) });
        } else {
            return Err(anyhow!(
                "invalid script {line_raw:?}: unexpected content {:?}",
                String::from_utf8_lossy(bytes)
            ));
        }
    }
    Ok(lines)
}
