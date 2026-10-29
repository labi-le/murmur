use std::io::Write;

use anyhow::{anyhow, Result};

use murmur_constant::provider::interface::{parse_behavior, parse_rule_format, RuleBehavior, RuleFormat};

use super::mrs_reader::MRS_MAGIC_BYTES;
use super::provider::{err_invalid_format, new_strategy, rules_parse};

pub fn convert_to_mrs(buf: &[u8], behavior: RuleBehavior, format: RuleFormat, w: &mut dyn Write) -> Result<()> {
    let strategy = new_strategy(behavior, None).ok_or_else(|| anyhow!("unsupported rule behavior"))?;
    let strategy = rules_parse(buf, strategy, format)?;
    if strategy.count() == 0 {
        return Err(anyhow!("empty rule"));
    }

    let Some(mrs_strategy) = strategy.as_mrs() else {
        return Err(err_invalid_format());
    };

    if format == RuleFormat::MRS_RULE {
        let mut write_err: Option<std::io::Error> = None;
        mrs_strategy.dump_mrs(&mut |key: &str| match writeln!(w, "{key}") {
            Ok(()) => true,
            Err(err) => {
                write_err = Some(err);
                false
            }
        });
        return match write_err {
            Some(err) => Err(err.into()),
            None => Ok(()),
        };
    }

    let mut encoder = zstd::Encoder::new(w, 0)?;
    let body_result = (|| -> Result<()> {
        encoder.write_all(&MRS_MAGIC_BYTES)?;

        let behavior_byte = [behavior.byte()];
        encoder.write_all(&behavior_byte)?;

        let count = i64::from(mrs_strategy.count());
        encoder.write_all(&count.to_be_bytes())?;

        let extra: [u8; 0] = [];
        encoder.write_all(&i64::try_from(extra.len())?.to_be_bytes())?;
        encoder.write_all(&extra)?;

        mrs_strategy.write_mrs(&mut encoder)
    })();

    let close_result = encoder.finish();
    match (body_result, close_result) {
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err.into()),
        (Ok(()), Ok(_)) => Ok(()),
    }
}

#[expect(
    clippy::panic,
    reason = "`convert-ruleset` is the CLI entry point; a malformed invocation must terminate the process fatally"
)]
pub fn convert_main(args: &[String]) {
    let [behavior_arg, format_arg, source, target, ..] = args else {
        panic!("Usage: convert-ruleset <behavior> <format> <source file> <target file>");
    };

    let behavior = parse_behavior(behavior_arg).unwrap_or_else(|err| panic!("{err}"));
    let format = parse_rule_format(format_arg).unwrap_or_else(|err| panic!("{err}"));

    let source_file = std::fs::read(source).unwrap_or_else(|err| panic!("{err}"));

    let mut target_file = open_target(target).unwrap_or_else(|err| panic!("{err}"));

    convert_to_mrs(&source_file, behavior, format, &mut target_file).unwrap_or_else(|err| panic!("{err}"));

    target_file.sync_all().unwrap_or_else(|err| panic!("{err}"));
}

#[cfg(unix)]
fn open_target(target: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o644).open(target)
}

#[cfg(not(unix))]
fn open_target(target: &str) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(target)
}
