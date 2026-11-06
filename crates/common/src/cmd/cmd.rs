use std::process::ExitStatus;

use anyhow::{anyhow, Result};
use tokio::process::Command;

#[cfg(not(target_os = "windows"))]
use super::cmd_other::prepare_background_command;
#[cfg(target_os = "windows")]
use super::cmd_windows::prepare_background_command;

/// Runs `cmd_str` and returns its combined output; the error carries the failure text and the
/// output collected so far.
pub async fn exec_cmd(cmd_str: &str) -> Result<String> {
    // NOT cancel-safe: dropping the future leaves the child process running and discards the
    // output collected so far.
    let args = split_args(cmd_str);
    let Some((program, rest)) = args.split_first() else {
        return Err(anyhow!("empty command"));
    };

    let mut cmd = Command::new(program);
    cmd.args(rest);
    run_combined_output(&mut cmd).await
}

pub(crate) fn split_args(cmd: &str) -> Vec<String> {
    let mut args: Vec<String> = cmd.split(' ').map(str::to_owned).collect();

    // use in pipeline
    if args.len() > 2 && cmd.contains('|') {
        let suffix = args.split_off(2).join(" ");
        args.push(suffix);
    }
    args
}

/// Runs `shell_str` through `cmd.exe /C` on Windows and `sh -c` elsewhere.
pub async fn exec_shell(shell_str: &str) -> Result<String> {
    // NOT cancel-safe: as `exec_cmd`, the child keeps running once this future is dropped.
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut cmd = Command::new("cmd.exe");
        cmd.arg("/C").arg(shell_str);
        cmd
    };
    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(shell_str);
        cmd
    };

    run_combined_output(&mut cmd).await
}

async fn run_combined_output(cmd: &mut Command) -> Result<String> {
    // NOT cancel-safe: a dropped call leaves the spawned child running and discards partial output.
    prepare_background_command(cmd);
    let (out, err) = match cmd.output().await {
        Ok(output) => {
            let out = combined_output(&output);
            let err = if output.status.success() { None } else { Some(exit_status_text(output.status)) };
            (out, err)
        }
        Err(err) => (String::new(), Some(err.to_string())),
    };
    match err {
        Some(err) => Err(anyhow!("{err}, {out}")),
        None => Ok(out),
    }
}

fn combined_output(output: &std::process::Output) -> String {
    let mut out = String::from_utf8_lossy(&output.stdout).into_owned();
    out.push_str(&String::from_utf8_lossy(&output.stderr));
    out
}

fn exit_status_text(status: ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exit status {code}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return format!("signal: {signal}");
        }
    }
    "exit status unknown".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_args() {
        let args = split_args("ls");
        let args1 = split_args("ls -la");
        let args2 = split_args("bash -c ls");
        let args3 = split_args("bash -c ls -lahF | grep 'cmd'");

        assert_eq!(1, args.len());
        assert_eq!(2, args1.len());
        assert_eq!(3, args2.len());
        assert_eq!(3, args3.len());
    }

    #[tokio::test]
    async fn test_exec_cmd() {
        if cfg!(target_os = "windows") {
            assert!(exec_cmd("cmd -c 'dir'").await.is_ok());
            return;
        }
        assert!(exec_cmd("ls").await.is_ok());
        assert!(exec_cmd("ls -la").await.is_ok());
        assert!(exec_cmd("bash -c ls").await.is_ok());
        assert!(exec_cmd("bash -c ls -la").await.is_ok());
    }
}
