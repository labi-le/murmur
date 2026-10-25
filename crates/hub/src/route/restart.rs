use hyper::{Method, Response, StatusCode};
use tokio::sync::oneshot;

use crate::executor::executor::shutdown;
use murmur_log::{fatalln, infoln};

use super::common::{json_response, json_response_with_completion, status_only, Req, RespBody};
use super::errors::HttpError;

#[expect(
    clippy::unused_async,
    reason = "the mount entry point is awaited by the shared dispatcher in `server.rs`; the handler behind it only spawns"
)]
pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    match segs {
        [] => {
            if req.method() != Method::POST {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(restart())
        }
        _ => None,
    }
}

fn restart() -> Response<RespBody> {
    let exec_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            return json_response(StatusCode::INTERNAL_SERVER_ERROR, &HttpError::new(format!("getting path: {err}")))
        }
    };

    let (resp, response_sent) = json_response_with_completion(StatusCode::OK, &serde_json::json!({"status": "ok"}));

    // The background context is used because the underlying functions wrap it with timeout and
    // shut down the server, which handles current request. It also should be done in a separate
    // task for the same reason.
    tokio::spawn(restart_executable(exec_path, response_sent));

    resp
}

/// Restart and upgrade flush their response synchronously before spawning the
/// shutdown-and-re-exec task, guaranteeing the client already has the 200 response before the
/// listener it connected through goes away. This crate's response is a plain value handed to hyper
/// when the handler returns, with no synchronous flush hook exposed to application code;
/// `response_sent` (a [`super::common::json_response_with_completion`] receiver) instead orders
/// this past the point hyper has drained the response body, and this fixed grace period covers the
/// remaining gap between that hand-off and the kernel actually accepting the write.
const RESTART_GRACE_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

pub(crate) async fn restart_executable(exec_path: std::path::PathBuf, response_sent: oneshot::Receiver<()>) {
    let _ = response_sent.await;
    tokio::time::sleep(RESTART_GRACE_DELAY).await;
    shutdown().await;

    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().skip(1).collect();
        infoln!("restarting: {:?} {:?}", exec_path, args);
        match std::process::Command::new(&exec_path).args(&args).spawn() {
            Ok(_) => std::process::exit(0),
            Err(err) => fatalln!("restarting: {}", err),
        }
    }

    #[cfg(not(windows))]
    {
        use std::os::unix::process::CommandExt;

        let args: Vec<String> = std::env::args().collect();
        infoln!("restarting: {:?} {:?}", exec_path, args);
        let err = std::process::Command::new(&exec_path).args(args.get(1..).unwrap_or_default()).exec();
        fatalln!("restarting: {}", err);
    }
}
