use hyper::{Method, Response, StatusCode};

use murmur_component_updater::{update_core::DEFAULT_CORE_UPDATER, update_ui};
use murmur_log::{infoln, warnln};

use super::common::{json_response, json_response_with_completion, status_only, Req, RespBody};
use super::errors::HttpError;
use super::restart::restart_executable;
use super::server::{embed_mode, query_param};

pub(crate) async fn route(req: Req, segs: &[&str]) -> Option<Response<RespBody>> {
    match segs {
        ["ui"] => {
            if req.method() != Method::POST {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(update_ui().await)
        }
        [] if !embed_mode() => {
            if req.method() != Method::POST {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(upgrade_core(&req).await)
        }
        ["geo"] if !embed_mode() => {
            if req.method() != Method::POST {
                return Some(status_only(StatusCode::METHOD_NOT_ALLOWED));
            }
            Some(super::configs::update_geo_databases().await)
        }
        _ => None,
    }
}

async fn upgrade_core(req: &Req) -> Response<RespBody> {
    infoln!("start update");
    let exec_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            return json_response(StatusCode::INTERNAL_SERVER_ERROR, &HttpError::new(format!("getting path: {err}")))
        }
    };

    let query = req.uri().query().unwrap_or("");
    let channel = query_param(query, "channel").unwrap_or_default();
    let force = query_param(query, "force").as_deref() == Some("true");

    if let Err(err) = DEFAULT_CORE_UPDATER.update(&exec_path.to_string_lossy(), &channel, force).await {
        warnln!("{}", err);
        return json_response(StatusCode::INTERNAL_SERVER_ERROR, &HttpError::new(err.to_string()));
    }

    let (resp, response_sent) = json_response_with_completion(StatusCode::OK, &serde_json::json!({"status": "ok"}));
    tokio::spawn(restart_executable(exec_path, response_sent));
    resp
}

async fn update_ui() -> Response<RespBody> {
    if let Err(err) = update_ui::ui_updater().download_ui().await {
        warnln!("{}", err);
        return json_response(StatusCode::INTERNAL_SERVER_ERROR, &HttpError::new(format!("{err}")));
    }

    json_response(StatusCode::OK, &serde_json::json!({"status": "ok"}))
}
