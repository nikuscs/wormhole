use serde::Serialize;
use worker::{Headers, Response, Result};

pub const ROBOTS_TAG: &str = "noindex, nofollow, noarchive, nosnippet";

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorDetail<'a>,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
}

pub fn error(status: u16, code: &'static str, message: &'static str) -> Result<Response> {
    Response::from_json(&ErrorBody { error: ErrorDetail { code, message } })
        .map(|response| response.with_status(status).with_headers(no_store_headers()))
}

pub fn json<T: Serialize>(status: u16, value: &T) -> Result<Response> {
    Response::from_json(value)
        .map(|response| response.with_status(status).with_headers(no_store_headers()))
}

pub fn empty(status: u16) -> Result<Response> {
    Ok(Response::empty()?.with_status(status).with_headers(no_store_headers()))
}

pub fn index_policy(response: Result<Response>, noindex: bool) -> Result<Response> {
    let response = response?;
    if !noindex {
        return Ok(response);
    }
    let headers = Headers::new();
    for (name, value) in response.headers().entries() {
        headers.append(&name, &value)?;
    }
    headers.set("x-robots-tag", ROBOTS_TAG)?;
    Ok(response.with_headers(headers))
}

pub fn no_store_headers() -> Headers {
    let headers = Headers::new();
    let _ignored = headers.set("cache-control", "no-store");
    let _ignored = headers.set("x-content-type-options", "nosniff");
    headers
}
