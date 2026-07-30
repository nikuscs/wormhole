//! HTTP/1 request and response head translation for tunnel streams.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderName, HeaderValue, Method, Request, Version};
use wormhole_proto::frames::{HeaderField, HttpRequestHead, HttpResponseHead};

use crate::{error::DriverError, wormhole_stream::ClientBody};

pub fn build_request(
    head: HttpRequestHead,
    body: ClientBody,
    preserve_upgrade: bool,
) -> Result<Request<ClientBody>, DriverError> {
    let mut builder = Request::builder()
        .method(Method::from_bytes(head.method.as_bytes()).map_err(protocol_error)?)
        .uri(head.uri)
        .version(parse_version(&head.version));
    let connection_tokens = connection_tokens(&head.headers);
    if let Some(headers) = builder.headers_mut() {
        for field in head.headers {
            let name = HeaderName::from_bytes(field.name.as_bytes()).map_err(protocol_error)?;
            if should_strip(&name, &connection_tokens, preserve_upgrade) {
                continue;
            }
            let value = STANDARD.decode(field.value_b64).map_err(protocol_error)?;
            headers.append(name, HeaderValue::from_bytes(&value).map_err(protocol_error)?);
        }
    }
    builder.body(body).map_err(protocol_error)
}

pub fn response_head(
    response: &hyper::Response<hyper::body::Incoming>,
    upgrade: bool,
) -> HttpResponseHead {
    let connection_tokens = response
        .headers()
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut headers = Vec::new();
    for (name, value) in response.headers() {
        if should_strip(name, &connection_tokens, upgrade) {
            continue;
        }
        headers.push(HeaderField {
            name: name.as_str().to_owned(),
            value_b64: STANDARD.encode(value.as_bytes()),
        });
    }
    HttpResponseHead {
        status: response.status().as_u16(),
        version: version_string(response.version()).to_owned(),
        headers,
    }
}

pub fn request_is_upgrade(head: &HttpRequestHead) -> bool {
    head.headers.iter().any(|field| field.name.eq_ignore_ascii_case("upgrade"))
}

fn connection_tokens(fields: &[HeaderField]) -> Vec<String> {
    fields
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case("connection"))
        .filter_map(|field| STANDARD.decode(&field.value_b64).ok())
        .filter_map(|value| String::from_utf8(value).ok())
        .flat_map(|value| {
            value.split(',').map(str::trim).map(str::to_ascii_lowercase).collect::<Vec<_>>()
        })
        .collect()
}

fn should_strip(name: &HeaderName, connection_tokens: &[String], preserve_upgrade: bool) -> bool {
    let upgrade_header = name == http::header::CONNECTION || name == http::header::UPGRADE;
    (is_hop_header(name) || connection_tokens.iter().any(|token| token == name.as_str()))
        && !(preserve_upgrade && upgrade_header)
}

fn is_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

const fn version_string(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}

fn parse_version(version: &str) -> Version {
    match version {
        "HTTP/0.9" => Version::HTTP_09,
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/2" => Version::HTTP_2,
        "HTTP/3" => Version::HTTP_3,
        _ => Version::HTTP_11,
    }
}

fn protocol_error(error: impl std::fmt::Display) -> DriverError {
    DriverError::Protocol(error.to_string())
}
