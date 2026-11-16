//! A request helper that sees the headers and the raw body.

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use tower::ServiceExt;

pub(in crate::api::tests) const PROBLEM: &str = "application/problem+json";

/// One answer: status, headers and the body parsed as JSON.
pub(in crate::api::tests) struct Answer {
	pub status: StatusCode,
	pub headers: HeaderMap,
	pub body: serde_json::Value,
}

impl Answer {
	pub fn header(&self, name: &str) -> Option<&str> {
		self.headers.get(name).and_then(|value| value.to_str().ok())
	}
}

/// Send one request from `peer`, with the optional bearer `token`,
/// `Accept` and JSON body.
pub(in crate::api::tests) async fn call(
	app: &axum::Router,
	method: &str,
	path: &str,
	token: Option<&str>,
	accept: Option<&str>,
	body: Option<serde_json::Value>,
) -> Answer {
	let mut builder = Request::builder().method(method).uri(path);
	if let Some(token) = token {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	if let Some(accept) = accept {
		builder = builder.header(header::ACCEPT, accept);
	}
	let payload = match body {
		Some(json) => {
			builder = builder.header(header::CONTENT_TYPE, "application/json");
			Body::from(json.to_string())
		}
		None => Body::empty(),
	};
	let mut request = builder.body(payload).expect("request");
	request
		.extensions_mut()
		.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
			[198, 51, 100, 7],
			4000,
		))));
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let headers = response.headers().clone();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
	Answer {
		status,
		headers,
		body,
	}
}
