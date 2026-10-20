//! `GET /api/v1/openapi.json`: the OpenAPI 3.1 description of every HTTP
//! route the server registers.
//!
//! The description is written as `openapi.yaml` next to this file, embedded
//! in the binary, and read into JSON the first time it is asked for (the
//! subset it uses is in [`yaml`]). `route_openapi_tests.rs` fails when a
//! route in the code is missing from the file or the file lists one the code
//! does not register, so the description cannot fall behind the router.

use std::sync::OnceLock;

use axum::http::header;
use axum::response::{IntoResponse, Response};

use super::error::ApiError;

mod yaml;

/// The description as written, YAML.
pub(crate) const SOURCE: &str = include_str!("openapi.yaml");

/// The description as JSON, rendered once; `None` when the embedded YAML does
/// not read (a build whose tests did not run).
fn document() -> Option<&'static str> {
	static JSON: OnceLock<Option<String>> = OnceLock::new();
	JSON.get_or_init(|| {
		let value = yaml::parse(SOURCE).ok()?;
		serde_json::to_string(&value).ok()
	})
	.as_deref()
}

/// The embedded description read into JSON, for the tests that check it.
#[cfg(test)]
pub(crate) fn parsed() -> Result<serde_json::Value, String> {
	yaml::parse(SOURCE)
}

/// `GET /api/v1/openapi.json`. Behind the bearer check like the rest of
/// `/api/v1`, with the `read` scope a `GET` needs there.
pub async fn get() -> Result<Response, ApiError> {
	let body = document().ok_or_else(ApiError::internal)?;
	Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

#[cfg(test)]
#[path = "route_openapi_tests.rs"]
mod route_openapi_tests;

#[cfg(test)]
#[path = "openapi_shape_tests.rs"]
mod openapi_shape_tests;
