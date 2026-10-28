//! HTTP-01 challenge responder (RFC 8555 §8.3).
//!
//! The CA fetches `http://<domain>/.well-known/acme-challenge/<token>` and
//! expects the challenge's key authorization. The renewal flow publishes the
//! token→key-authorization mapping into the shared store before asking the CA
//! to validate, and removes it afterwards.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;

/// Thread-safe store of pending HTTP-01 key authorizations, keyed by token.
#[derive(Clone, Default)]
pub struct ChallengeStore {
	inner: Arc<RwLock<HashMap<String, String>>>,
}

impl ChallengeStore {
	/// Build an empty store. Equivalent to `ChallengeStore::default()`.
	pub fn new() -> Self {
		Self::default()
	}

	/// Publish a token's key authorization.
	pub fn set(&self, token: &str, key_authorization: &str) {
		self.inner
			.write()
			.expect("challenge lock")
			.insert(token.to_string(), key_authorization.to_string());
	}

	/// Remove a token once its challenge is done.
	pub fn remove(&self, token: &str) {
		self.inner.write().expect("challenge lock").remove(token);
	}

	/// The key authorization for a token, if published.
	pub fn get(&self, token: &str) -> Option<String> {
		self.inner
			.read()
			.expect("challenge lock")
			.get(token)
			.cloned()
	}
}

/// Router serving the ACME HTTP-01 well-known path from `store`.
pub fn router(store: ChallengeStore) -> Router {
	Router::new()
		.route("/.well-known/acme-challenge/{token}", get(serve))
		.with_state(store)
}

async fn serve(State(store): State<ChallengeStore>, Path(token): Path<String>) -> Response {
	match store.get(&token) {
		Some(key_authorization) => (StatusCode::OK, key_authorization),
		None => (StatusCode::NOT_FOUND, String::new()),
	}
}

type Response = (StatusCode, String);

#[cfg(test)]
mod tests;
