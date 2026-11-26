//! For the tests that hold a command to its route: the router a server
//! with a given configuration and resolver serves, and the bearer that
//! reaches everything on it.

use std::sync::Arc;

use crate::config::Config;
use crate::spf::{DnsFailure, DnsLookup};

type Lookup<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

/// A resolver that knows no name, for a route that makes no lookup.
pub(crate) struct Empty;

impl DnsLookup for Empty {
	fn txt(&self, _: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
	fn addresses(&self, _: &str) -> Lookup<'_, Vec<std::net::IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}
	fn mx(&self, _: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// The configured token of the router below.
pub(crate) const TOKEN: &str = "dns-parity-token";

/// `GET path` on the router, as the configured token.
pub(crate) async fn route(
	config: &Config,
	dns: Arc<dyn DnsLookup>,
	path: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
	use tower::ServiceExt;
	let store = Arc::new(
		crate::directory_store::AccountStore::open(
			&config.data_dir,
			config.domains.clone(),
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	let state = crate::api::ApiState::new(
		&crate::api::api_keys::sha256_hash(TOKEN),
		config.data_dir.clone(),
		config.domains.clone(),
		store.clone(),
		crate::storage::FsSpool::open(&config.data_dir).expect("spool"),
	)
	.with_directory(store.handle())
	.with_live_domains(crate::editable::LiveConfig::new(config.clone()))
	.with_dns_lookup(dns);
	let request = axum::http::Request::builder()
		.uri(path)
		.header(axum::http::header::AUTHORIZATION, format!("Bearer {TOKEN}"))
		.body(axum::body::Body::empty())
		.expect("request");
	let response = crate::api::router(state)
		.oneshot(request)
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, serde_json::from_slice(&bytes).expect("JSON"))
}
