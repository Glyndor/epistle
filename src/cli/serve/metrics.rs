//! The `metrics` listener.

use std::sync::Arc;

/// The router of the `metrics` listener: the Prometheus text at `/metrics`.
pub(super) fn router(metrics: Arc<crate::metrics::Metrics>) -> axum::Router {
	axum::Router::new().route(
		"/metrics",
		axum::routing::get(move || {
			let metrics = Arc::clone(&metrics);
			async move {
				(
					[(
						axum::http::header::CONTENT_TYPE,
						"text/plain; version=0.0.4",
					)],
					metrics.render(),
				)
			}
		}),
	)
}
