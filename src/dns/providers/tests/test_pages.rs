//! A server that answers each request with a body the test chooses by path
//! and by how many requests came before it, for listings whose pages say
//! something about themselves (a total, a next link).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::{StatusCode, Uri, header};
use axum::response::IntoResponse;

/// Start the server. `answer(base, path_and_query, n)` returns the body (and
/// a `Link` header value, if any) for the `n`th request, counted from 0.
/// Returns the base URL and the number of requests served.
pub(crate) async fn serve_by<F>(answer: F) -> (String, Arc<AtomicUsize>)
where
	F: Fn(&str, &str, usize) -> (String, Option<String>) + Send + Sync + 'static,
{
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let base = format!("http://{}", listener.local_addr().expect("addr"));
	let hits = Arc::new(AtomicUsize::new(0));
	let (served, own_base) = (hits.clone(), base.clone());
	let answer = Arc::new(answer);
	let app = axum::Router::new().fallback(move |uri: Uri| {
		let n = served.fetch_add(1, Ordering::SeqCst);
		let path = uri.path_and_query().map_or("", |p| p.as_str()).to_string();
		let (body, link) = answer(&own_base, &path, n);
		async move {
			let mut response = (
				StatusCode::OK,
				[(header::CONTENT_TYPE, "application/json")],
				body,
			)
				.into_response();
			if let Some(link) = link {
				response
					.headers_mut()
					.insert(header::LINK, link.parse().expect("header value"));
			}
			response
		}
	});
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	(base, hits)
}
