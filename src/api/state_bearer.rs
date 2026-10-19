//! The bearer middleware: every API request must carry the configured token or
//! an API key, subject to the per-client failure limits and the argon2 gate
//! described in `state_auth.rs` and `state_limiter.rs`.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use super::super::api_keys::Scope;
use super::super::error::ApiError;
use super::{ApiState, ClientIp, MatchedAuth, auth};

/// Infer the coarse-grained scope the request needs from its method and path.
/// The middleware uses this as a first pass; per-method JMAP handlers
/// (`src/api/jmap/mod.rs::dispatch_request`) tighten it on top.
///
/// Unambiguous routes (`POST /api/v1/send`, `POST /jmap/upload`) get a
/// single-scope slice. `POST /jmap/api` is ambiguous (every method call
/// shares the same path), so the slice accepts any of `Read`/`Write`/`Send`
/// — the dispatcher then enforces the actual scope per method call. The
/// SCIM 2.0 surface under `/scim/v2` is its own damage class; both reads
/// and writes on it require the dedicated `Scim` scope.
pub(in crate::api) fn acceptable_scopes_for(method: &axum::http::Method, path: &str) -> Vec<Scope> {
	const ALL: &[Scope] = &[Scope::Read, Scope::Write, Scope::Send];
	if method == axum::http::Method::POST && path == "/api/v1/send" {
		return vec![Scope::Send];
	}
	if path.starts_with("/scim/v2") {
		return vec![Scope::Scim];
	}
	match *method {
		axum::http::Method::GET | axum::http::Method::HEAD => vec![Scope::Read],
		axum::http::Method::POST
		| axum::http::Method::PUT
		| axum::http::Method::DELETE
		| axum::http::Method::PATCH => {
			if path.starts_with("/api/v1/") || path.starts_with("/jmap/upload") {
				vec![Scope::Write]
			} else {
				ALL.to_vec()
			}
		}
		_ => vec![Scope::Write],
	}
}

/// Longest bearer token considered at all.
const MAX_BEARER_LEN: usize = 1024;

/// Middleware: every request must carry the bearer token.
pub async fn require_bearer_token(
	State(state): State<ApiState>,
	mut request: Request,
	next: Next,
) -> Result<Response, ApiError> {
	// Read `now` once and pass the same value to both the pre-check and the
	// record/reset at the bottom of the request, so a single request can never
	// roll the window between the read and the write.
	let now = std::time::Instant::now();
	// The client IP for API-key CIDR allowlists and for the failure limit.
	// `ConnectInfo` is present when the router is served with
	// `into_make_service_with_connect_info`; absent (e.g. in tests) it is
	// `None`, so an IP-restricted key cannot match and every such request
	// shares one failure budget.
	// A dual-stack `::` listener reports an IPv4 peer as `::ffff:a.b.c.d`;
	// canonicalize here so an operator who pinned `192.0.2.0/24` on their key
	// still gets matched by an IPv4 client that connected through the dual-stack
	// bind. The audit channel uses the same canonical form.
	let client_ip = request
		.extensions()
		.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
		.map(|info| crate::net::canonical_peer(info.0).ip());
	// Reject before any token work when this client's failure budget is
	// exhausted, and reserve one failure under the same lock: requests that
	// arrive together would all pass a bare check before any was counted. The
	// reservation is given back below if the token proves valid.
	{
		let mut limiter = state
			.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		if !limiter.reserve(client_ip, now) {
			return Err(ApiError::rate_limited());
		}
	}

	let token = request
		.headers()
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.strip_prefix("Bearer "))
		// Nothing a key or the configured token can be: refused before any
		// hashing, so oversized junk costs a comparison of lengths.
		.filter(|value| !value.is_empty() && value.len() <= MAX_BEARER_LEN)
		.map(str::to_owned);

	// Coarse-grained scope from the request line: the per-route JMAP handlers
	// apply their own fine-grained check on top of this. Unambiguous
	// mutators (e.g. POST /api/v1/send, POST /jmap/upload) are caught here;
	// ambiguous routes (POST /jmap/api) accept any scoped key and let the
	// dispatcher decide per method call.
	let acceptable_scopes = acceptable_scopes_for(request.method(), request.uri().path());
	let token_ref = token.as_deref();
	// The configured token has every scope; a leaked configured token is
	// admin-equivalent regardless.
	// API keys first: a SHA-256 lookup, so a key never pays for the configured
	// token's (possibly argon2) hash.
	let key_ok = token_ref.is_some_and(|t| state.key_authorizes(t, client_ip, &acceptable_scopes));
	let configured = match token_ref {
		Some(t) if !key_ok => match state.bearer_is_configured_async(t, client_ip).await {
			Ok(answer) => answer,
			// Too many guesses are already waiting for an argon2: tell this
			// one to come back. Nothing was checked, so it was no failed
			// credential and the failure it reserved is given back: otherwise
			// a flood that fills the queue would run good clients into
			// their limit.
			Err(auth::ArgonBusy) => {
				state
					.inner
					.auth_limiter
					.lock()
					.unwrap_or_else(|p| p.into_inner())
					.refund(client_ip);
				return Err(ApiError::rate_limited());
			}
		},
		_ => false,
	};
	let authorized = configured || key_ok;

	{
		let mut limiter = state
			.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		// A valid call gives back only the failure it reserved, not the
		// client's earlier ones: someone holding one key of their own could
		// otherwise guess, call and guess again.
		if authorized {
			limiter.refund(client_ip);
		}
		// Only a request that failed is asked about the /48 and the global
		// ceiling; a valid token is never refused for other people's failures.
		if !authorized && limiter.limited_after_failure(client_ip, now) {
			return Err(ApiError::rate_limited());
		}
	}

	if !authorized {
		return Err(ApiError::unauthenticated());
	}
	// Inject the resolved client IP so privileged handlers can attribute
	// their state-changing actions in the audit log.
	request.extensions_mut().insert(ClientIp(client_ip));
	// Stash the matched credentials so per-route handlers can apply a
	// fine-grained scope check on top of the coarse path/method inference
	// the middleware just performed.
	request.extensions_mut().insert(MatchedAuth {
		token: token.clone(),
		client_ip,
		configured,
	});
	Ok(next.run(request).await)
}
