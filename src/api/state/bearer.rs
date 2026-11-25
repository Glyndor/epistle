//! The bearer middleware: API requests carry the configured token or an API
//! key; JMAP also accepts a local OAuth token. All share the failure limits and argon2 gate
//! described in `auth.rs` and `limiter.rs`.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::super::api_keys::Scope;
use super::super::error::ApiError;
use super::{ApiState, ClientIp, MatchedAuth, auth};

/// Infer the coarse-grained scope the request needs from its method and path.
/// The middleware uses this as a first pass; per-method JMAP handlers
/// (`src/api/jmap/mod.rs::dispatch_request`) tighten it on top.
///
/// Unambiguous routes (`POST /api/v1/send`, `POST /jmap/upload`) get a
/// single-scope slice. `POST /jmap/api` is ambiguous (every method call
/// shares the same path), so the slice accepts any of the mail scopes and
/// `Send` — the dispatcher then enforces the actual scope per method call.
/// The SCIM 2.0 surface under `/scim/v2` is its own damage class; both reads
/// and writes on it require the dedicated `Scim` scope.
///
/// Management (`/api/v1`) and mail (JMAP) are separate: a `manage:` scope
/// never opens JMAP and a `mail:` scope never opens a management route. The
/// routes an account-bound key reaches under `/api/v1` (the delivery log, the
/// suppression list) are mail routes an administrator reads too, so each takes
/// its `mail:` scope or its `manage:` one.
pub(in crate::api) fn acceptable_scopes_for(method: &axum::http::Method, path: &str) -> Vec<Scope> {
	const MAIL: &[Scope] = &[Scope::MailRead, Scope::MailWrite, Scope::Send];
	let reading = matches!(*method, axum::http::Method::GET | axum::http::Method::HEAD);
	if method == axum::http::Method::POST && path == "/api/v1/send" {
		return vec![Scope::Send];
	}
	// Taking a send back is for the key that sent it, or one that may write.
	if method == axum::http::Method::DELETE && path.starts_with("/api/v1/send/") {
		return vec![Scope::Send, Scope::ManageWrite];
	}
	if path.starts_with("/scim/v2") {
		return vec![Scope::Scim];
	}
	// The alias routes redirect mail, so listing them is as much theirs as
	// changing them: only the `alias` scope opens them, whatever the method.
	if path == "/api/v1/aliases" || path.starts_with("/api/v1/aliases/") {
		return vec![Scope::Alias];
	}
	// The ban routes lock clients out and exempt them from every ban: only the
	// `ban` scope opens them, whatever the method.
	if path == "/api/v1/bans" || path.starts_with("/api/v1/bans/") {
		return vec![Scope::Ban];
	}
	// The health routes name the server's listeners, certificates and keys:
	// only the `health` scope opens them.
	if path == "/api/v1/health" || path.starts_with("/api/v1/health/") {
		return vec![Scope::Health];
	}
	// The key routes make and revoke keys: only the `key` scope opens them.
	if path == "/api/v1/keys" || path.starts_with("/api/v1/keys/") {
		return vec![Scope::Key];
	}
	if path.starts_with("/api/v1/") && super::super::account_bound::path_is_account_scoped(path) {
		return if reading {
			vec![Scope::MailRead, Scope::ManageRead]
		} else {
			vec![Scope::MailWrite, Scope::ManageWrite]
		};
	}
	let mail = path == "/.well-known/jmap" || path.starts_with("/jmap/");
	match *method {
		axum::http::Method::GET | axum::http::Method::HEAD => {
			vec![if mail {
				Scope::MailRead
			} else {
				Scope::ManageRead
			}]
		}
		axum::http::Method::POST
		| axum::http::Method::PUT
		| axum::http::Method::DELETE
		| axum::http::Method::PATCH => {
			if path.starts_with("/api/v1/") {
				vec![Scope::ManageWrite]
			} else if path.starts_with("/jmap/upload") {
				vec![Scope::MailWrite]
			} else {
				MAIL.to_vec()
			}
		}
		_ => vec![Scope::ManageWrite],
	}
}

/// What a client turned away because too many credential checks are already
/// waiting is told to wait: a check takes well under a second, so the queue
/// is short-lived.
const ARGON_BUSY_RETRY_SECS: u64 = 1;

/// Longest bearer token considered at all.
const MAX_BEARER_LEN: usize = 1024;

/// Middleware: every request must carry the bearer token.
pub async fn require_bearer_token(
	State(state): State<ApiState>,
	mut request: Request,
	next: Next,
) -> Response {
	// Read `now` once and pass the same value to both the pre-check and the
	// record/reset at the bottom of the request, so a single request can never
	// roll the window between the read and the write.
	let now = std::time::Instant::now();
	let peer = request
		.extensions()
		.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
		.map(|info| info.0);
	let client_ip = state.effective_client_ip(peer, request.headers());
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
			return rate_limited(limiter.retry_after(client_ip, now, false));
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
	// A verified local OAuth identity is confined to JMAP even when the
	// account is an administrator. It never falls through to API-key or
	// configured-token privileges while it authenticates as OAuth.
	let oauth = token_ref.and_then(|t| state.oauth_principal(t, client_ip));
	let oauth_ok = oauth.is_some() && super::super::oauth::is_jmap_path(request.uri().path());
	if let Some(principal) = &oauth
		&& oauth_ok
		&& !acceptable_scopes
			.iter()
			.any(|scope| principal.admits_scope(*scope))
	{
		state
			.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner())
			.refund(client_ip);
		return ApiError::forbidden("The credential does not have the scope this route needs.")
			.into_response();
	}
	// The configured token has every scope; a leaked configured token is
	// admin-equivalent regardless.
	// API keys use a SHA-256 lookup, so a key never pays for the configured
	// token's (possibly argon2) hash.
	let key_ok = oauth.is_none()
		&& token_ref.is_some_and(|t| state.key_authorizes(t, client_ip, &acceptable_scopes));
	// A key that is valid but does not cover this route is not a failed
	// credential: answer 403 and give back the failure this request
	// reserved. Nothing else is checked, so it costs no argon2.
	if oauth.is_none()
		&& !key_ok
		&& token_ref.is_some_and(|t| state.key_lacks_scope(t, client_ip, &acceptable_scopes))
	{
		state
			.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner())
			.refund(client_ip);
		return ApiError::forbidden("This API key does not have the scope this route needs.")
			.into_response();
	}
	let configured = match token_ref {
		Some(t) if !key_ok && oauth.is_none() => {
			match state.bearer_is_configured_async(t, client_ip).await {
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
					return ApiError::rate_limited(ARGON_BUSY_RETRY_SECS).into_response();
				}
			}
		}
		_ => false,
	};
	let authorized = configured || key_ok || oauth_ok;

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
			return rate_limited(limiter.retry_after(client_ip, now, true));
		}
	}

	if !authorized {
		return ApiError::unauthenticated().into_response();
	}
	// Inject the resolved client IP so privileged handlers can attribute
	// their state-changing actions in the audit log.
	request.extensions_mut().insert(ClientIp(client_ip));
	let account_scoped = super::super::account_bound::path_is_account_scoped(request.uri().path());
	// Stash the matched credentials so per-route handlers can apply a
	// fine-grained scope check on top of the coarse path/method inference
	// the middleware just performed.
	request.extensions_mut().insert(MatchedAuth {
		token: token.clone(),
		client_ip,
		configured,
		acceptable_scopes,
		account_scoped,
	});
	next.run(request).await
}

fn rate_limited(seconds: u64) -> Response {
	ApiError::rate_limited(seconds).into_response()
}
