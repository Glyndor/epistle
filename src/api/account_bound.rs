//! An API key bound to one account (`account = "<name>"` in `api_keys.toml`)
//! reaches only the account-scoped surface: JMAP and `/api/v1/send`, where the
//! handlers derive the acting account from the key. Every other route is
//! administrative (accounts, domains, queue, SCIM, ...) and has no notion of
//! "the key's own account", so such a key is refused there with a 403 before
//! the handler runs. Without this the key would be read on those routes like
//! an unconfined one.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use super::ApiState;
use super::api_keys::Scope;
use super::error::ApiError;
use super::state::MatchedAuth;

/// Whether `path` belongs to the surface an account-bound key may use.
pub(crate) fn path_is_account_scoped(path: &str) -> bool {
	path == "/api/v1/send" || path == "/.well-known/jmap" || path.starts_with("/jmap/")
}

/// Whether the credentials in `auth` are an API key bound to one account.
/// The configured static token never is.
pub(crate) fn is_account_bound(state: &ApiState, auth: &MatchedAuth) -> bool {
	let Some(token) = auth.token.as_deref() else {
		return false;
	};
	if state.is_configured_token(token) {
		return false;
	}
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	const EVERY_SCOPE: &[Scope] = &[Scope::Read, Scope::Write, Scope::Send, Scope::Scim];
	state
		.api_keys()
		.snapshot()
		.iter()
		.find(|key| key.admits_any(token, auth.client_ip, now, EVERY_SCOPE))
		.is_some_and(|key| key.account.is_some())
}

/// Middleware layered inside the bearer check: refuse an account-bound key on
/// any route outside [`path_is_account_scoped`].
pub(crate) async fn confine(
	State(state): State<ApiState>,
	request: Request,
	next: Next,
) -> Result<Response, ApiError> {
	if !path_is_account_scoped(request.uri().path())
		&& request
			.extensions()
			.get::<MatchedAuth>()
			.is_some_and(|auth| is_account_bound(&state, auth))
	{
		return Err(ApiError::account_bound_route());
	}
	Ok(next.run(request).await)
}
