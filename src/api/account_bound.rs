//! An API key bound to one account (`account = "<name>"` in `api_keys.toml`)
//! reaches only the account-scoped surface: JMAP and `/api/v1/send`, where the
//! handlers derive the acting account from the key. Every other route is
//! administrative (accounts, domains, queue, SCIM, ...) and has no notion of
//! "the key's own account", so such a key is refused there with a 403 before
//! the handler runs. Without this the key would be read on those routes like
//! an unconfined one.
//!
//! On the account-scoped surface the key acts for its account only while that
//! account exists and is not disabled. [`bound_account_is_live`] is the one
//! check for that: [`confine`] runs it on every HTTP request, and the JMAP
//! WebSocket runs it again on every frame of a socket opened before the
//! account went away.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use super::ApiState;
use super::Principal;
use super::api_keys::Scope;
use super::error::ApiError;
use super::state::MatchedAuth;

/// Whether `path` belongs to the surface an account-bound key may use.
pub(crate) fn path_is_account_scoped(path: &str) -> bool {
	path == "/api/v1/send"
		|| path == "/api/v1/deliveries"
		|| path == "/.well-known/jmap"
		|| path.starts_with("/jmap/")
}

/// Whether the credentials in `auth` are an API key bound to one account.
/// The configured static token never is.
pub(crate) fn is_account_bound(state: &ApiState, auth: &MatchedAuth) -> bool {
	let Some(token) = auth.token.as_deref() else {
		return false;
	};
	if auth.configured {
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

/// Whether the account `principal` is bound to can still be acted on: it
/// exists and is not disabled. A principal not bound to one account is not
/// affected. A disabled account keeps its mail, so without this its keys would
/// go on reading and sending as if nothing happened.
pub(crate) fn bound_account_is_live(state: &ApiState, principal: &Principal) -> bool {
	match principal {
		Principal::Account { name, .. } => {
			!state.store().is_disabled(name)
				&& state.accounts().iter().any(|account| &account.name == name)
		}
		_ => true,
	}
}

/// Middleware layered inside the bearer check: refuse an account-bound key on
/// any route outside [`path_is_account_scoped`], and on the routes inside it
/// once its account is disabled or removed.
pub(crate) async fn confine(
	State(state): State<ApiState>,
	request: Request,
	next: Next,
) -> Result<Response, ApiError> {
	if let Some(auth) = request.extensions().get::<MatchedAuth>() {
		if !path_is_account_scoped(request.uri().path()) {
			if is_account_bound(&state, auth) {
				return Err(ApiError::account_bound_route());
			}
		} else if !bound_account_is_live(&state, &Principal::for_token(&state, auth)) {
			return Err(ApiError::bound_account_unavailable());
		}
	}
	Ok(next.run(request).await)
}
