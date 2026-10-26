//! An API key bound to one account (`account = "<name>"` in `api_keys.toml`)
//! reaches only the account-scoped surface: JMAP and `/api/v1/send`, where the
//! handlers derive the acting account from the key. Every other route is
//! administrative (accounts, domains, queue, SCIM, ...) and has no notion of
//! "the key's own account", so such a key is refused there with a 403 before
//! the handler runs. Without this the key would be read on those routes like
//! an unconfined one.
//!
//! On the account-scoped surface the key acts for its own account only while
//! that account exists and is not disabled. [`bound_account_is_live`] is the one
//! check for that: [`confine`] runs it on every HTTP request, and the JMAP
//! WebSocket runs it again on every frame of a socket opened before the
//! account went away.
//!
//! The binding is read from the same authorization snapshot every other
//! restriction comes from, so a key bound to one account *and* confined to
//! some domains is confined by both at once.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use super::ApiState;
use super::Principal;
use super::error::ApiError;
use super::state::MatchedAuth;

/// Whether `path` belongs to the surface an account-bound key may use.
pub(crate) fn path_is_account_scoped(path: &str) -> bool {
	path == "/api/v1/send"
		|| path == "/api/v1/deliveries"
		|| path == "/.well-known/jmap"
		|| path.starts_with("/jmap/")
}

/// Whether the account `principal` is bound to can still be acted on: it
/// exists and is not disabled. A principal not bound to one account is not
/// affected. A disabled account keeps its mail, so without this its keys would
/// go on reading and sending as if nothing happened.
pub(crate) fn bound_account_is_live(state: &ApiState, principal: &Principal) -> bool {
	match principal.bound_account() {
		Some(name) => {
			!state.store().is_disabled(name)
				&& state.accounts().iter().any(|account| account.name == name)
		}
		None => true,
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
		// One resolution of the credential, the same one the handlers use:
		// the account binding, the domain binding and the scopes all come
		// from the same key snapshot.
		let principal = Principal::for_token(&state, auth);
		if !path_is_account_scoped(request.uri().path()) {
			if principal.bound_account().is_some() {
				return Err(ApiError::account_bound_route());
			}
		} else if !bound_account_is_live(&state, &principal) {
			return Err(ApiError::bound_account_unavailable());
		}
	}
	Ok(next.run(request).await)
}
