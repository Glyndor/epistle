//! `/api/v1/auth`: credential verification for the admin panel.
//!
//! The management API is already bearer-authenticated — only `epistle-panel`,
//! holding the API token server-side, can reach this route. It lets the panel
//! verify an operator's account credentials (and whether that account is a
//! panel admin) so the panel can establish its own admin session, instead of
//! the panel having to hold or hash operator passwords itself.

use axum::Json;
use axum::extract::{Extension, State};
use serde::{Deserialize, Serialize};

use crate::api::domain_scope::DomainScope;
use crate::api::state::{ApiState, ClientIp, MatchedAuth};

/// A credential-verification request.
#[derive(Deserialize)]
pub struct VerifyRequest {
	/// The login name or address to verify.
	name: String,
	/// The plaintext password to check against the stored argon2id hash.
	password: String,
}

/// The result of a credential verification.
#[derive(Serialize)]
pub struct VerifyResponse {
	/// Whether the credentials matched a real account.
	valid: bool,
	/// Whether that account is allowed to administer the panel. Always `false`
	/// when `valid` is `false`.
	admin: bool,
}

/// POST `/auth/verify`: check `{name, password}` against the account directory.
///
/// Returns the same `valid: false` shape for both an unknown account and a
/// wrong password (no user-enumeration oracle), mirroring the mail protocols'
/// authentication. `admin` is set only for a valid account listed in
/// `[api] admins`.
pub async fn verify(
	State(state): State<ApiState>,
	Extension(client_ip): Extension<ClientIp>,
	Extension(auth): Extension<MatchedAuth>,
	Json(request): Json<VerifyRequest>,
) -> Json<VerifyResponse> {
	let refused = Json(VerifyResponse {
		valid: false,
		admin: false,
	});
	// A key confined to some domains checks the passwords of its own
	// tenant's accounts only. For any other login the password is never
	// tried: the answer would tell the key whether another tenant's account
	// has that password, and the attempt would count against the account.
	let scope = state.domain_scope(&auth);
	if !login_in_scope(&state, &scope, &request.name) {
		return refused;
	}
	match state.authenticate_with_ip(
		&request.name,
		&request.password,
		client_ip.0,
		crate::config::Protocol::Api,
	) {
		Some(resolved) if account_in_scope(&state, &scope, &resolved) => Json(VerifyResponse {
			valid: true,
			admin: state.is_admin(&resolved),
		}),
		_ => refused,
	}
}

/// Whether `login` (an account name or one of its addresses) names an account
/// the scope covers. Everything is covered by an unconfined key.
fn login_in_scope(state: &ApiState, scope: &DomainScope, login: &str) -> bool {
	if matches!(scope, DomainScope::All) {
		return true;
	}
	let login = crate::util::address::normalize(login);
	state.accounts().iter().any(|account| {
		(account.name == login
			|| account
				.addresses
				.iter()
				.any(|address| crate::util::address::normalize(address) == login))
			&& scope.admits_account(account.addresses.iter().map(String::as_str))
	})
}

/// Whether the account named `name` is covered by the scope. An unconfined key
/// (the configured token and any API key without `domains`) never filters by
/// account: the post-auth check exists to keep a confined key from confirming
/// the password of another tenant's account, and that risk only exists for
/// scoped keys.
fn account_in_scope(state: &ApiState, scope: &DomainScope, name: &str) -> bool {
	if matches!(scope, DomainScope::All) {
		return true;
	}
	state
		.accounts()
		.iter()
		.find(|account| account.name == name)
		.is_some_and(|account| scope.admits_account(account.addresses.iter().map(String::as_str)))
}
