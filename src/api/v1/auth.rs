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

use crate::api::state::{ApiState, ClientIp};

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
	Json(request): Json<VerifyRequest>,
) -> Json<VerifyResponse> {
	match state.authenticate_with_ip(&request.name, &request.password, client_ip.0) {
		Some(resolved) => Json(VerifyResponse {
			valid: true,
			admin: state.is_admin(&resolved),
		}),
		None => Json(VerifyResponse {
			valid: false,
			admin: false,
		}),
	}
}
