//! SCIM `/Groups` endpoints — not implemented in this release.
//!
//! Groups are deliberately out of scope: this implementation limits itself to
//! `/Users`, and the directory has no notion of group membership yet
//! (multi-target aliases are operator-configured, not user-provisioned).
//! RFC 7644 §3.4 lets a server respond `501 Not Implemented` when a
//! resource type is not supported, so we return a proper SCIM error
//! rather than a 404 (which an IdP would interpret as "Groups endpoint
//! does not exist", a different and confusing state).

use axum::extract::{Path, State};
use axum::response::IntoResponse;

use crate::api::state::ApiState;

use super::error::ScimError;

const DETAIL: &str = "Groups are not supported in this release";

/// `GET /Groups` — 501 with a SCIM error envelope.
pub async fn list_groups() -> impl IntoResponse {
	ScimError::not_implemented(DETAIL).into_response()
}

/// `POST /Groups` — 501.
pub async fn create_group() -> impl IntoResponse {
	ScimError::not_implemented(DETAIL).into_response()
}

/// `GET /Groups/{id}` — 501.
pub async fn get_group(
	State(_state): State<ApiState>,
	Path(_id): Path<String>,
) -> impl IntoResponse {
	ScimError::not_implemented(DETAIL).into_response()
}

/// `PUT /Groups/{id}` — 501.
pub async fn put_group(
	State(_state): State<ApiState>,
	Path(_id): Path<String>,
) -> impl IntoResponse {
	ScimError::not_implemented(DETAIL).into_response()
}

/// `PATCH /Groups/{id}` — 501.
pub async fn patch_group(
	State(_state): State<ApiState>,
	Path(_id): Path<String>,
) -> impl IntoResponse {
	ScimError::not_implemented(DETAIL).into_response()
}

/// `DELETE /Groups/{id}` — 501.
pub async fn delete_group(
	State(_state): State<ApiState>,
	Path(_id): Path<String>,
) -> impl IntoResponse {
	ScimError::not_implemented(DETAIL).into_response()
}
