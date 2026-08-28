//! `/api/v1/accounts/{name}/masked`: list, create, update, delete masked
//! email addresses for one account. Read scope for the listing, write scope
//! for create/update/delete (the middleware already enforces the path-based
//! scope; `require_scope` would only matter for an ambiguous POST, which
//! this route is not).

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};

use crate::api::audit::{self, AuditEvent};
use crate::api::error::ApiError;
use crate::api::state::{ApiState, ClientIp};
use crate::directory_store::{MaskedAddressView, StoreError};

/// One row of [`list`]'s response, plus `created` for symmetry with the
/// other endpoints.
#[derive(Serialize)]
pub struct ListResponse {
	addresses: Vec<MaskedAddressView>,
}

/// `GET /api/v1/accounts/{name}/masked`: list every masked address the
/// account owns. Sorted by creation time so the listing is stable.
pub async fn list(
	State(state): State<ApiState>,
	Path(name): Path<String>,
) -> Result<Json<ListResponse>, ApiError> {
	Ok(Json(ListResponse {
		addresses: state.store().list_masked(&name),
	}))
}

#[derive(Deserialize)]
pub struct CreateRequest {
	/// Human-readable label. The address's local part is `<label-slug>.<8
	/// random base32 chars>`; the label itself is preserved verbatim for
	/// display.
	label: String,
}

#[derive(Serialize)]
pub struct CreatedResponse {
	address: String,
}

/// `POST /api/v1/accounts/{name}/masked`: mint a new masked address. The
/// server picks the random suffix; the client only supplies the label.
/// Replies `201 Created` with the freshly minted address.
pub async fn create(
	State(state): State<ApiState>,
	Extension(client_ip): Extension<ClientIp>,
	Path(name): Path<String>,
	Json(request): Json<CreateRequest>,
) -> Result<(axum::http::StatusCode, Json<CreatedResponse>), ApiError> {
	let domain = pick_domain(&state)?;
	let now = unix_now();
	let entry = state
		.store()
		.add_masked(&name, &request.label, domain, now)
		.map_err(map_store_error)?;
	audit::log_privilege_change(AuditEvent::MaskedCreated, &name, client_ip.0);
	Ok((
		axum::http::StatusCode::CREATED,
		Json(CreatedResponse {
			address: entry.address,
		}),
	))
}

#[derive(Deserialize)]
pub struct UpdateRequest {
	enabled: bool,
}

#[derive(Serialize)]
pub struct UpdatedResponse {
	address: String,
	enabled: bool,
}

/// `PATCH /api/v1/accounts/{name}/masked/{address}`: toggle `enabled`.
/// `404` when the address is unknown or belongs to a different account,
/// matching `DELETE`.
pub async fn update(
	State(state): State<ApiState>,
	Extension(client_ip): Extension<ClientIp>,
	Path((name, address)): Path<(String, String)>,
	Json(request): Json<UpdateRequest>,
) -> Result<Json<UpdatedResponse>, ApiError> {
	state
		.store()
		.set_masked_enabled(&name, &address, request.enabled)
		.map_err(map_store_error)?;
	audit::log_privilege_change(AuditEvent::MaskedUpdated, &name, client_ip.0);
	Ok(Json(UpdatedResponse {
		address,
		enabled: request.enabled,
	}))
}

#[derive(Serialize)]
pub struct RemovedResponse {
	removed: String,
}

/// `DELETE /api/v1/accounts/{name}/masked/{address}`: remove the masked
/// address. `404` when the address is unknown or owned by a different
/// account.
pub async fn remove(
	State(state): State<ApiState>,
	Extension(client_ip): Extension<ClientIp>,
	Path((name, address)): Path<(String, String)>,
) -> Result<Json<RemovedResponse>, ApiError> {
	state
		.store()
		.remove_masked(&name, &address)
		.map_err(map_store_error)?;
	audit::log_privilege_change(AuditEvent::MaskedRemoved, &name, client_ip.0);
	Ok(Json(RemovedResponse { removed: address }))
}

/// Pick the first configured domain as the masked address's home. A more
/// sophisticated policy could key the domain off the account's primary
/// address, but the API surfaces one domain at a time and most installs run
/// a single domain; one mask per domain keeps the listing simple and the
/// slug suffix unique.
fn pick_domain(state: &ApiState) -> Result<&str, ApiError> {
	state
		.domains()
		.first()
		.map(String::as_str)
		.ok_or_else(|| ApiError::invalid_input("No domain configured for masked addresses."))
}

/// Map a [`StoreError`] from a masked write to the API surface.
fn map_store_error(error: StoreError) -> ApiError {
	match error {
		StoreError::Invalid(message) => ApiError::invalid_input(&message),
		StoreError::Duplicate(_) => ApiError::invalid_input("address already exists"),
		// A masked `NotFound` is the address being absent or owned by
		// someone else — both collapse to `404` so the endpoint never
		// reveals cross-account addresses.
		StoreError::NotFound(_) => ApiError::not_found("no such masked address"),
		StoreError::LimitReached { max } => {
			ApiError::rate_limited_with(format!("masked-address limit ({max}) reached for account"))
		}
		StoreError::Io(_) => ApiError::internal(),
	}
}

fn unix_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|duration| duration.as_secs())
		.unwrap_or(0)
}
