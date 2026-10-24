//! `PUT /api/v1/accounts/{name}/display_name`: set or clear the person's
//! name of a dynamic account. The name is kept as given (trimmed); an empty
//! one clears it.

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};

use super::accounts::{require_in_scope, store_error};
use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};

#[derive(Deserialize)]
pub struct SetDisplayName {
	display_name: String,
}

/// The stored display name, `null` when cleared.
#[derive(Serialize)]
pub struct DisplayName {
	display_name: Option<String>,
}

pub async fn set(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Path(name): Path<String>,
	Json(request): Json<SetDisplayName>,
) -> Result<Json<DisplayName>, ApiError> {
	let principal = Principal::for_token(&state, &auth);
	require_in_scope(&state, &principal, &name)?;
	let display_name = state
		.store()
		.set_display_name(&name, &request.display_name)
		.map_err(store_error)?;
	Ok(Json(DisplayName { display_name }))
}
