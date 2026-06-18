//! `/api/v1/accounts`: list, create, delete, change password.

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::{AccountView, ApiState};
use crate::directory_store::{DynamicAccount, StoreError};

#[derive(Serialize)]
pub struct Accounts {
	accounts: Vec<AccountView>,
}

pub async fn list(State(state): State<ApiState>) -> Json<Accounts> {
	Json(Accounts {
		accounts: state.accounts(),
	})
}

#[derive(Deserialize)]
pub struct CreateAccount {
	name: String,
	addresses: Vec<String>,
	password: String,
}

#[derive(Serialize)]
pub struct Created {
	created: String,
}

/// Minimum password length accepted by the API.
const MIN_PASSWORD: usize = 12;

pub async fn create(
	State(state): State<ApiState>,
	Json(request): Json<CreateAccount>,
) -> Result<Json<Created>, ApiError> {
	if request.password.len() < MIN_PASSWORD {
		return Err(ApiError::invalid_input(
			"Password must be at least 12 characters.",
		));
	}
	let password_hash =
		crate::smtp::auth::hash_password(&request.password).map_err(|_| ApiError::internal())?;
	state
		.store()
		.add(DynamicAccount {
			name: request.name.clone(),
			addresses: request.addresses,
			password_hash,
			scram: Some(derive_scram(&request.password)),
		})
		.map_err(store_error)?;
	Ok(Json(Created {
		created: request.name,
	}))
}

#[derive(Serialize)]
pub struct Removed {
	removed: String,
}

pub async fn remove(
	State(state): State<ApiState>,
	Path(name): Path<String>,
) -> Result<Json<Removed>, ApiError> {
	state.store().remove(&name).map_err(store_error)?;
	Ok(Json(Removed { removed: name }))
}

#[derive(Deserialize)]
pub struct SetPassword {
	password: String,
}

#[derive(Serialize)]
pub struct PasswordChanged {
	updated: String,
}

pub async fn set_password(
	State(state): State<ApiState>,
	Path(name): Path<String>,
	Json(request): Json<SetPassword>,
) -> Result<Json<PasswordChanged>, ApiError> {
	if request.password.len() < MIN_PASSWORD {
		return Err(ApiError::invalid_input(
			"Password must be at least 12 characters.",
		));
	}
	let hash =
		crate::smtp::auth::hash_password(&request.password).map_err(|_| ApiError::internal())?;
	let scram = derive_scram(&request.password);
	state
		.store()
		.set_password_hash(&name, hash, Some(scram))
		.map_err(store_error)?;
	Ok(Json(PasswordChanged { updated: name }))
}

/// Derive SCRAM-SHA-256 credentials from a plaintext password with a fresh
/// random salt (RFC 7677 minimum 4096 iterations).
fn derive_scram(password: &str) -> crate::smtp::scram::ScramStored {
	use ring::rand::SecureRandom;
	let mut salt = [0u8; 16];
	let _ = ring::rand::SystemRandom::new().fill(&mut salt);
	let credentials = crate::smtp::scram::ScramCredentials::derive(password, &salt, 4096);
	crate::smtp::scram::ScramStored::from_credentials(&credentials)
}

fn store_error(error: StoreError) -> ApiError {
	match error {
		StoreError::Invalid(message) => ApiError::invalid_input(&message),
		StoreError::Duplicate(what) => ApiError::invalid_input(&format!("{what} already exists.")),
		StoreError::NotFound(_) => ApiError::not_found("no such dynamic account"),
		StoreError::Io(_) => ApiError::internal(),
	}
}
