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
/// Maximum password length: a DoS ceiling on the Argon2 input, generous enough
/// that no real passphrase or password-manager output is rejected.
const MAX_PASSWORD: usize = 64;

/// Enforce the global password length policy (12–64 characters, counted as
/// Unicode scalar values so multibyte input is never silently truncated).
fn check_password(password: &str) -> Result<(), ApiError> {
	let chars = password.chars().count();
	if !(MIN_PASSWORD..=MAX_PASSWORD).contains(&chars) {
		return Err(ApiError::invalid_input(
			"Password must be between 12 and 64 characters.",
		));
	}
	Ok(())
}

pub async fn create(
	State(state): State<ApiState>,
	Json(request): Json<CreateAccount>,
) -> Result<Json<Created>, ApiError> {
	check_password(&request.password)?;
	let password_hash =
		crate::smtp::auth::hash_password(&request.password).map_err(|_| ApiError::internal())?;
	state
		.store()
		.add(DynamicAccount {
			name: request.name.clone(),
			addresses: request.addresses,
			password_hash,
			scram: Some(derive_scram(&request.password)?),
			totp_secret: None,
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
	check_password(&request.password)?;
	let hash =
		crate::smtp::auth::hash_password(&request.password).map_err(|_| ApiError::internal())?;
	let scram = derive_scram(&request.password)?;
	state
		.store()
		.set_password_hash(&name, hash, Some(scram))
		.map_err(store_error)?;
	Ok(Json(PasswordChanged { updated: name }))
}

/// Derive SCRAM-SHA-256 credentials from a plaintext password with a fresh
/// random salt (RFC 7677 minimum 4096 iterations). Fails closed if the CSPRNG
/// cannot produce a salt rather than storing a predictable one.
fn derive_scram(password: &str) -> Result<crate::smtp::scram::ScramStored, ApiError> {
	use ring::rand::SecureRandom;
	let mut salt = [0u8; 16];
	ring::rand::SystemRandom::new()
		.fill(&mut salt)
		.map_err(|_| ApiError::internal())?;
	let credentials = crate::smtp::scram::ScramCredentials::derive(password, &salt, 4096);
	Ok(crate::smtp::scram::ScramStored::from_credentials(
		&credentials,
	))
}

/// The enrolled TOTP secret and its `otpauth://` provisioning URI.
#[derive(Serialize)]
pub struct TotpEnrolled {
	secret: String,
	otpauth_uri: String,
}

/// POST `/accounts/{name}/totp`: generate and store a fresh TOTP secret (2FA).
pub async fn enroll_totp(
	State(state): State<ApiState>,
	Path(name): Path<String>,
) -> Result<Json<TotpEnrolled>, ApiError> {
	use ring::rand::SecureRandom;
	let mut bytes = [0u8; 20];
	ring::rand::SystemRandom::new()
		.fill(&mut bytes)
		.map_err(|_| ApiError::internal())?;
	let secret = crate::totp::encode_base32(&bytes);
	state
		.store()
		.set_totp(&name, Some(secret.clone()))
		.map_err(store_error)?;
	let issuer = state
		.domains()
		.first()
		.map(String::as_str)
		.unwrap_or("mail");
	let otpauth_uri = format!("otpauth://totp/{issuer}:{name}?secret={secret}&issuer={issuer}");
	Ok(Json(TotpEnrolled {
		secret,
		otpauth_uri,
	}))
}

/// DELETE `/accounts/{name}/totp`: disable two-factor auth for the account.
pub async fn disable_totp(
	State(state): State<ApiState>,
	Path(name): Path<String>,
) -> Result<Json<PasswordChanged>, ApiError> {
	state.store().set_totp(&name, None).map_err(store_error)?;
	Ok(Json(PasswordChanged { updated: name }))
}

fn store_error(error: StoreError) -> ApiError {
	match error {
		StoreError::Invalid(message) => ApiError::invalid_input(&message),
		StoreError::Duplicate(what) => ApiError::invalid_input(&format!("{what} already exists.")),
		StoreError::NotFound(_) => ApiError::not_found("no such dynamic account"),
		StoreError::Io(_) => ApiError::internal(),
	}
}
