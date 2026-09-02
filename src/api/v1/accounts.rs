//! `/api/v1/accounts`: list, create, delete, change password.

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};

use crate::api::audit::{self, AuditEvent};
use crate::api::domain_scope::DomainScope;
use crate::api::error::ApiError;
use crate::api::state::{AccountView, ApiState, ClientIp, MatchedAuth};
use crate::directory_store::{DynamicAccount, StoreError};

#[derive(Serialize)]
pub struct Accounts {
	accounts: Vec<AccountView>,
}

pub async fn list(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
) -> Json<Accounts> {
	let scope = state.domain_scope(&auth);
	Json(Accounts {
		accounts: state
			.accounts()
			.into_iter()
			.filter(|account| scope.admits_account(account.addresses.iter().map(String::as_str)))
			.collect(),
	})
}

/// Reject a mutation aimed at an account outside the caller's domains.
///
/// The answer is `404`, not `403`: a key confined to one tenant must not be
/// able to enumerate another tenant's account names by reading the status
/// code, so an account it may not touch is indistinguishable from one that
/// does not exist.
fn require_in_scope(state: &ApiState, scope: &DomainScope, name: &str) -> Result<(), ApiError> {
	let known = state
		.accounts()
		.into_iter()
		.find(|account| account.name == name);
	match known {
		Some(account) if scope.admits_account(account.addresses.iter().map(String::as_str)) => {
			Ok(())
		}
		Some(_) => Err(ApiError::not_found("no such account")),
		// Unknown to us: let the store produce its own error, which is what
		// happened before scopes existed.
		None => Ok(()),
	}
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

/// Enforce the global password policy (length, printable-ASCII character set,
/// and rejection of known-breached passwords) via the shared `password` module,
/// mapping any rejection to a `400` with a non-revealing message.
fn check_password(password: &str) -> Result<(), ApiError> {
	crate::password::validate(password)
		.map_err(|rejection| ApiError::invalid_input(rejection.message()))
}

pub async fn create(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Json(request): Json<CreateAccount>,
) -> Result<Json<Created>, ApiError> {
	// Checked before the password, so a caller cannot use the password
	// rejection to probe which addresses another tenant already has.
	let scope = state.domain_scope(&auth);
	if !scope.admits_account(request.addresses.iter().map(String::as_str)) {
		return Err(ApiError::invalid_input(
			"address outside the domains this key may act on",
		));
	}
	// Per-tenant `max_accounts`: a cap waiting will not lift is a `409`, not
	// a `429` (`ApiError::conflict` exists exactly for this). Checked before
	// the password for the same reason as the scope check above.
	if let Err(message) = state
		.tenant_limits()
		.check_account_creation(state.store(), &request.addresses)
	{
		return Err(ApiError::conflict(message));
	}
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
			disabled: false,
			allowed_protocols: None,
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
	Extension(client_ip): Extension<ClientIp>,
	Extension(auth): Extension<MatchedAuth>,
	Path(name): Path<String>,
) -> Result<Json<Removed>, ApiError> {
	require_in_scope(&state, &state.domain_scope(&auth), &name)?;
	state.store().remove(&name).map_err(store_error)?;
	audit::log_privilege_change(AuditEvent::AccountRemoved, &name, client_ip.0);
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
	Extension(client_ip): Extension<ClientIp>,
	Extension(auth): Extension<MatchedAuth>,
	Path(name): Path<String>,
	Json(request): Json<SetPassword>,
) -> Result<Json<PasswordChanged>, ApiError> {
	require_in_scope(&state, &state.domain_scope(&auth), &name)?;
	check_password(&request.password)?;
	let hash =
		crate::smtp::auth::hash_password(&request.password).map_err(|_| ApiError::internal())?;
	let scram = derive_scram(&request.password)?;
	state
		.store()
		.set_password_hash(&name, hash, Some(scram))
		.map_err(store_error)?;
	audit::log_privilege_change(AuditEvent::PasswordReset, &name, client_ip.0);
	Ok(Json(PasswordChanged { updated: name }))
}

/// Derive SCRAM-SHA-256 credentials from a plaintext password with a fresh
/// random salt (RFC 7677 minimum 4096 iterations). Fails closed if the CSPRNG
/// cannot produce a salt rather than storing a predictable one.
fn derive_scram(password: &str) -> Result<crate::smtp::scram::ScramStored, ApiError> {
	crate::smtp::scram::ScramStored::with_fresh_salt(password).ok_or_else(ApiError::internal)
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
	Extension(client_ip): Extension<ClientIp>,
	Extension(auth): Extension<MatchedAuth>,
	Path(name): Path<String>,
) -> Result<Json<TotpEnrolled>, ApiError> {
	require_in_scope(&state, &state.domain_scope(&auth), &name)?;
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
	audit::log_privilege_change(AuditEvent::TotpEnrolled, &name, client_ip.0);
	Ok(Json(TotpEnrolled {
		secret,
		otpauth_uri,
	}))
}

/// DELETE `/accounts/{name}/totp`: disable two-factor auth for the account.
pub async fn disable_totp(
	State(state): State<ApiState>,
	Extension(client_ip): Extension<ClientIp>,
	Extension(auth): Extension<MatchedAuth>,
	Path(name): Path<String>,
) -> Result<Json<PasswordChanged>, ApiError> {
	require_in_scope(&state, &state.domain_scope(&auth), &name)?;
	state.store().set_totp(&name, None).map_err(store_error)?;
	audit::log_privilege_change(AuditEvent::TotpDisabled, &name, client_ip.0);
	Ok(Json(PasswordChanged { updated: name }))
}

fn store_error(error: StoreError) -> ApiError {
	match error {
		StoreError::Invalid(message) => ApiError::invalid_input(&message),
		StoreError::Duplicate(what) => ApiError::invalid_input(&format!("{what} already exists.")),
		StoreError::NotFound(_) => ApiError::not_found("no such dynamic account"),
		StoreError::LimitReached { .. } => ApiError::internal(),
		StoreError::Io(_) => ApiError::internal(),
	}
}
