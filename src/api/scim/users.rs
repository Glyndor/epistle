//! SCIM `/Users` endpoints: list, create, read, replace, patch, delete.
//!
//! All write paths land on the same `AccountStore` the management API uses
//! (`POST /api/v1/accounts`, `DELETE /api/v1/accounts/{name}`), so SCIM and
//! the operator-facing CLI see one consistent account model.
//!
//! `id` is the account login name. SCIM treats it as an opaque identifier;
//! using the same string for `id` and `userName` keeps IdP round trips
//! unambiguous. We do not honour `userName` changes (`PUT` and `PATCH` both
//! reject them): the account name is the directory's primary key, and
//! renaming a primary key would orphan every dependent record (mailbox,
//! quota, scram credentials).

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use super::error::{CONTENT_TYPE, ScimError};
use super::types::{Email, ListResponse, Name, PatchOperation, PatchRequest, USER_SCHEMA, User};
use crate::api::audit::{self, AuditEvent};
use crate::api::state::ApiState;
use crate::directory_store::removal::QueuePolicy;
use crate::directory_store::{DynamicAccount, StoreError};

/// Build a SCIM `User` JSON from a `DynamicAccount` (RFC 7643 §4.1). The
/// `id` is the account name; `active` mirrors `disabled`; `emails` carries
/// every address the account owns. `password` is intentionally never
/// rendered (RFC 7643 §8.2 marks it write-only).
fn render_user(account: &DynamicAccount) -> User {
	let emails: Vec<Email> = account
		.addresses
		.iter()
		.enumerate()
		.map(|(index, value)| Email {
			value: value.clone(),
			r#type: Some(if index == 0 {
				"work".to_string()
			} else {
				"other".to_string()
			}),
			primary: Some(index == 0),
		})
		.collect();
	User {
		id: Some(account.name.clone()),
		schemas: vec![USER_SCHEMA.to_string()],
		external_id: None,
		user_name: account.name.clone(),
		display_name: Some(account.name.clone()),
		active: !account.disabled,
		emails,
		name: Some(Name::default()),
		password: None,
	}
}

/// Wrap a serialisable resource into the SCIM `Content-Type` envelope.
fn scim_resource<T: serde::Serialize>(status: StatusCode, value: T) -> impl IntoResponse {
	let body = serde_json::to_value(value).expect("encode SCIM resource");
	(
		status,
		[(axum::http::header::CONTENT_TYPE, CONTENT_TYPE)],
		Json(body),
	)
}

/// Look up a dynamic account by name. `NotFound` becomes a SCIM 404; any
/// other store error becomes a 500 with no leaked detail.
fn lookup(state: &ApiState, name: &str) -> Result<DynamicAccount, ScimError> {
	state
		.store()
		.dynamic(name)
		.ok_or_else(|| ScimError::not_found(format!("no such user \"{name}\"")))
}

/// Map `StoreError` from a write path into the right SCIM error. `409` for
/// duplicates (the SCIM spec's "userName exists already" case), `404` for
/// unknown targets, `400` for invalid input, `500` for everything else.
fn store_to_scim(error: StoreError) -> ScimError {
	match error {
		StoreError::Duplicate(what) => ScimError::conflict(format!("\"{what}\" already exists")),
		StoreError::NotFound(what) => ScimError::not_found(format!("no such user \"{what}\"")),
		StoreError::Invalid(what) => ScimError::invalid(what),
		StoreError::LimitReached { .. } => ScimError::internal(),
		StoreError::Io(_) => ScimError::internal(),
	}
}

/// Enforce the global password policy via the shared `password` module,
/// mapping any rejection to a SCIM 400 with a non-revealing message.
fn check_password(password: &str) -> Result<(), ScimError> {
	crate::password::validate(password).map_err(|rejection| ScimError::invalid(rejection.message()))
}

/// Derive SCRAM-SHA-256 credentials from a plaintext password with a fresh
/// random salt (RFC 7677 minimum 4096 iterations). Fails closed if the
/// CSPRNG cannot produce a salt rather than storing a predictable one.
fn derive_scram(password: &str) -> Result<crate::smtp::scram::ScramStored, ScimError> {
	crate::smtp::scram::ScramStored::with_fresh_salt(password).ok_or_else(ScimError::internal)
}

/// Hash a plaintext password with the global argon2id KDF. The `password`
/// module has already vetted it; this just hashes it.
fn hash_password(password: &str) -> Result<String, ScimError> {
	crate::smtp::auth::hash_password(password).map_err(|_| ScimError::internal())
}

/// Resolve an account's full delivery list from the SCIM `emails` field.
/// Falls back to `fallback` if the IdP sent an empty list (the RFC permits
/// it; the directory requires at least one address, so we use the existing
/// set on PUT when the IdP omits `emails`).
fn resolve_addresses(emails: &[Email], fallback: &[String]) -> Result<Vec<String>, ScimError> {
	if emails.is_empty() {
		return Ok(fallback.to_vec());
	}
	let mut out: Vec<String> = Vec::with_capacity(emails.len());
	for email in emails {
		let lower = email.value.trim().to_ascii_lowercase();
		if lower.is_empty() {
			return Err(ScimError::invalid("email value must not be empty"));
		}
		if !lower.contains('@') {
			return Err(ScimError::invalid(format!(
				"invalid email \"{}\"",
				email.value
			)));
		}
		out.push(lower);
	}
	Ok(out)
}

/// `GET /Users?filter=userName eq "x"&startIndex=1&count=50`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
	/// RFC 7644 §3.4.2.5 filter expression. We honour only
	/// `userName eq "x"` (case-sensitive value, single user). Anything
	/// else is rejected as 400 — silently ignoring unsupported filters
	/// would hide IdP misconfigurations.
	#[serde(default)]
	filter: Option<String>,
	/// 1-based index of the first result (default 1).
	#[serde(default)]
	start_index: Option<u64>,
	/// Maximum number of results to return (default 100, capped at 200
	/// to match the ServiceProviderConfig declaration).
	#[serde(default)]
	count: Option<u64>,
}

/// Parse `userName eq "value"` exactly. SCIM strings are double-quoted
/// with backslash-escapes; we honour `\"` and `\\` and nothing else.
fn parse_user_name_eq(filter: &str) -> Result<String, ScimError> {
	let trimmed = filter.trim();
	let rest = trimmed.strip_prefix("userName").unwrap_or("").trim();
	let rest = rest
		.strip_prefix("eq")
		.ok_or_else(|| ScimError::invalid("only `userName eq \"x\"` is supported"))?
		.trim();
	let inner = rest
		.strip_prefix('"')
		.ok_or_else(|| ScimError::invalid("filter value must be a quoted string"))?
		.trim_end();
	let inner = inner
		.strip_suffix('"')
		.ok_or_else(|| ScimError::invalid("filter value must be a quoted string"))?;
	let mut out = String::with_capacity(inner.len());
	let mut chars = inner.chars();
	while let Some(c) = chars.next() {
		match c {
			'\\' => match chars.next() {
				Some('"') => out.push('"'),
				Some('\\') => out.push('\\'),
				Some(other) => {
					return Err(ScimError::invalid(format!(
						"unsupported filter escape \"\\{other}\""
					)));
				}
				None => return Err(ScimError::invalid("dangling filter escape")),
			},
			other => out.push(other),
		}
	}
	if out.is_empty() {
		return Err(ScimError::invalid("filter value must not be empty"));
	}
	Ok(out)
}

pub async fn list_users(
	State(state): State<ApiState>,
	Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, ScimError> {
	let start_index = query.start_index.unwrap_or(1).max(1);
	let count = query.count.unwrap_or(100).clamp(1, 200);

	let users: Vec<DynamicAccount> = state.store().dynamic_accounts();

	let matched: Vec<DynamicAccount> = if let Some(filter) = query.filter.as_deref() {
		let needle = parse_user_name_eq(filter)?;
		users
			.into_iter()
			.filter(|account| account.name == needle)
			.collect()
	} else {
		users
	};

	let rendered: Vec<User> = matched
		.iter()
		.skip((start_index.saturating_sub(1)) as usize)
		.take(count as usize)
		.map(render_user)
		.collect();
	let response = ListResponse::single_page(start_index, rendered.len() as u64, rendered);
	Ok(scim_resource(StatusCode::OK, response))
}

/// `POST /Users` — create the account. Returns 201 with the rendered
/// resource on success.
pub async fn create_user(
	State(state): State<ApiState>,
	Json(body): Json<User>,
) -> Result<impl IntoResponse, ScimError> {
	let name = body.user_name.trim().to_string();
	if name.is_empty() {
		return Err(ScimError::invalid("userName must not be empty"));
	}

	let (password_hash, scram) = if let Some(plain) = body.password.as_deref() {
		check_password(plain)?;
		(hash_password(plain)?, Some(derive_scram(plain)?))
	} else {
		// No password supplied: create the account with an inert hash and
		// no SCRAM credentials. The IdP can PATCH `password` later, or the
		// operator can set one through the management API.
		(String::new(), None)
	};

	let addresses = resolve_addresses(&body.emails, &[])?;
	let active = body.active;
	let account = DynamicAccount {
		name,
		addresses,
		password_hash,
		scram,
		totp_secret: None,
		disabled: !active,
		allowed_protocols: None,
	};
	state.store().add(account).map_err(store_to_scim)?;
	let stored = lookup(&state, &body.user_name)?;
	Ok(scim_resource(StatusCode::CREATED, render_user(&stored)))
}

/// `GET /Users/{id}`.
pub async fn get_user(
	State(state): State<ApiState>,
	Path(id): Path<String>,
) -> Result<impl IntoResponse, ScimError> {
	let account = lookup(&state, &id)?;
	Ok(scim_resource(StatusCode::OK, render_user(&account)))
}

/// `DELETE /Users/{id}` returns 204 with no body. Drains the account's
/// queued mail by default (SCIM has no place for an operator to choose
/// between discard and drain, and dropping mail silently is the worse
/// default). Emits the same `account.removed` audit event as the
/// management API so an IdP-driven deletion leaves the same trace as
/// an operator-initiated one.
pub async fn delete_user(
	State(state): State<ApiState>,
	Path(id): Path<String>,
) -> Result<impl IntoResponse, ScimError> {
	let data_dir = state.data_dir().to_path_buf();
	let counts = crate::directory_store::removal::remove_account(
		state.store(),
		state.spool(),
		&data_dir,
		&id,
		QueuePolicy::Drain,
	)
	.map_err(store_to_scim)?;
	audit::log_privilege_change(AuditEvent::AccountRemoved, &id, None);
	audit::log_account_removal(&id, None, &counts);
	Ok(StatusCode::NO_CONTENT)
}

/// `PUT /Users/{id}` — replace the account. We refuse to change `userName`
/// (renames are not supported; see the module doc). Otherwise we honour
/// `active`, `emails`, and the optional `password` extension. Returns 200
/// with the rendered resource.
pub async fn put_user(
	State(state): State<ApiState>,
	Path(id): Path<String>,
	Json(body): Json<User>,
) -> Result<impl IntoResponse, ScimError> {
	let existing = lookup(&state, &id)?;
	if body.user_name != id {
		return Err(ScimError::invalid(
			"userName cannot be changed via PUT; use DELETE then POST",
		));
	}

	if let Some(plain) = body.password.as_deref() {
		check_password(plain)?;
		let hash = hash_password(plain)?;
		let scram = derive_scram(plain)?;
		state
			.store()
			.set_password_hash(&id, hash, Some(scram))
			.map_err(store_to_scim)?;
	}

	let addresses = resolve_addresses(&body.emails, &existing.addresses)?;
	state
		.store()
		.replace_account(
			&id,
			DynamicAccount {
				name: id.clone(),
				addresses,
				password_hash: existing.password_hash.clone(),
				scram: existing.scram.clone(),
				totp_secret: existing.totp_secret.clone(),
				disabled: !body.active,
				allowed_protocols: existing.allowed_protocols.clone(),
			},
		)
		.map_err(store_to_scim)?;
	let stored = lookup(&state, &id)?;
	Ok(scim_resource(StatusCode::OK, render_user(&stored)))
}

/// `PATCH /Users/{id}` — apply a sequence of narrow operations. We
/// accept `replace` (and the equivalent `add` for single-value
/// attributes) on `active` and `password` only. Everything else is 400.
///
/// The SCIM RFC names `remove` and `add` of multi-value attributes as
/// legitimate operations; we do not honour them — the directory has no
/// notion of multi-valued user attributes besides `emails`, and adding
/// individual emails without the IdP first re-issuing the full set
/// invites drift. If an IdP needs to change addresses, the right move is
/// `PUT` with the new full list.
pub async fn patch_user(
	State(state): State<ApiState>,
	Path(id): Path<String>,
	Json(body): Json<PatchRequest>,
) -> Result<impl IntoResponse, ScimError> {
	let _existing = lookup(&state, &id)?;
	for op in &body.operations {
		apply_operation(&state, &id, op)?;
	}
	let stored = lookup(&state, &id)?;
	Ok(scim_resource(StatusCode::OK, render_user(&stored)))
}

fn apply_operation(state: &ApiState, id: &str, op: &PatchOperation) -> Result<(), ScimError> {
	match (op.op.as_str(), op.path.as_deref()) {
		("remove", _) => Err(ScimError::invalid("`remove` operations are not supported")),
		("replace", Some("active")) | ("add", Some("active")) => {
			let active = op
				.value
				.as_bool()
				.ok_or_else(|| ScimError::invalid("active must be a boolean"))?;
			state
				.store()
				.set_disabled(id, !active)
				.map_err(store_to_scim)?;
			Ok(())
		}
		("replace", Some("password")) | ("add", Some("password")) => {
			let plain = op
				.value
				.as_str()
				.ok_or_else(|| ScimError::invalid("password must be a string"))?;
			check_password(plain)?;
			let hash = hash_password(plain)?;
			let scram = derive_scram(plain)?;
			state
				.store()
				.set_password_hash(id, hash, Some(scram))
				.map_err(store_to_scim)?;
			Ok(())
		}
		("replace", Some(path)) | ("add", Some(path)) => Err(ScimError::invalid(format!(
			"`{path}` cannot be modified via PATCH; only `active` and `password` are accepted"
		))),
		("replace", None) | ("add", None) => {
			Err(ScimError::invalid("a `path` is required for replace/add"))
		}
		(other, _) => Err(ScimError::invalid(format!(
			"unsupported PATCH op \"{other}\""
		))),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn filter_parser_accepts_user_name_eq() {
		assert_eq!(
			parse_user_name_eq(r#"userName eq "alice""#).unwrap(),
			"alice"
		);
	}

	#[test]
	fn filter_parser_honours_string_escapes() {
		assert_eq!(parse_user_name_eq(r#"userName eq "a\"b""#).unwrap(), "a\"b");
		assert_eq!(parse_user_name_eq(r#"userName eq "a\\b""#).unwrap(), "a\\b");
	}

	#[test]
	fn filter_parser_rejects_other_expressions() {
		assert!(parse_user_name_eq("displayName eq \"Alice\"").is_err());
		assert!(parse_user_name_eq("userName co \"al\"").is_err());
		assert!(parse_user_name_eq("userName eq alice").is_err());
	}
}
