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

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::Deserialize;

use super::error::{CONTENT_TYPE, ScimError};
use super::types::{Email, ListResponse, Name, PatchOperation, PatchRequest, USER_SCHEMA, User};
use crate::api::audit::{self, AuditEvent};
use crate::api::domain_scope::DomainScope;
use crate::api::state::{ApiState, MatchedAuth};
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
		display_name: account.display_name.clone(),
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

/// Look up a dynamic account the calling key may act on. A key confined to
/// some domains (`--domain` on `api-key add`) provisions the accounts that sit
/// entirely inside them and nobody else's. An account outside the scope is
/// reported exactly like one that does not exist, so the key cannot learn
/// another tenant's account names from the status code.
fn lookup_in_scope(
	state: &ApiState,
	scope: &DomainScope,
	name: &str,
) -> Result<DynamicAccount, ScimError> {
	let account = lookup(state, name)?;
	if scope.admits_account(account.addresses.iter().map(String::as_str)) {
		Ok(account)
	} else {
		Err(ScimError::not_found(format!("no such user \"{name}\"")))
	}
}

/// Refuse addresses the calling key may not give out: a confined key cannot
/// create or move an account into a domain it was not given.
fn require_addresses_in_scope(scope: &DomainScope, addresses: &[String]) -> Result<(), ScimError> {
	if scope.admits_account(addresses.iter().map(String::as_str)) {
		Ok(())
	} else {
		Err(ScimError::invalid(
			"address outside the domains this key may act on",
		))
	}
}

/// For a confined key, a `userName` that cannot be used answers one way
/// whether it is malformed or already held by an account outside the key's
/// domains. Account names are one namespace for the whole server, so without
/// this the "already exists" answer would let a tenant probe which names
/// the others use. A name held inside the scope still answers `409`, which the
/// key may know. An unconfined key keeps the precise errors.
fn require_name_available(
	state: &ApiState,
	scope: &DomainScope,
	name: &str,
) -> Result<(), ScimError> {
	if matches!(scope, DomainScope::All) {
		return Ok(());
	}
	let held_outside = state.accounts().iter().any(|account| {
		account.name == name && !scope.admits_account(account.addresses.iter().map(String::as_str))
	});
	if held_outside || crate::directory_store::validate_name(name).is_err() {
		return Err(ScimError::invalid("userName is not available"));
	}
	Ok(())
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
		StoreError::BayesPurge { .. } => ScimError::internal(),
	}
}

/// Enforce the global password policy via the shared `password` module,
/// mapping any rejection to a SCIM 400 with a non-revealing message.
fn check_password(password: &str) -> Result<(), ScimError> {
	crate::password::validate(password).map_err(|rejection| ScimError::invalid(rejection.message()))
}

/// Derive SCRAM-SHA-256 credentials from a plaintext password with a fresh
/// random salt. `None` when SCRAM is disabled via `[auth] scram = false`,
/// so a PUT that changes the password for an account that already has a
/// verifier drops the verifier. Fails closed if the CSPRNG cannot produce
/// a salt rather than storing a predictable one. The candidate is
/// NFKC-normalised under the store's password policy first, so a SCRAM
/// verifier derived here matches the proof a SCRAM-SHA-256 client sends
/// after its own SASLprep step (RFC 5802 / RFC 7677).
fn derive_scram(
	password: &str,
	store: &crate::directory_store::AccountStore,
) -> Result<Option<crate::smtp::scram::ScramStored>, ScimError> {
	if !store.scram_enabled() {
		return Ok(None);
	}
	let prepared = store
		.password_policy()
		.prepare(password)
		.map_err(|rejection| ScimError::invalid(rejection.message()))?;
	crate::smtp::scram::ScramStored::with_fresh_salt(prepared.as_ref())
		.map(Some)
		.ok_or_else(ScimError::internal)
}

/// Hash a plaintext password with the global argon2id KDF. The `password`
/// module has already vetted it; this just hashes the policy-prepared
/// bytes so the stored PHC matches what `verify_password` will see after
/// its own prepare step at login-time.
fn hash_password(
	password: &str,
	store: &crate::directory_store::AccountStore,
) -> Result<String, ScimError> {
	let prepared = store
		.password_policy()
		.prepare(password)
		.map_err(|rejection| ScimError::invalid(rejection.message()))?;
	crate::smtp::auth::hash_password(prepared.as_ref()).map_err(|_| ScimError::internal())
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
		let lower = crate::util::address::normalize(&email.value);
		if lower.is_empty() {
			return Err(ScimError::invalid("email value must not be empty"));
		}
		if let Err(why) = crate::util::address_reason::parse(&lower) {
			return Err(ScimError::invalid(format!("email: {why}")));
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
	#[serde(default, alias = "startIndex")]
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
	Extension(auth): Extension<MatchedAuth>,
	Query(query): Query<ListQuery>,
) -> Result<impl IntoResponse, ScimError> {
	let start_index = query.start_index.unwrap_or(1).max(1);
	let count = query.count.unwrap_or(100).min(200);

	let scope = state.domain_scope(&auth);
	let users: Vec<DynamicAccount> = state
		.store()
		.dynamic_accounts()
		.into_iter()
		.filter(|account| scope.admits_account(account.addresses.iter().map(String::as_str)))
		.collect();

	let matched: Vec<DynamicAccount> = if let Some(filter) = query.filter.as_deref() {
		let needle = parse_user_name_eq(filter)?;
		users
			.into_iter()
			.filter(|account| account.name == needle)
			.collect()
	} else {
		users
	};

	let total_results = matched.len() as u64;
	let offset = usize::try_from(start_index.saturating_sub(1)).unwrap_or(usize::MAX);
	let rendered: Vec<User> = matched
		.iter()
		.skip(offset)
		.take(count as usize)
		.map(render_user)
		.collect();
	let response = ListResponse::single_page(start_index, total_results, rendered);
	Ok(scim_resource(StatusCode::OK, response))
}

/// `POST /Users` — create the account. Returns 201 with the rendered
/// resource on success.
pub async fn create_user(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Json(body): Json<User>,
) -> Result<impl IntoResponse, ScimError> {
	let name = crate::directory_store::account_name(&body.user_name);
	if name.is_empty() {
		return Err(ScimError::invalid("userName must not be empty"));
	}
	// The domains and the tenant's account cap are checked before the
	// password, so a caller cannot use the password rejection to probe which
	// addresses another tenant already has.
	let addresses = resolve_addresses(&body.emails, &[])?;
	let scope = state.domain_scope(&auth);
	require_addresses_in_scope(&scope, &addresses)?;
	require_name_available(&state, &scope, &name)?;
	state
		.tenant_limits()
		.check_account_creation(state.store(), &addresses)
		.map_err(ScimError::conflict)?;

	let (password_hash, scram) = if let Some(plain) = body.password.as_deref() {
		check_password(plain)?;
		(
			hash_password(plain, state.store())?,
			derive_scram(plain, state.store())?,
		)
	} else {
		// No password supplied: create the account with an inert hash and
		// no SCRAM credentials. The IdP can PATCH `password` later, or the
		// operator can set one through the management API.
		(String::new(), None)
	};

	let active = body.active;
	let account = DynamicAccount {
		name: name.clone(),
		addresses,
		password_hash,
		scram,
		totp_secret: None,
		disabled: !active,
		quota_bytes: None,
		allowed_protocols: None,
		display_name: body.display_name.clone(),
		..DynamicAccount::default()
	};
	state.store().add(account).map_err(store_to_scim)?;
	let stored = lookup(&state, &name)?;
	Ok(scim_resource(StatusCode::CREATED, render_user(&stored)))
}

/// `GET /Users/{id}`.
pub async fn get_user(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Path(id): Path<String>,
) -> Result<impl IntoResponse, ScimError> {
	let account = lookup_in_scope(&state, &state.domain_scope(&auth), &id)?;
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
	Extension(auth): Extension<MatchedAuth>,
	Path(id): Path<String>,
) -> Result<impl IntoResponse, ScimError> {
	lookup_in_scope(&state, &state.domain_scope(&auth), &id)?;
	let data_dir = state.data_dir().to_path_buf();
	let counts = crate::directory_store::removal::remove_account(
		state.store(),
		state.spool(),
		&data_dir,
		&id,
		QueuePolicy::Drain,
		state.bayes_store(),
	)
	.await
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
	Extension(auth): Extension<MatchedAuth>,
	Path(id): Path<String>,
	Json(body): Json<User>,
) -> Result<impl IntoResponse, ScimError> {
	let scope = state.domain_scope(&auth);
	let existing = lookup_in_scope(&state, &scope, &id)?;
	if crate::directory_store::account_name(&body.user_name) != id {
		return Err(ScimError::invalid(
			"userName cannot be changed via PUT; use DELETE then POST",
		));
	}

	// The new addresses are checked before anything is written, so a refused
	// replace leaves the password as it was.
	let addresses = resolve_addresses(&body.emails, &existing.addresses)?;
	require_addresses_in_scope(&scope, &addresses)?;
	state
		.tenant_limits()
		.check_account_move(state.store(), &existing.addresses, &addresses)
		.map_err(ScimError::conflict)?;
	if let Some(plain) = body.password.as_deref() {
		check_password(plain)?;
		let hash = hash_password(plain, state.store())?;
		let scram = derive_scram(plain, state.store())?;
		state
			.store()
			.set_password_hash(&id, hash, scram)
			.map_err(store_to_scim)?;
	}
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
				quota_bytes: None,
				allowed_protocols: existing.allowed_protocols.clone(),
				display_name: body.display_name.clone(),
				..DynamicAccount::default()
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
	Extension(auth): Extension<MatchedAuth>,
	Path(id): Path<String>,
	Json(body): Json<PatchRequest>,
) -> Result<impl IntoResponse, ScimError> {
	let scope = state.domain_scope(&auth);
	lookup_in_scope(&state, &scope, &id)?;
	for op in &body.operations {
		apply_operation(&state, &id, op)?;
	}
	let stored = lookup_in_scope(&state, &scope, &id)?;
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
			let hash = hash_password(plain, state.store())?;
			let scram = derive_scram(plain, state.store())?;
			state
				.store()
				.set_password_hash(id, hash, scram)
				.map_err(store_to_scim)?;
			Ok(())
		}
		("replace", Some("displayName")) | ("add", Some("displayName")) => {
			let display_name = op.value.as_str().unwrap_or_default();
			state
				.store()
				.set_display_name(id, display_name)
				.map_err(store_to_scim)?;
			Ok(())
		}
		("replace", Some(path)) | ("add", Some(path)) => Err(ScimError::invalid(format!(
			"`{path}` cannot be modified via PATCH; only `active`, `password` and \
			 `displayName` are accepted"
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
