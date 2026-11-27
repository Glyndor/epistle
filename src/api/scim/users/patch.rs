//! `PATCH /Users/{id}`: how a request is planned and written.
//!
//! RFC 7644 section 3.5.2: when one operation is not valid the whole request
//! fails, so every operation is checked, and the passwords hashed, before the
//! first one is written. The plan is the result of that check: one checked
//! operation per operation of the request, ready to be written in one go.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};

use crate::api::Principal;
use crate::api::api_keys::Scope;
use crate::api::scim::error::ScimError;
use crate::api::scim::types::{PatchOperation, PatchRequest};
use crate::api::state::{ApiState, ClientIp, MatchedAuth};
use crate::directory_store::{AccountChanges, NewPassword};

use super::audit::Changes;
use super::{
	check_password, derive_scram, hash_password, lookup_in_scope, render_user, scim_resource,
	store_to_scim,
};

/// One checked operation, ready to be written.
enum Step {
	Active(bool),
	Password {
		hash: String,
		scram: Option<crate::smtp::scram::ScramStored>,
	},
	DisplayName(String),
}

/// Check one operation and prepare what it writes.
fn plan_operation(state: &ApiState, op: &PatchOperation) -> Result<Step, ScimError> {
	match (op.op.as_str(), op.path.as_deref()) {
		("remove", _) => Err(ScimError::invalid("`remove` operations are not supported")),
		("replace", Some("active")) | ("add", Some("active")) => op
			.value
			.as_bool()
			.map(Step::Active)
			.ok_or_else(|| ScimError::invalid("active must be a boolean")),
		("replace", Some("password")) | ("add", Some("password")) => {
			let plain = op
				.value
				.as_str()
				.ok_or_else(|| ScimError::invalid("password must be a string"))?;
			check_password(plain)?;
			let hash = hash_password(plain, state.store())?;
			let scram = derive_scram(plain, state.store())?;
			Ok(Step::Password { hash, scram })
		}
		// Checked here, operation by operation: a later one on the same field
		// replaces its value, which must not spare it the check.
		("replace", Some("displayName")) | ("add", Some("displayName")) => {
			let raw = op.value.as_str().unwrap_or_default();
			crate::directory_store::display_name::validate(raw).map_err(ScimError::invalid)?;
			Ok(Step::DisplayName(raw.to_string()))
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

/// The changes of `plan`, in order: a later operation on a field replaces an
/// earlier one.
fn gather(plan: Vec<Step>) -> AccountChanges {
	let mut changes = AccountChanges::default();
	for step in plan {
		match step {
			Step::Active(active) => changes.disabled = Some(!active),
			Step::Password { hash, scram } => {
				changes.password = Some(NewPassword { hash, scram });
			}
			Step::DisplayName(name) => changes.display_name = Some(name),
		}
	}
	changes
}

/// The most operations one `PATCH` may carry. The narrow set this API honours
/// needs a handful; the rest of a large request is a request to loop.
const MAX_PATCH_OPERATIONS: usize = 20;

/// The most password changes one `PATCH` may carry: each is an Argon2 hash and
/// a 600000 round SCRAM derivation.
const MAX_PATCH_PASSWORDS: usize = 3;

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
	Extension(client_ip): Extension<ClientIp>,
	Path(id): Path<String>,
	Json(body): Json<PatchRequest>,
) -> Result<impl IntoResponse, ScimError> {
	let principal = Principal::for_token(&state, &auth);
	lookup_in_scope(&state, &principal, &id)?;
	if body.operations.len() > MAX_PATCH_OPERATIONS {
		return Err(ScimError::invalid(format!(
			"a PATCH takes at most {MAX_PATCH_OPERATIONS} operations"
		)));
	}
	// A password costs two key derivations, so the cap on them is lower than
	// the cap on operations.
	let passwords = body
		.operations
		.iter()
		.filter(|op| op.path.as_deref() == Some("password"))
		.count();
	if passwords > MAX_PATCH_PASSWORDS {
		return Err(ScimError::invalid(format!(
			"a PATCH takes at most {MAX_PATCH_PASSWORDS} password changes"
		)));
	}
	// RFC 7644 section 3.5.2: when one operation is not valid the whole request
	// fails, so every operation is checked, and the passwords hashed, before
	// the first one is written.
	let mut plan = Vec::new();
	for op in &body.operations {
		plan.push(plan_operation(&state, op)?);
	}
	// The plan is written in one go. The key is read again and asked about the
	// account as it is under the store's lock: both were last checked before
	// the passwords were hashed.
	if !plan.is_empty() {
		let wanted = gather(plan);
		let disabled = wanted.disabled;
		let password_sent = wanted.password.is_some();
		let previous = state
			.store()
			.change_account_if(&id, wanted, |account| {
				Principal::still_reaches_account(
					&state,
					&auth,
					Scope::Scim,
					&account.name,
					&account.addresses,
				)
			})
			.map_err(store_to_scim)?;
		// The account is written: the line of every change it made follows,
		// on this task and before anything else can be awaited. A password is
		// a change whenever it is sent: the stored verifier, its salt and the
		// SCRAM credentials are replaced, and the account's outstanding
		// credentials are reset. The state is a change only when the write
		// found another one, so a `PATCH` that asks for the account as it is
		// writes no line.
		let mut changes = Changes::new(&id, principal.key_label(), client_ip.0);
		if password_sent {
			changes.password();
		}
		if let Some(disabled) = disabled {
			changes.state(previous.disabled, disabled);
		}
		changes.write();
	}
	let stored = lookup_in_scope(&state, &principal, &id)?;
	Ok(scim_resource(StatusCode::OK, render_user(&stored)))
}
