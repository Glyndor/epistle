//! How a `PATCH` is planned and what it leaves the account with.
//!
//! RFC 7644 section 3.5.2: when one operation is not valid the whole request
//! fails, so every operation is checked, and the passwords hashed, before the
//! first one is written. The plan is the result of that check: one checked
//! operation per operation of the request, ready to be written in one go.

use crate::api::scim::error::ScimError;
use crate::api::scim::types::PatchOperation;
use crate::api::state::ApiState;
use crate::directory_store::{AccountChanges, NewPassword};

use super::{check_password, derive_scram, hash_password};

/// One checked operation, ready to be written.
pub(super) enum Step {
	Active(bool),
	Password {
		hash: String,
		scram: Option<crate::smtp::scram::ScramStored>,
	},
	DisplayName(String),
}

/// Check one operation and prepare what it writes.
pub(super) fn plan_operation(state: &ApiState, op: &PatchOperation) -> Result<Step, ScimError> {
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
pub(super) fn gather(plan: Vec<Step>) -> AccountChanges {
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

/// The `active` value the plan leaves the account with: a later operation
/// on the field replaces an earlier one.
pub(super) fn wanted_active(plan: &[Step]) -> Option<bool> {
	plan.iter().rev().find_map(|step| match step {
		Step::Active(active) => Some(*active),
		_ => None,
	})
}

/// Whether the plan replaces the password of the account.
pub(super) fn wants_password(plan: &[Step]) -> bool {
	plan.iter()
		.any(|step| matches!(step, Step::Password { .. }))
}
