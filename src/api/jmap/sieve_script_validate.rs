//! `SieveScript/validate` (RFC 9661 section 2.6): check a script without
//! storing it. Same check as ManageSieve's CHECKSCRIPT and as a `/set`.

use serde_json::{Value, json};

use super::super::Principal;
use super::super::state::ApiState;
use super::sieve_content::Unusable;
use super::sieve_script::method_error;
use super::uploads::Uploads;

/// `SieveScript/validate`.
pub(crate) fn validate(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
	uploads: &Uploads,
) -> Value {
	let account = match super::state::admitted_account(state, principal, args, call_id) {
		Ok(account) => account,
		Err(error) => return error,
	};
	let Some(blob_id) = args.get("blobId").and_then(Value::as_str) else {
		return method_error("invalidArguments", call_id);
	};
	let verdict = uploads.script(&account, blob_id);
	let error = match &verdict.script {
		Err(Unusable::NotFound) => return method_error("blobNotFound", call_id),
		Err(Unusable::Error(error)) => error.clone(),
		Ok(_) => Value::Null,
	};
	json!(["SieveScript/validate", { "accountId": account, "error": error }, call_id])
}
