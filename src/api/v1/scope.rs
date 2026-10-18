//! The two checks every `/api/v1` route with per-tenant data asks of a key
//! that is confined to some domains. The answers are the same everywhere, so
//! they live in one place; `route_rules` lists which routes use which.

use crate::api::domain_scope::DomainScope;
use crate::api::error::ApiError;
use crate::api::state::ApiState;

/// The account `name` must be one the key's domains cover. A key that is not
/// confined passes unchanged, and the route reports an unknown account in its
/// own way. For a confined key an unknown account and an account of another
/// tenant answer the same `404`, so the status code cannot be used to list
/// the other tenants' accounts.
pub(super) fn account_in_scope(
	state: &ApiState,
	scope: &DomainScope,
	name: &str,
) -> Result<(), ApiError> {
	if matches!(scope, DomainScope::All) {
		return Ok(());
	}
	let covered = state
		.store()
		.account_views()
		.into_iter()
		.find(|(known, _, _)| known == name)
		.is_some_and(|(_, addresses, _)| {
			scope.admits_account(addresses.iter().map(String::as_str))
		});
	if covered {
		Ok(())
	} else {
		Err(ApiError::not_found("no such account"))
	}
}

/// A route whose data is shared by every tenant is not for a confined key.
pub(super) fn require_unconfined(scope: &DomainScope, what: &str) -> Result<(), ApiError> {
	if matches!(scope, DomainScope::All) {
		Ok(())
	} else {
		Err(ApiError::forbidden(&format!(
			"{what} is shared by every tenant and is not available to a key confined to some domains."
		)))
	}
}

/// For a confined key, a new account name that cannot be used answers one way
/// whether it is malformed or already held by an account outside the key's
/// domains. Account names are one namespace for the whole server, so the
/// precise "already exists" would let a tenant probe the names the others
/// use. A name held inside the scope keeps the precise answer.
pub(super) fn name_available(
	state: &ApiState,
	scope: &DomainScope,
	name: &str,
) -> Result<(), ApiError> {
	if matches!(scope, DomainScope::All) {
		return Ok(());
	}
	let held_outside = state.accounts().iter().any(|account| {
		account.name == name && !scope.admits_account(account.addresses.iter().map(String::as_str))
	});
	if held_outside || crate::directory_store::validate_name(name).is_err() {
		return Err(ApiError::invalid_input("account name is not available"));
	}
	Ok(())
}
