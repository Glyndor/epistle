//! The checks every `/api/v1` route with per-tenant data asks of a key that
//! is confined to some domains. The answers are the same everywhere, so they
//! live in one place; `route_rules` lists which routes use which.

use crate::api::Principal;
use crate::api::api_keys::Scope;
use crate::api::error::ApiError;
use crate::api::state::ApiState;

/// The account `name` must be one the key may act on. An unrestricted key
/// passes unchanged, and the route reports an unknown account in its own
/// way. For a confined key an unknown account and an account of another
/// tenant answer the same `404`, so the status code cannot be used to list
/// the other tenants' accounts.
pub(super) fn account_in_scope(
	state: &ApiState,
	principal: &Principal,
	name: &str,
) -> Result<(), ApiError> {
	if principal.is_unrestricted() {
		return Ok(());
	}
	let covered = state
		.store()
		.account_views()
		.into_iter()
		.find(|(known, _, _)| known == name)
		.is_some_and(|(_, addresses, _)| principal.admits_account(name, &addresses));
	if covered {
		Ok(())
	} else {
		Err(ApiError::not_found("no such account"))
	}
}

/// The routes an account-bound key reaches under a mail scope (the delivery
/// log, the suppression lists) take `scope`, a management scope, from every key
/// that is not bound to one account. The coarse check lets a mail scope in
/// for them because the bound key needs it, and a key that only holds a mail
/// scope must not use that way in to a list that is the server's or a
/// tenant's, or to another account's. A bound key reaches only its own
/// account, which the route resolves.
pub(super) fn require_manage_unless_bound(
	principal: &Principal,
	scope: Scope,
	what: &str,
) -> Result<(), ApiError> {
	if principal.bound_account().is_some() || principal.admits_scope(scope) {
		Ok(())
	} else {
		Err(ApiError::forbidden(&format!(
			"{what} needs the {} scope unless the key is bound to one account.",
			scope.as_str()
		)))
	}
}

/// A route whose data is shared by every tenant is not for a confined key.
pub(super) fn require_unconfined(principal: &Principal, what: &str) -> Result<(), ApiError> {
	if principal.is_unrestricted() {
		Ok(())
	} else {
		Err(ApiError::forbidden(&format!(
			"{what} is shared by every tenant and is not available to a key confined to an account or some domains."
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
	principal: &Principal,
	name: &str,
) -> Result<(), ApiError> {
	if principal.is_unrestricted() {
		return Ok(());
	}
	let held_outside = state.accounts().iter().any(|account| {
		account.name == name && !principal.admits_account(&account.name, &account.addresses)
	});
	if held_outside || crate::directory_store::validate_name(name).is_err() {
		return Err(ApiError::invalid_input("account name is not available"));
	}
	Ok(())
}
