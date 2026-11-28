//! The credential read again at the moment a write is made.
//!
//! A request that derives a password takes a while between the check of the
//! credential and the write, and then waits for the account store's lock. The
//! write asks again, under that lock, so a key revoked, narrowed or stripped of
//! the scope in between does not write.

use super::Principal;
use crate::api::api_keys::Scope;
use crate::api::state::{ApiState, MatchedAuth};
use crate::directory_store::DynamicAccount;

impl Principal {
	/// Whether the credential of `auth`, read now, holds `scope` and reaches
	/// the account `name` with the addresses `addresses`.
	pub(crate) fn still_reaches_account(
		state: &ApiState,
		auth: &MatchedAuth,
		scope: Scope,
		name: &str,
		addresses: &[String],
	) -> bool {
		let now = Principal::for_token(state, auth);
		now.admits_scope(scope) && now.admits_account(name, addresses)
	}

	/// Whether the credential of `auth`, read now, holds `scope` and is
	/// confined to no account and no domain. Reading it again also asks whether
	/// it has expired and whether the client is still inside its network.
	pub(crate) fn still_unrestricted(state: &ApiState, auth: &MatchedAuth, scope: Scope) -> bool {
		let now = Principal::for_token(state, auth);
		now.admits_scope(scope) && now.is_unrestricted()
	}

	/// Whether the credential of `auth`, read now, holds `scope`, reaches
	/// `account` as it is and may give it the address `address`. A suspended
	/// account's addresses are for an unconfined credential to change.
	pub(crate) fn still_adds_address(
		state: &ApiState,
		auth: &MatchedAuth,
		scope: Scope,
		account: &DynamicAccount,
		address: &str,
	) -> bool {
		let now = Principal::for_token(state, auth);
		now.admits_scope(scope)
			&& now.admits_account(&account.name, &account.addresses)
			&& now.admits_sender(address)
			&& now.admits_suspended(account.disabled)
	}

	/// Whether the credential of `auth`, read now, holds `scope`, reaches
	/// `account` as it is and may take an address off it. A suspended
	/// account's addresses are for an unconfined credential to take.
	pub(crate) fn still_removes_address(
		state: &ApiState,
		auth: &MatchedAuth,
		scope: Scope,
		account: &DynamicAccount,
	) -> bool {
		let now = Principal::for_token(state, auth);
		now.admits_scope(scope)
			&& now.admits_account(&account.name, &account.addresses)
			&& now.admits_suspended(account.disabled)
	}

	/// Whether the credential of `auth`, read now, holds `scope` and may create
	/// an account with the addresses `addresses`.
	pub(crate) fn still_reaches_addresses(
		state: &ApiState,
		auth: &MatchedAuth,
		scope: Scope,
		addresses: &[String],
	) -> bool {
		let now = Principal::for_token(state, auth);
		now.admits_scope(scope) && now.admits_addresses(addresses)
	}
}
