//! The credential read again at the moment a write is made.
//!
//! A request that derives a password takes a while between the check of the
//! credential and the write, and then waits for the account store's lock. The
//! write asks again, under that lock, so a key revoked, narrowed or stripped of
//! the scope in between does not write.

use super::Principal;
use crate::api::api_keys::Scope;
use crate::api::state::{ApiState, MatchedAuth};

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
