//! What a suspended account is closed to. The operator suspended it, so a
//! credential confined to domains does not resume it, remove it (its names
//! would be free to take) or change its addresses. An unconfined one does all
//! three.
//!
//! A write asks this under the account store's lock, with the account the file
//! holds and the credential read again there. A route also asks it earlier, to
//! refuse before it does any work.

use std::collections::HashSet;

use super::Principal;

/// The refusal of a resumption.
pub(in crate::api) const RESUMING: &str =
	"resuming an account is for a key that is not confined to an account or some domains.";

/// The refusal of the removal of a suspended account.
pub(in crate::api) const REMOVING: &str =
	"removing a suspended account is for a key that is not confined to an account or some domains.";

/// The refusal of a change to the addresses of a suspended account.
pub(in crate::api) const READDRESSING: &str = "changing the addresses of a suspended account is for a key that is not confined to an account or some domains.";

impl Principal {
	/// Whether the credential may resume, remove or readdress an account that
	/// is suspended or not, as `suspended` says.
	pub(in crate::api) fn admits_suspended(&self, suspended: bool) -> bool {
		!suspended || self.is_unrestricted()
	}
}

/// What replacing an account that holds the addresses `held` would undo of a
/// suspension, as the refusal of it, when the replacement is `disabled` and
/// holds `wanted`. `None` when it leaves a suspension as it is.
///
/// Both lists hold addresses in their stored form. They are compared as the
/// account file keeps them: one of each, in their order, since the first is the
/// one the account is known by.
pub(in crate::api) fn undone_by_replacement(
	disabled: bool,
	held: &[String],
	wanted: &[String],
) -> Option<&'static str> {
	if !disabled {
		Some(RESUMING)
	} else if as_kept(held) != as_kept(wanted) {
		Some(READDRESSING)
	} else {
		None
	}
}

fn as_kept(addresses: &[String]) -> Vec<&str> {
	let mut seen = HashSet::new();
	addresses
		.iter()
		.map(String::as_str)
		.filter(|address| seen.insert(*address))
		.collect()
}
