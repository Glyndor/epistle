//! The SRS keys of the routing sink, replaceable while the server runs: a
//! domain added to the hosted-domain state brings a secret of its own, and
//! its forwarded mail is signed with it from the next message on.

use std::sync::{Arc, RwLock};

use crate::queue::srs::SrsKeys;

/// The keys and the domain SRS addresses are made at, or `None` while SRS is
/// off. Every clone shares the slot.
#[derive(Clone, Default)]
pub struct SrsSlot(Arc<RwLock<Option<SrsInEffect>>>);

/// The keys and the domain they are used at, shared by every reader.
pub(crate) type SrsInEffect = Arc<(SrsKeys, String)>;

impl SrsSlot {
	/// The keys in effect now.
	pub(crate) fn current(&self) -> Option<SrsInEffect> {
		self.0.read().expect("srs slot lock").clone()
	}

	/// Sign and verify with `keys` at `our_domain` from now on, or switch SRS
	/// off with `None`.
	pub fn replace(&self, keys: Option<(SrsKeys, String)>) {
		*self.0.write().expect("srs slot lock") = keys.map(Arc::new);
	}
}
