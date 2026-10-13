//! Per-caller counts of JMAP work in flight: open event-source streams, API
//! requests and uploads. A slot is taken before the work starts and given
//! back when it is dropped, however the work ends (answered, failed, or the
//! client hung up), so a count never leaks.
//!
//! The caller is the identity the push subscriptions are kept under
//! ([`super::push_subscription::owner_of`]): the account a bound credential
//! belongs to, the label of any other key, or the configured token. The
//! Session limits are the user's, so two keys bound to one account share
//! that account's slots.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::api::Principal;
use crate::api::state::ApiState;

/// The kinds of work counted, each against its own limit.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Work {
	/// An open `/jmap/eventsource` stream.
	EventSource,
	/// A `POST /jmap/api` request or a WebSocket `Request` frame
	/// (`maxConcurrentRequests`).
	Request,
	/// A `POST /jmap/upload` request (`maxConcurrentUpload`).
	Upload,
}

impl Work {
	fn tag(self) -> &'static str {
		match self {
			Work::EventSource => "eventsource",
			Work::Request => "request",
			Work::Upload => "upload",
		}
	}
}

/// One unit of work counted against its caller until dropped.
pub(crate) struct CallerSlot {
	slots: Arc<Mutex<HashMap<String, usize>>>,
	key: String,
}

impl CallerSlot {
	/// Take one of the `max` slots of `work` the caller behind `principal`
	/// has, or `None` when all of them are in use.
	///
	/// A credential that no longer maps to a key has no caller identity; all
	/// such requests share one count rather than escaping it.
	pub(crate) fn take(
		state: &ApiState,
		principal: &Principal,
		work: Work,
		max: usize,
	) -> Option<Self> {
		let caller = super::push_subscription::owner_of(state, principal).unwrap_or_default();
		Self::take_for(state, &caller, work, max)
	}

	/// [`Self::take`] for a caller identity already resolved.
	pub(crate) fn take_for(state: &ApiState, caller: &str, work: Work, max: usize) -> Option<Self> {
		let slots = state.caller_slots();
		let key = format!("{}|{caller}", work.tag());
		{
			let mut open = slots.lock().unwrap_or_else(|p| p.into_inner());
			let count = open.entry(key.clone()).or_insert(0);
			if *count >= max {
				return None;
			}
			*count += 1;
		}
		Some(Self { slots, key })
	}
}

impl Drop for CallerSlot {
	fn drop(&mut self) {
		let mut open = self.slots.lock().unwrap_or_else(|p| p.into_inner());
		if let Some(count) = open.get_mut(&self.key) {
			*count = count.saturating_sub(1);
			if *count == 0 {
				open.remove(&self.key);
			}
		}
	}
}
