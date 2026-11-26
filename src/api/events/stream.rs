//! The response body: one stream's view of the ring.

use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::response::sse::Event;
use serde_json::json;

use super::hub::Window;
use super::topic::{Topic, visible_at_resync};
use crate::api::Principal;
use crate::api::api_keys::Scope;
use crate::api::jmap::caller_slots::CallerSlot;
use crate::api::state::{ApiState, MatchedAuth};

/// Counts one stream against the server's cap until it is dropped.
pub(super) struct ServerSlot(ApiState);

impl ServerSlot {
	/// `None` when the server holds as many streams as it may.
	pub(super) fn take(state: &ApiState) -> Option<Self> {
		state.events().admit().then(|| Self(state.clone()))
	}
}

impl Drop for ServerSlot {
	fn drop(&mut self) {
		self.0.events().release();
	}
}

/// An open event stream.
pub(super) struct Events {
	state: ApiState,
	auth: MatchedAuth,
	principal: Principal,
	/// The first ring position not yet looked at.
	cursor: u64,
	/// Events ready to send: at most one per topic.
	pending: VecDeque<Event>,
	look: tokio::time::Interval,
	ends: tokio::time::Instant,
	done: bool,
	/// Held while the stream is open and given back the moment it ends.
	slots: Option<(CallerSlot, ServerSlot)>,
}

impl Events {
	/// A stream that starts at `cursor`; with `resync` it first names every
	/// topic the credential may be told about, because it cannot be known
	/// what it missed.
	pub(super) fn open(
		state: ApiState,
		auth: MatchedAuth,
		principal: Principal,
		(cursor, resync): (u64, bool),
		slots: (CallerSlot, ServerSlot),
	) -> Self {
		let hub = state.events();
		let mut pending = VecDeque::new();
		if resync {
			let id = hub.id(hub.head().saturating_sub(1));
			for topic in Topic::ALL {
				if visible_at_resync(topic, &principal) {
					pending.push_back(event(&id, topic));
				}
			}
		}
		let now = tokio::time::Instant::now();
		let every = hub.limits().look;
		let mut look = tokio::time::interval_at(now + every, every);
		look.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
		let ends = now + hub.limits().max_lifetime;
		Self {
			state,
			auth,
			principal,
			cursor,
			pending,
			look,
			ends,
			done: false,
			slots: Some(slots),
		}
	}

	/// Whether the credential that opened the stream still holds: the key is
	/// still there, unchanged, unexpired and with the `read` scope.
	fn still_allowed(&self) -> bool {
		crate::api::jmap::websocket::credential_still_valid(
			&self.state,
			&self.auth,
			&self.principal,
		) && self
			.state
			.require_scope_for_principal(&self.principal, Scope::ManageRead)
			.is_ok()
	}

	/// Read the ring. `false` when this reader fell behind it and is dropped.
	fn read_ring(&mut self) -> bool {
		let hub = self.state.events();
		let (head, window) = hub.since(self.cursor, &self.principal);
		self.cursor = head;
		let Window::Entries(entries) = window else {
			return false;
		};
		// One event per topic, however many times it moved: the last id.
		let mut last: BTreeMap<Topic, u64> = BTreeMap::new();
		for (seq, topic) in entries {
			last.insert(topic, seq);
		}
		let mut ordered: Vec<(u64, Topic)> = last.into_iter().map(|(t, s)| (s, t)).collect();
		ordered.sort();
		for (seq, topic) in ordered {
			self.pending.push_back(event(&hub.id(seq), topic));
		}
		true
	}
}

/// The event for `topic`: its name and nothing about what changed.
fn event(id: &str, topic: Topic) -> Event {
	Event::default()
		.id(id)
		.event(topic.name())
		.data(json!({ "topic": topic.name() }).to_string())
}

impl futures_core::Stream for Events {
	type Item = Result<Event, std::convert::Infallible>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let this = &mut *self;
		loop {
			if this.done {
				return Poll::Ready(None);
			}
			if let Some(event) = this.pending.pop_front() {
				return Poll::Ready(Some(Ok(event)));
			}
			if this.look.poll_tick(cx).is_pending() {
				return Poll::Pending;
			}
			if tokio::time::Instant::now() >= this.ends
				|| !this.still_allowed()
				|| !this.read_ring()
			{
				this.done = true;
				this.slots = None;
			}
		}
	}
}
