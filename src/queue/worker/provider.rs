//! Provider connection admission before the connector opens a socket.
//!
//! Every provider connection is counted, so a rate-limit reply observed while
//! other sessions are running prevents any further connection until they drain.
//! A candidate owns its slot until its SMTP session ends or its future drops.

use std::collections::HashMap;
use std::sync::Mutex;

use super::Worker;
use crate::queue::warmup::Group;

#[derive(Default)]
pub(super) struct Connections(Mutex<HashMap<Group, usize>>);

/// One connection slot. Cancellation and panic release it through Drop.
struct Slot<'a> {
	connections: &'a Connections,
	group: Group,
}

impl Connections {
	fn take(&self, group: Group, limited: bool) -> Option<Slot<'_>> {
		let mut counts = self.0.lock().unwrap_or_else(|e| e.into_inner());
		let count = counts.entry(group).or_default();
		if limited && *count > 0 {
			return None;
		}
		*count += 1;
		Some(Slot {
			connections: self,
			group,
		})
	}
}

impl Drop for Slot<'_> {
	fn drop(&mut self) {
		let mut counts = self.connections.0.lock().unwrap_or_else(|e| e.into_inner());
		if let Some(count) = counts.get_mut(&self.group) {
			*count = count.saturating_sub(1);
		}
	}
}

/// A connector may try several hosts; moving to a different provider releases
/// the previous candidate's slot. Rechecking the same group keeps its slot.
#[derive(Default)]
pub(super) struct Admission<'a>(Mutex<Option<Slot<'a>>>);

impl<'a> Admission<'a> {
	pub(super) fn held(&self, worker: &'a Worker, host: &str, now: u64) -> bool {
		let group = Group::of_exchanger(host);
		let holds = worker.holds();
		if holds.provider_held(host, now).is_some() {
			return true;
		}
		let limited = holds.provider_limited(group);
		let mut slot = self.0.lock().unwrap_or_else(|e| e.into_inner());
		if slot.as_ref().is_some_and(|slot| slot.group == group) {
			return false;
		}
		*slot = None;
		if !group.is_provider() {
			return false;
		}
		*slot = worker.provider_connections.take(group, limited);
		slot.is_none()
	}
}

/// Keep the machine marker when Yahoo puts it beyond the stored prose bound.
pub(super) fn hold_reason(reason: &str) -> String {
	let mut short: String = reason.chars().take(200).collect();
	if crate::queue::reply::provider_cause(reason)
		== Some(crate::queue::reply::ProviderCause::YahooThrottle)
		&& crate::queue::reply::provider_cause(&short).is_none()
	{
		short = reason.chars().take(190).collect();
		short.push_str(" [TSS04]");
	}
	short
}

impl Worker {
	/// Keep in-memory admission in step with a persisted (or just observed)
	/// slow-down reply. The next scan rebuilds this from recipient states.
	pub(super) fn remember_slow(&self, slow: &super::conversation::SlowDown) {
		let mut holds = self.holds();
		holds.note(
			slow.domain.clone(),
			slow.until,
			slow.deferrals,
			&slow.reason,
		);
		if let Some(host) = &slow.host {
			holds.note(
				crate::queue::destination::Destination::exchanger(host),
				slow.until,
				slow.deferrals,
				&slow.reason,
			);
		}
	}

	/// Set the minimum pause for provider rate limits, in seconds.
	pub fn with_provider_pause(mut self, seconds: u64) -> Self {
		self.provider_pause_secs = seconds.clamp(1, crate::queue::backoff::MAX_STEP_SECS);
		self
	}
}
