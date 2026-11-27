//! A ban store in memory that behaves like the PostgreSQL one for what an
//! operator does: bans ordered by subject, a manual ban that moves an
//! existing row, a removal that counts what it cleared, and an allow list
//! that keeps each block once. The tests of the command and of the routes
//! run against it, so the two are held to one store.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use super::super::{AllowPlaced, AllowRoom, Answer, BanAdmin, BanRoom, Placed, StoreError};
use crate::antispam::bans::{BanRow, BanTarget, MANUAL_REASON, UnbanTarget};
use crate::cidr::Cidr;

#[derive(Default)]
struct State {
	/// Subject to reason and end.
	bans: BTreeMap<String, (String, u64)>,
	/// Subject to the failures counted.
	failures: BTreeMap<String, u64>,
	allow: BTreeSet<String>,
	/// Operations that changed something, in order.
	writes: Vec<String>,
	/// Every call made, whatever it did.
	calls: usize,
	broken: bool,
	/// Held after every write that changed something, when a test asks.
	hold: Option<std::sync::Arc<WriteHold>>,
	/// The time and the end of every ban that was put, in order.
	ban_times: Vec<(u64, u64)>,
}

/// A write that has been made and is held before it answers, for a test
/// that has to act in between: it says when a write has been made, and
/// answers only when it is let go.
#[derive(Debug)]
pub(crate) struct WriteHold {
	written: tokio::sync::Semaphore,
	resume: tokio::sync::Semaphore,
}

impl WriteHold {
	/// Wait until a write has been made and is being held. The limit is only
	/// there so that a lost signal fails the test and does not hang it.
	pub(crate) async fn written(&self) {
		tokio::time::timeout(std::time::Duration::from_secs(60), self.written.acquire())
			.await
			.expect("a write was made")
			.expect("open")
			.forget();
	}

	/// Let one held write answer.
	pub(crate) fn resume(&self) {
		self.resume.add_permits(1);
	}

	async fn hold(&self) {
		self.written.add_permits(1);
		self.resume.acquire().await.expect("open").forget();
	}
}

/// The in-memory store.
#[derive(Default)]
pub(crate) struct FakeAdmin {
	state: Mutex<State>,
}

impl std::fmt::Debug for FakeAdmin {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("FakeAdmin")
	}
}

impl FakeAdmin {
	/// A store that has `bans` (subject, reason, end) and `failures`.
	pub(crate) fn with(bans: &[(&str, &str, u64)], failures: &[(&str, u64)]) -> Self {
		let store = FakeAdmin::default();
		{
			let mut state = store.lock();
			for (subject, reason, until) in bans {
				state
					.bans
					.insert((*subject).to_string(), ((*reason).to_string(), *until));
			}
			for (subject, count) in failures {
				state.failures.insert((*subject).to_string(), *count);
			}
		}
		store
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, State> {
		self.state.lock().expect("fake ban store")
	}

	/// Hold every write after it was made, before it answers, until the test
	/// lets it go with [`WriteHold::resume`].
	pub(crate) fn hold_writes(&self) -> std::sync::Arc<WriteHold> {
		let hold = std::sync::Arc::new(WriteHold {
			written: tokio::sync::Semaphore::new(0),
			resume: tokio::sync::Semaphore::new(0),
		});
		self.lock().hold = Some(std::sync::Arc::clone(&hold));
		hold
	}

	/// The time the store was given and the end it was told, for each ban put
	/// in it: the same `now` the end was counted from.
	pub(crate) fn ban_times(&self) -> Vec<(u64, u64)> {
		self.lock().ban_times.clone()
	}

	/// Make every call fail, as a database that is down does.
	pub(crate) fn break_down(&self) {
		self.lock().broken = true;
	}

	/// A ban in force until `until`, put there without going through the rules.
	pub(crate) fn preload_ban(&self, subject: &str, until: u64) {
		self.lock()
			.bans
			.insert(subject.to_string(), ("preloaded".to_string(), until));
	}

	/// A manual ban in force until `until`, as an operator's `ban add` leaves it.
	pub(crate) fn preload_manual(&self, subject: &str, until: u64) {
		self.lock()
			.bans
			.insert(subject.to_string(), (MANUAL_REASON.to_string(), until));
	}

	pub(crate) fn allow_entries(&self, entries: impl IntoIterator<Item = String>) {
		self.lock().allow.extend(entries);
	}

	pub(crate) fn ban_subjects(&self) -> Vec<String> {
		self.lock().bans.keys().cloned().collect()
	}

	pub(crate) fn ban_until(&self, subject: &str) -> Option<u64> {
		self.lock().bans.get(subject).map(|(_, until)| *until)
	}

	pub(crate) fn allowed(&self) -> Vec<String> {
		self.lock().allow.iter().cloned().collect()
	}

	/// What was changed, one line per operation.
	pub(crate) fn writes(&self) -> Vec<String> {
		self.lock().writes.clone()
	}

	pub(crate) fn calls(&self) -> usize {
		self.lock().calls
	}

	fn enter(&self) -> Result<std::sync::MutexGuard<'_, State>, StoreError> {
		let mut state = self.lock();
		state.calls += 1;
		if state.broken {
			return Err(StoreError("database: connection refused".to_string()));
		}
		Ok(state)
	}
}

impl BanAdmin for FakeAdmin {
	fn list_bans(&self, now: u64) -> Answer<'_, Vec<BanRow>> {
		Box::pin(async move {
			let state = self.enter()?;
			Ok(state
				.bans
				.iter()
				.filter(|(_, (_, until))| *until > now)
				.map(|(subject, (reason, until))| BanRow {
					subject: subject.clone(),
					reason: reason.clone(),
					until_secs: *until,
				})
				.collect())
		})
	}

	fn add_ban_within(
		&self,
		target: BanTarget,
		now: u64,
		until: u64,
		room: BanRoom,
	) -> Answer<'_, Placed> {
		Box::pin(async move {
			let hold = {
				let mut state = self.enter()?;
				let subject = target.subject();
				let renews = state
					.bans
					.get(&subject)
					.is_some_and(|(reason, until)| reason == MANUAL_REASON && *until > now);
				if !renews {
					let manual = state
						.bans
						.values()
						.filter(|(reason, until)| reason == MANUAL_REASON && *until > now);
					if manual.clone().count() >= room.max_manual {
						return Ok(Placed::Full("manual bans"));
					}
					let networks = state
						.bans
						.iter()
						.filter(|(subject, (reason, until))| {
							reason == MANUAL_REASON && *until > now && subject.starts_with("cidr:")
						})
						.count();
					if matches!(target, BanTarget::Cidr(_)) && networks >= room.max_networks {
						return Ok(Placed::Full("banned networks"));
					}
				}
				state
					.bans
					.insert(subject, (MANUAL_REASON.to_string(), until));
				state.writes.push(format!("ban {target}"));
				state.ban_times.push((now, until));
				state.hold.clone()
			};
			if let Some(hold) = hold {
				hold.hold().await;
			}
			Ok(Placed::Done)
		})
	}

	fn remove_ban(&self, target: UnbanTarget) -> Answer<'_, (u64, u64)> {
		Box::pin(async move {
			let (counts, hold) = {
				let mut state = self.enter()?;
				let mut bans = 0;
				let mut failures = 0;
				for subject in target.subjects() {
					bans += u64::from(state.bans.remove(&subject).is_some());
					failures += state.failures.remove(&subject).map_or(0, |_| 1);
				}
				if bans + failures > 0 {
					state.writes.push(format!("unban {target}"));
				}
				((bans, failures), state.hold.clone())
			};
			if let Some(hold) = hold
				&& counts.0 + counts.1 > 0
			{
				hold.hold().await;
			}
			Ok(counts)
		})
	}

	fn allow_list(&self) -> Answer<'_, Vec<String>> {
		Box::pin(async move { Ok(self.enter()?.allow.iter().cloned().collect()) })
	}

	fn allow_add_within(&self, cidr: Cidr, room: AllowRoom) -> Answer<'_, AllowPlaced> {
		Box::pin(async move {
			let hold = {
				let mut state = self.enter()?;
				if state.allow.contains(&cidr.to_string()) {
					return Ok(AllowPlaced::Already);
				}
				if state.allow.len() >= room.max_entries {
					return Ok(AllowPlaced::Full("allow-list entries"));
				}
				let networks = state
					.allow
					.iter()
					.filter_map(|entry| Cidr::parse(entry))
					.filter(|entry| !entry.is_host())
					.count();
				if !cidr.is_host() && networks >= room.max_networks {
					return Ok(AllowPlaced::Full("allowed networks"));
				}
				state.allow.insert(cidr.to_string());
				state.writes.push(format!("allow {cidr}"));
				state.hold.clone()
			};
			if let Some(hold) = hold {
				hold.hold().await;
			}
			Ok(AllowPlaced::Added)
		})
	}

	fn allow_remove(&self, cidr: Cidr) -> Answer<'_, bool> {
		Box::pin(async move {
			let (removed, hold) = {
				let mut state = self.enter()?;
				let removed = state.allow.remove(&cidr.to_string());
				if removed {
					state.writes.push(format!("disallow {cidr}"));
				}
				(removed, state.hold.clone())
			};
			if let Some(hold) = hold
				&& removed
			{
				hold.hold().await;
			}
			Ok(removed)
		})
	}
}
