//! The one task that notices changes, while any stream is open.
//!
//! Nothing in the server announces a change to the queue, the lists or the
//! directory, and none of them is made to: the task reads a cheap
//! fingerprint of each every `sample` interval and appends a notification when one
//! moved. A burst inside the window is one notification, which is the
//! coalescing. With no stream open the task is not running at all.

use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;

use super::topic::{Reach, Topic};
use crate::api::state::ApiState;

/// The most notifications one topic gets in one window: a mass change is
/// split in this many, never more, so one window cannot fill the ring.
const MAX_CHUNKS: usize = 16;
/// The fewest names one notification covers when a change is split.
const MIN_CHUNK: usize = 32;

/// The fingerprints of everything a topic watches. A fingerprint that could
/// not be read is `None`, which never counts as a change.
pub(super) struct Sample {
	queue: Option<u64>,
	deliveries: Option<u64>,
	suppression: Option<u64>,
	domains: BTreeMap<String, u64>,
	accounts: BTreeMap<String, (u64, Vec<String>)>,
}

fn hashed(value: impl Hash) -> u64 {
	let mut hasher = DefaultHasher::new();
	value.hash(&mut hasher);
	hasher.finish()
}

/// A fingerprint of a directory: its entry count and modification time move
/// when something is added to it or removed from it.
fn stamp(path: &Path) -> u64 {
	let Ok(meta) = std::fs::metadata(path) else {
		return 0;
	};
	let modified = meta
		.modified()
		.ok()
		.and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
		.map_or(0, |elapsed| elapsed.as_nanos());
	hashed((meta.len(), modified))
}

/// A fingerprint of the files of a directory: name, size and modification
/// time of each, so an append to a log moves it.
fn file_stamps(dir: &Path) -> u64 {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return 0;
	};
	let mut names: Vec<_> = entries
		.flatten()
		.map(|entry| (entry.file_name(), stamp(&entry.path())))
		.collect();
	names.sort();
	hashed(names)
}

impl Sample {
	/// Read the fingerprints. Blocking: it lists directories.
	pub(super) fn take(state: &ApiState) -> Self {
		let queue = state.spool().list().ok().map(hashed);
		let deliveries = (state.delivery_log_days().unwrap_or(0) > 0)
			.then(|| file_stamps(&state.data_dir().join("deliverylog")));
		let suppression = {
			let root = state.data_dir().join("suppression");
			let accounts = root.join("accounts");
			Some(hashed((
				stamp(&root),
				stamp(&accounts),
				file_stamps(&accounts),
			)))
		};
		let domains = state
			.domain_catalog()
			.rows()
			.into_iter()
			.map(|row| (row.domain.to_ascii_lowercase(), hashed(format!("{row:?}"))))
			.collect::<BTreeMap<_, _>>();
		let accounts = state
			.accounts()
			.into_iter()
			.map(|account| {
				let locked = state.store().is_locked(&account.name);
				let fingerprint = hashed((
					&account.display_name,
					&account.addresses,
					account.dynamic,
					locked,
				));
				(account.name, (fingerprint, account.addresses))
			})
			.collect();
		Self {
			queue,
			deliveries,
			suppression,
			domains,
			accounts,
		}
	}
}

#[cfg(test)]
impl Sample {
	/// A sample with the given queue fingerprint, domains and accounts.
	pub(super) fn for_test(
		queue: u64,
		domains: &[(&str, u64)],
		accounts: &[(&str, u64, &[&str])],
	) -> Self {
		Self::for_test_owned(
			queue,
			domains.iter().map(|(n, f)| (n.to_string(), *f)).collect(),
			accounts
				.iter()
				.map(|(n, f, a)| (n.to_string(), *f, a.iter().map(|s| s.to_string()).collect()))
				.collect(),
		)
	}

	/// [`Self::for_test`] for values already owned.
	pub(super) fn for_test_owned(
		queue: u64,
		domains: Vec<(String, u64)>,
		accounts: Vec<(String, u64, Vec<String>)>,
	) -> Self {
		Self {
			queue: Some(queue),
			deliveries: None,
			suppression: None,
			domains: domains.into_iter().collect(),
			accounts: accounts
				.into_iter()
				.map(|(name, fingerprint, addresses)| (name, (fingerprint, addresses)))
				.collect(),
		}
	}
}

/// Whether a fingerprint moved. One that could not be read, now or before,
/// did not.
fn moved(before: Option<u64>, now: Option<u64>) -> bool {
	matches!((before, now), (Some(a), Some(b)) if a != b)
}

/// Split `items` into at most [`MAX_CHUNKS`] groups.
fn chunks<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
	let size = items.len().div_ceil(MAX_CHUNKS).max(MIN_CHUNK);
	items.chunks(size).map(<[T]>::to_vec).collect()
}

/// The notifications for the difference between two samples.
pub(super) fn changes(before: &Sample, now: &Sample) -> Vec<(Topic, Reach)> {
	let mut out = Vec::new();
	if moved(before.queue, now.queue) {
		out.push((Topic::Queue, Reach::Everyone));
		out.push((Topic::Status, Reach::Everyone));
	}
	if moved(before.deliveries, now.deliveries) {
		out.push((Topic::Deliveries, Reach::Everyone));
	}
	if moved(before.suppression, now.suppression) {
		out.push((Topic::Suppression, Reach::Everyone));
	}
	let touched: Vec<String> = before
		.domains
		.keys()
		.chain(now.domains.keys())
		.filter(|name| before.domains.get(*name) != now.domains.get(*name))
		.cloned()
		.collect::<std::collections::BTreeSet<_>>()
		.into_iter()
		.collect();
	for group in chunks(&touched) {
		let reach = Reach::Tenants {
			domains: group,
			accounts: Vec::new(),
		};
		out.push((Topic::Domains, reach.clone()));
		out.push((Topic::Status, reach));
	}
	let mut touched: Vec<(String, Vec<String>)> = Vec::new();
	for (name, (fingerprint, addresses)) in &now.accounts {
		let old = before.accounts.get(name);
		if old.map(|(known, _)| known) != Some(fingerprint) {
			touched.push((name.clone(), addresses.clone()));
			// The tenant the account left is told too.
			if let Some((_, previous)) = old {
				touched.push((name.clone(), previous.clone()));
			}
		}
	}
	for (name, (_, addresses)) in &before.accounts {
		if !now.accounts.contains_key(name) {
			touched.push((name.clone(), addresses.clone()));
		}
	}
	for group in chunks(&touched) {
		let reach = Reach::Tenants {
			domains: Vec::new(),
			accounts: group,
		};
		out.push((Topic::Accounts, reach.clone()));
		out.push((Topic::Status, reach));
	}
	out
}

/// Sample until the last stream is gone.
pub(super) async fn run(state: ApiState) {
	let mut tick = tokio::time::interval(state.events().limits().sample);
	tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	let mut before: Option<Sample> = None;
	loop {
		tick.tick().await;
		if !state.events().keep_sampling() {
			return;
		}
		let probe = state.clone();
		let Ok(now) = tokio::task::spawn_blocking(move || Sample::take(&probe)).await else {
			continue;
		};
		if let Some(before) = &before {
			state.events().publish(changes(before, &now));
		}
		before = Some(now);
	}
}
