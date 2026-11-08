//! One lock per DNS zone, shared by everything that writes the zone.
//!
//! The reconcile loop and the DKIM and TLSA rotations write the same
//! zone, and nothing kept them apart: a plan made against an older
//! listing can be written after a value was published, and the value
//! published last wins. The loop would put back the TLSA association of
//! the certificate it read before the rotation published the new one, and
//! the receivers that validate DANE would refuse the mail until the next
//! run.
//!
//! One lock per zone, held for the whole read-modify-write of that zone,
//! keeps the writers apart: whoever reads the zone holds the lock until
//! its writes are in, and the other writer waits. The registry is
//! process-wide, so the loop, the rotations and the commands that run in
//! the same server share it.
//!
//! The locks are taken one zone at a time, and the writer that holds
//! several of them takes them in the order the zones are named, so the
//! wait cannot end in a deadlock: no writer holds a lock while it waits
//! for another one.
//!
//! The command `epistle dns publish` holds the lock of every zone it
//! read while it asks the operator to confirm: the write it does then
//! lands whole, and the rotation waits for the answer.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// The lock of a zone. It is held for as long as the handle lives.
///
/// The handle is shared: a run that holds the lock of a zone hands the
/// same handle to every part of the run that writes there, and the lock
/// is released when the last of them is done with it.
#[derive(Clone)]
pub struct ZoneLock {
	/// The guard of the zone's lock.
	_guard: Arc<OwnedMutexGuard<()>>,
}

impl std::fmt::Debug for ZoneLock {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("ZoneLock")
	}
}

/// The locks of this process, one per zone.
fn registry() -> &'static Mutex<BTreeMap<String, Arc<AsyncMutex<()>>>> {
	static REGISTRY: OnceLock<Mutex<BTreeMap<String, Arc<AsyncMutex<()>>>>> = OnceLock::new();
	REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// The lock of `zone`, waited for until it is free.
///
/// The guard holds the lock until it is dropped: it is dropped when the
/// read-modify-write of the zone is over.
pub async fn lock(zone: &str) -> ZoneLock {
	acquire(&key(zone)).await
}

/// The locks of one run, one per zone.
///
/// A run that touches several zones holds the lock of each of them from
/// the moment it reads the zone until its writes are in. Two of those
/// zones can share a lock (the same registrable domain), and a run that
/// waited for a lock it holds itself would never finish: the lock of a
/// zone the run already holds is handed out again instead of waited for.
#[derive(Default)]
pub struct Locks {
	/// The lock of every zone this run holds, by its key.
	held: BTreeMap<String, ZoneLock>,
}

impl Locks {
	/// The lock of `zone`: taken now, or the one this run already holds.
	pub async fn lock(&mut self, zone: &str) -> ZoneLock {
		let key = key(zone);
		if let Some(lock) = self.held.get(&key) {
			return lock.clone();
		}
		let lock = acquire(&key).await;
		self.held.insert(key, lock.clone());
		lock
	}
}

/// Take the lock of `key`, waiting for whoever holds it.
async fn acquire(key: &str) -> ZoneLock {
	let mutex = {
		// The registry is held for as long as it takes to find the lock,
		// never across a wait: the lock itself is the async one.
		let mut locks = registry().lock().expect("the zone locks");
		Arc::clone(
			locks
				.entry(key.to_string())
				.or_insert_with(|| Arc::new(AsyncMutex::new(()))),
		)
	};
	ZoneLock {
		_guard: Arc::new(mutex.lock_owned().await),
	}
}

/// The name the writers of one zone agree on.
///
/// The same zone is named differently by the writers: the reconcile loop
/// names it by the domain the records belong to ("example.org") and the
/// certificate refresh by the mail host ("mail.example.org"), and a
/// provider that names no zone keeps whichever name it was given. The
/// registrable domain is the name they agree on: every name inside one
/// zone has the same registrable domain, so the writers of one zone wait
/// for each other even when they name it differently.
fn key(zone: &str) -> String {
	registrable_domain(&crate::dns::names::canonical_name(zone))
}

/// The registrable domain of `host`, the way the rest of the code asks
/// for it: the Mozilla Public Suffix List, and the last two labels when
/// the list does not know the name.
fn registrable_domain(host: &str) -> String {
	use psl::Psl;
	let labels: Vec<&str> = host.split('.').collect();
	if labels.len() <= 2 {
		return host.to_string();
	}
	if let Some(domain) = psl::List.domain(host.as_bytes())
		&& let Ok(domain) = std::str::from_utf8(domain.as_bytes())
	{
		return domain.to_ascii_lowercase();
	}
	labels[labels.len() - 2..].join(".")
}
