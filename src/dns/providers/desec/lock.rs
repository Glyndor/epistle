//! The write lock of one zone of one account. A change to a record set is
//! read, edited and written back because deSEC's PUT replaces the whole set
//! at a (type, name); two changes interleaved there would each write a set
//! that lacks the other's edit and the later write would erase it. Every
//! provider in the process that names the same account key and zone takes
//! the same lock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use tokio::sync::OwnedMutexGuard;

type Locks = Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>;

/// Wait for the zone's turn; the change is made while the guard is held.
pub(super) async fn hold(api_key: &str, zone: &str) -> OwnedMutexGuard<()> {
	static LOCKS: OnceLock<Locks> = OnceLock::new();
	let key = format!(
		"{}\u{0}{}",
		api_key.to_ascii_lowercase(),
		zone.to_ascii_lowercase()
	);
	let lock = {
		let mut locks = LOCKS
			.get_or_init(|| Mutex::new(HashMap::new()))
			.lock()
			.unwrap_or_else(PoisonError::into_inner);
		Arc::clone(locks.entry(key).or_default())
	};
	lock.lock_owned().await
}
