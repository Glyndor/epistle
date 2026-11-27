//! The one writer of the in-memory directory.
//!
//! Every change to the store's state rebuilds the directory and swaps it
//! into the handle. The swap is where the race shows: two threads can
//! build the directory in one order and swap it in the other, and the
//! older directory wins — an account the server just suspended is active
//! again. The store's directory lock is held from the build to the swap,
//! so the directory that reaches the handle is always the one built last,
//! and it is built from the state as it is at that moment.
//!
//! The lock is a leaf: nothing takes a file lock or a mirror lock while
//! holding it, so it cannot deadlock with the writers that hold those.

use std::sync::MutexGuard;

use super::AccountStore;

impl AccountStore {
	/// Rebuild the directory from the current state and swap it into the
	/// handle.
	///
	/// The store's directory lock is held from the build to the swap, so
	/// two threads cannot build in one order and swap in the other: the
	/// directory that stays in memory is the one built last, and it is
	/// built from the state as it is at that moment.
	pub(super) fn rebuild_directory(&self) {
		let _guard = self.lock_directory();
		let directory = self.build_directory();
		#[cfg(test)]
		self.pause_before_swap();
		self.handle.replace(directory);
	}

	/// Take the store's directory lock, waiting for the holder when there
	/// is one. A thread that has to wait says so, so a test can tell
	/// that a rebuild is behind another one.
	fn lock_directory(&self) -> MutexGuard<'_, ()> {
		match self.directory_lock.try_lock() {
			Ok(guard) => guard,
			Err(_) => {
				#[cfg(test)]
				self.directory_events.add_permits(1);
				self.directory_lock
					.lock()
					.unwrap_or_else(|poisoned| poisoned.into_inner())
			}
		}
	}

	/// The pause a test puts between the build and the swap, so it can
	/// hold a rebuild there while another thread writes.
	#[cfg(test)]
	fn pause_before_swap(&self) {
		let pause = self
			.build_pause
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.clone();
		if let Some(pause) = pause {
			pause();
		}
	}

	/// The permit a test waits for when a rebuild had to wait for the
	/// directory lock: the rebuild is behind another one.
	#[cfg(test)]
	pub(crate) fn directory_events(&self) -> std::sync::Arc<tokio::sync::Semaphore> {
		std::sync::Arc::clone(&self.directory_events)
	}

	/// The pause between the build and the swap. `None` lets every
	/// rebuild through.
	#[cfg(test)]
	pub(crate) fn set_build_pause(&self, pause: Option<std::sync::Arc<dyn Fn() + Send + Sync>>) {
		*self
			.build_pause
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner()) = pause;
	}
}
