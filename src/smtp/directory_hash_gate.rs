//! A bound on how many password checks run at the same moment.
//!
//! The sessions are sans-IO state machines, so the argon2id checks of a login
//! run where the session is driven: on an async worker. Unbounded, that costs
//! twice. Many logins at once keep every worker inside a hash for tens of
//! milliseconds and the listeners that share the workers wait behind them, and
//! each hash holds about 19 MiB while it runs, so the memory follows the
//! number of connections and not the number of cores.
//!
//! [`HashGate::run`] hands the worker over for the whole check (the same
//! `block_in_place` the ban store uses) and lets only a few checks run at a
//! time. The rest wait for a place, up to a limit; beyond it the attempt is
//! turned away as [`Busy`] before it costs anything. The REST API has a gate
//! of its own for bearer tokens (`api::state_auth`); that one is async and
//! tied to the API state, so it cannot serve a synchronous session.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};

/// Too many checks are already waiting for a place.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Busy;

#[derive(Debug, Default)]
struct Places {
	running: usize,
	waiting: usize,
}

/// A counting gate over blocking work, with a bounded line behind it.
#[derive(Debug)]
pub(crate) struct HashGate {
	permits: usize,
	max_waiting: usize,
	places: Mutex<Places>,
	freed: Condvar,
	#[cfg(test)]
	peak: std::sync::atomic::AtomicUsize,
}

/// A place held until the check ends, on every path out of it.
struct Held<'a>(&'a HashGate);

impl Drop for Held<'_> {
	fn drop(&mut self) {
		self.0.lock().running -= 1;
		self.0.freed.notify_one();
	}
}

impl Default for HashGate {
	/// A gate of the size [`HashGate::shared`] uses. A directory built by
	/// `Directory::new` shares the process-wide one instead.
	fn default() -> Self {
		let (permits, line) = Self::sizes();
		Self::new(permits, line)
	}
}

impl HashGate {
	/// How many checks run at once and how many wait. Half the cores, between
	/// two and eight: a check is one core for about 15 ms and a few MiB held
	/// meanwhile.
	fn sizes() -> (usize, usize) {
		let cores = std::thread::available_parallelism().map_or(4, usize::from);
		let permits = (cores / 2).clamp(2, 8);
		// Tests share the process and run many logins in parallel; a line that
		// turns them away would make unrelated tests fail.
		(permits, if cfg!(test) { usize::MAX } else { permits * 16 })
	}

	/// A gate letting `permits` checks run at once, with `max_waiting` more in line.
	pub(crate) fn new(permits: usize, max_waiting: usize) -> Self {
		Self {
			permits: permits.max(1),
			max_waiting,
			places: Mutex::new(Places::default()),
			freed: Condvar::new(),
			#[cfg(test)]
			peak: std::sync::atomic::AtomicUsize::new(0),
		}
	}

	/// The gate every directory shares, so a directory rebuilt on a reload does
	/// not start a new count.
	pub(crate) fn shared() -> Arc<Self> {
		static GATE: OnceLock<Arc<HashGate>> = OnceLock::new();
		Arc::clone(GATE.get_or_init(|| Arc::new(Self::default())))
	}

	/// Run `work` once a place is free, off the async worker, or say [`Busy`]
	/// without running it when the line is full.
	pub(crate) fn run<T>(&self, work: impl FnOnce() -> T) -> Result<T, Busy> {
		crate::util::blocking::may_block(|| {
			let _held = self.enter()?;
			Ok(work())
		})
	}

	fn lock(&self) -> MutexGuard<'_, Places> {
		self.places.lock().unwrap_or_else(|p| p.into_inner())
	}

	fn enter(&self) -> Result<Held<'_>, Busy> {
		let mut places = self.lock();
		if places.running >= self.permits {
			if places.waiting >= self.max_waiting {
				return Err(Busy);
			}
			places.waiting += 1;
			while places.running >= self.permits {
				places = self.freed.wait(places).unwrap_or_else(|p| p.into_inner());
			}
			places.waiting -= 1;
		}
		places.running += 1;
		#[cfg(test)]
		self.peak
			.fetch_max(places.running, std::sync::atomic::Ordering::SeqCst);
		Ok(Held(self))
	}

	/// Test-only: the checks running now and the ones in line.
	#[cfg(test)]
	pub(crate) fn load(&self) -> (usize, usize) {
		let places = self.lock();
		(places.running, places.waiting)
	}

	/// Test-only: the most checks that ran at once.
	#[cfg(test)]
	pub(crate) fn peak(&self) -> usize {
		self.peak.load(std::sync::atomic::Ordering::SeqCst)
	}
}

impl super::Directory {
	/// Use `gate` for the password checks of this directory instead of the
	/// shared one.
	#[cfg(test)]
	pub(crate) fn with_hash_gate(mut self, gate: Arc<HashGate>) -> Self {
		self.hash_gate = gate;
		self
	}
}

#[cfg(test)]
#[path = "directory_hash_gate_tests.rs"]
mod tests;
