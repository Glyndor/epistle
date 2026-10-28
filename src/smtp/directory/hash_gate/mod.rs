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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};

/// How a password sign-in ended, for the sessions that can tell a refusal
/// from a sign-in the server had no room to check.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
	/// The credential opened `account`; `label` names the app password used.
	Admitted {
		/// The account the sign-in resolved to.
		account: String,
		/// The app password that matched, if one did.
		label: Option<String>,
	},
	/// The login is refused. Says nothing about why.
	Refused,
	/// Too many checks were waiting; nothing was tried. The session answers
	/// with the temporary failure of its protocol, which depends on the load
	/// and never on the login.
	Busy,
}

/// Seconds between two log lines about sign-ins turned away.
const LOG_EVERY_SECS: u64 = 30;

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
	/// Sign-ins turned away since the last log line, and when that was.
	unreported: AtomicU64,
	last_log: AtomicU64,
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
		let cores = std::thread::available_parallelism().map_or(4, usize::from);
		let (permits, line) = Self::sizes_for(cores);
		Self::new(permits, line)
	}
}

impl HashGate {
	/// How many checks run at once and how many wait on a host with `cores`
	/// cores. Half the cores, between two and eight: a check is one core for
	/// about 15 ms and a few MiB held meanwhile. Sixteen wait per place.
	pub(crate) fn sizes_for(cores: usize) -> (usize, usize) {
		let permits = (cores / 2).clamp(2, 8);
		(permits, permits * 16)
	}

	/// A gate letting `permits` checks run at once, with `max_waiting` more in line.
	pub(crate) fn new(permits: usize, max_waiting: usize) -> Self {
		Self {
			permits: permits.max(1),
			max_waiting,
			places: Mutex::new(Places::default()),
			freed: Condvar::new(),
			unreported: AtomicU64::new(0),
			last_log: AtomicU64::new(0),
			#[cfg(test)]
			peak: std::sync::atomic::AtomicUsize::new(0),
		}
	}

	/// The gate every directory shares, so a directory rebuilt on a reload does
	/// not start a new count.
	pub(crate) fn shared() -> Arc<Self> {
		static GATE: OnceLock<Arc<HashGate>> = OnceLock::new();
		Arc::clone(GATE.get_or_init(|| Arc::new(Self::shared_instance())))
	}

	/// The process-wide gate. Tests share the process and run many logins in
	/// parallel, so there its line has no limit; the sizes of production are
	/// tested through [`HashGate::sizes_for`] and the line through gates of
	/// their own.
	fn shared_instance() -> Self {
		let gate = Self::default();
		if cfg!(test) {
			Self::new(gate.permits, usize::MAX)
		} else {
			gate
		}
	}

	/// Count a sign-in turned away. Returns how many have been turned away
	/// since the last time this returned a number, at most once every
	/// [`LOG_EVERY_SECS`] seconds, so a flood writes one log line and not one
	/// per attempt.
	pub(crate) fn note_rejected(&self, now_secs: u64) -> Option<u64> {
		self.unreported.fetch_add(1, Ordering::Relaxed);
		let last = self.last_log.load(Ordering::Relaxed);
		if now_secs < last.saturating_add(LOG_EVERY_SECS) {
			return None;
		}
		self.last_log
			.compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
			.ok()
			.map(|_| self.unreported.swap(0, Ordering::Relaxed))
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
	/// Count a password sign-in turned away by the full gate and, at a limited
	/// rate, say so in the log.
	pub(super) fn note_gate_rejection(&self, protocol: crate::config::Protocol) {
		if let Some(metrics) = &self.metrics {
			metrics.auth_hash_gate_rejected();
		}
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map_or(0, |elapsed| elapsed.as_secs());
		if let Some(count) = self.hash_gate.note_rejected(now) {
			tracing::warn!(
				target: "epistle::auth",
				event = "auth.hash_gate_full",
				rejected = count,
				protocol = protocol.as_str(),
				"password checks are queued to the limit; sign-ins are told to try again"
			);
		}
	}

	/// Use `gate` for the password checks of this directory instead of the
	/// shared one.
	#[cfg(test)]
	pub(crate) fn with_hash_gate(mut self, gate: Arc<HashGate>) -> Self {
		self.hash_gate = gate;
		self
	}
}

#[cfg(test)]
pub(crate) mod tests;
