//! Reject new SMTP transactions when the data filesystem is too full to
//! accept another message.
//!
//! The mail server quota system (per-account, per-domain, per-tenant) only
//! covers mailbox storage; it does not protect the spool, the blob pool, the
//! log directory, the indices or the temporary files written while a message
//! is being processed. Without a filesystem-level guard, a full disk turns
//! the SMTP server into a black hole: every `MAIL FROM` gets a `250 OK`, the
//! server accepts the bytes and then fails to write the spool, and the
//! message is lost. The remote sender believes it was delivered and will not
//! retry.
//!
//! The fix is to refuse before accepting: poll the free space on the
//! filesystem holding `data_dir` at `MAIL FROM` time, and reject with `452`
//! (temporary) when there is not enough room. The remote will back off and
//! retry, and the protocol stays in spec (RFC 5321 §4.5.3.1.9, 4.3.1).
//!
//! # Caching
//!
//! `statvfs` on the hot path of every SMTP transaction is wasteful: a busy
//! server handling hundreds of messages per second would issue the syscall
//! for every single one. The result is sampled once and reused for
//! `CACHE_TTL`: a fresh measurement is only taken when the previous one
//! has aged out. Five seconds is short enough that recovery from a low-disk
//! event shows up in the next window, and long enough that polling cost is
//! negligible compared to the actual `MAIL FROM` work. The `MAIL FROM`
//! response itself is what the remote sees — the cache is invisible on the
//! wire.
//!
//! # Threshold
//!
//! The worst case for a single transaction is [`super::session::MAX_MESSAGE_SIZE`]
//! bytes (25 MiB, also advertised as the ESMTP `SIZE` extension): the server
//! caps incoming mail at that, so any accepted message fits in that budget
//! plus a small overhead for headers and per-recipient queue entries. If
//! the filesystem cannot hold that, the spool write that follows
//! `DATA`-termination cannot succeed either, so refusing here is strictly
//! better than the alternative of accepting and failing to write.
//!
//! # Unix-only
//!
//! `libc::statvfs` is the dependency-free probe and the runtime is Unix-only
//! today (the rest of the binary gates Unix-specific paths behind
//! `#[cfg(unix)]`). On non-Unix targets the guard short-circuits to "pass"
//! so the rest of the SMTP path keeps working until the wider port lands.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a free-space sample is reused before being refreshed. Five
/// seconds bounds the cost of `statvfs` on the hot path while keeping the
/// recovery latency from a low-disk event small enough that remote senders
/// see it within their next retry window.
const CACHE_TTL: Duration = Duration::from_secs(5);

/// Free-space probe injected by tests. Production code uses the default
/// `statvfs`-backed probe; tests inject a closure that returns whatever
/// bytes-free value they want, with no filesystem to fill.
pub(crate) type ProbeFn = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// A reusable, shared disk-space guard for the data filesystem.
///
/// Cloning is cheap: the only state is the cached sample plus the probe,
/// both of which live behind `Arc`.
#[derive(Clone)]
pub struct DiskGuard {
	path: PathBuf,
	cache: Arc<Mutex<Option<CachedSample>>>,
	probe: Option<ProbeFn>,
}

impl std::fmt::Debug for DiskGuard {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("DiskGuard")
			.field("path", &self.path)
			.finish_non_exhaustive()
	}
}

/// One cached free-space measurement: the value plus the wall-clock instant
/// it was taken. `None` means "never sampled"; the first call forces one.
#[derive(Clone, Copy)]
struct CachedSample {
	bytes: u64,
	at: Instant,
}

impl DiskGuard {
	/// Build a guard for the filesystem holding `path`. On Unix this probes
	/// via `statvfs`; on non-Unix it is a pass-through (see the module-level
	/// rationale).
	pub fn new(path: PathBuf) -> Self {
		DiskGuard {
			path,
			cache: Arc::new(Mutex::new(None)),
			probe: None,
		}
	}

	/// Build a guard with a caller-supplied probe. Used by tests to avoid
	/// touching the real filesystem; never wired up in production.
	#[cfg(test)]
	pub(crate) fn with_probe(path: PathBuf, probe: ProbeFn) -> Self {
		DiskGuard {
			path,
			cache: Arc::new(Mutex::new(None)),
			probe: Some(probe),
		}
	}

	/// The filesystem this guard polls. Kept for diagnostics and for the
	/// non-Unix stub.
	pub fn path(&self) -> &Path {
		&self.path
	}

	/// Whether the filesystem currently has at least `required` bytes free
	/// for an unprivileged writer. Returns `true` on probe failure: the
	/// alternative is a reject loop that masks real problems, and the
	/// downstream write will surface the underlying `ENOSPC` if it persists.
	/// "Fail open on probe error, fail closed on confirmed low space."
	pub fn has_room(&self, required: u64) -> bool {
		let Some(bytes) = self.sample() else {
			return true;
		};
		bytes >= required
	}

	/// Force a fresh sample, bypassing the cache. Public so tests can drive
	/// the real `statvfs` probe without going through the cache wrapper.
	pub fn refresh(&self) -> Option<u64> {
		let value = self.probe_now();
		if let Some(bytes) = value {
			let mut cache = self.cache.lock().expect("disk guard");
			*cache = Some(CachedSample {
				bytes,
				at: Instant::now(),
			});
		}
		value
	}

	/// Return a cached sample if one is still fresh, otherwise refresh it.
	fn sample(&self) -> Option<u64> {
		{
			let cache = self.cache.lock().expect("disk guard");
			if let Some(sample) = *cache
				&& sample.at.elapsed() < CACHE_TTL
			{
				return Some(sample.bytes);
			}
		}
		self.refresh()
	}

	/// Take a fresh measurement. Calls the injected probe in tests, or the
	/// `libc::statvfs` syscall on Unix. Returns `None` when the syscall
	/// itself fails (path no longer exists, permission denied, etc.) so the
	/// caller can choose to fail open.
	fn probe_now(&self) -> Option<u64> {
		match &self.probe {
			Some(probe) => probe(),
			None => default_probe(&self.path),
		}
	}
}

/// The default probe: `statvfs(2)` on the path, returning bytes available
/// to a non-privileged process. `f_bavail` (not `f_bfree`) is the right
/// field because it excludes the kernel's reserved blocks; using
/// `f_bfree` would over-report space the mail writer cannot actually use.
#[cfg(unix)]
fn default_probe(path: &Path) -> Option<u64> {
	use std::ffi::CString;
	use std::os::unix::ffi::OsStrExt;

	let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
	let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
	// SAFETY: `c_path` points at a NUL-terminated string for the lifetime of
	// the call; `stat` is a writable out-parameter that the kernel fills in
	// on success.
	let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
	if rc != 0 {
		return None;
	}
	let bavail = stat.f_bavail as u64;
	let frsize = stat.f_frsize as u64;
	Some(bavail.saturating_mul(frsize))
}

/// Non-Unix stub: the binary does not run on non-Unix today, but the
/// type still has to compile so the rest of the SMTP path stays put. The
/// stub returns `None` so the guard fails open until a real probe is wired
/// in alongside the wider port.
#[cfg(not(unix))]
fn default_probe(_path: &Path) -> Option<u64> {
	None
}

#[cfg(test)]
#[path = "diskspace_tests.rs"]
mod tests;
