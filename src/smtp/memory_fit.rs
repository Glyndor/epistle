//! How much message data the SMTP server may hold, sized to the memory the
//! mail container may use.
//!
//! A message in flight peaks at about 2.9 times its body (measured: a
//! 24 MiB BDAT transfer peaked at 55.7 MiB, the same body over DATA and TLS
//! at 70 MiB), while the budget counts body bytes only. A full budget can
//! therefore cost about [`PEAK_FACTOR`] times its size. When
//! `[server] message_memory_budget` is not set, the budget is a fifth of
//! the container's memory limit ([`LIMIT_DIVISOR`]), rounded down to whole
//! MiB: about 60% of the limit at the peak, under the [`WARN_PERCENT`] line
//! a configured budget is held to, the rest left to IMAP and JMAP sessions,
//! the queue and the allocator. It never drops below one message of the
//! largest size (a smaller budget would answer that message with 452
//! forever) and never grows past [`MAX_DERIVED_BUDGET`], which already
//! admits forty 25 MiB messages at once.
//!
//! The limit is the cgroup v2 `memory.max` of the running process, the
//! lowest one on the way up to the cgroup root. Outside a limited cgroup it
//! is the `mem_limit` of the `mail` service in the compose file `epistle
//! init` wrote, and failing both, the 1 GiB the `mail` service had before
//! its default followed the host.

use std::path::{Path, PathBuf};

/// The share of the container limit the derived budget takes: a fifth, so
/// a full budget at the peak ([`PEAK_FACTOR`] times it) stays at 60% of the
/// limit, under [`WARN_PERCENT`].
pub const LIMIT_DIVISOR: u64 = 5;

/// The largest derived budget: 1 GiB.
pub const MAX_DERIVED_BUDGET: u64 = 1024 * 1024 * 1024;

/// What a full budget costs at the peak, in multiples of the budget.
pub const PEAK_FACTOR: u64 = 3;

/// The share of the container limit, in percent, a full budget may cost at
/// the peak before start-up and `epistle status` warn.
pub const WARN_PERCENT: u64 = 70;

/// The limit assumed when none can be read: the `mail` default of the
/// compose files written before the default followed the host's memory.
pub const FALLBACK_LIMIT: u64 = 1024 * 1024 * 1024;

/// The most bytes read from a cgroup file or the compose file. A cgroup
/// file is a line; a compose file `epistle init` wrote is a few KiB.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// The most cgroup levels walked from the process's cgroup to the root.
const MAX_CGROUP_DEPTH: usize = 64;

/// Where the container's memory limit came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitSource {
	/// The cgroup v2 `memory.max` of the running process.
	Cgroup,
	/// The `mem_limit` of the `mail` service in the compose file.
	Compose,
	/// Neither could be read: [`FALLBACK_LIMIT`].
	Fallback,
}

impl LimitSource {
	/// How the source reads in a log or status line.
	pub fn describe(self) -> &'static str {
		match self {
			LimitSource::Cgroup => "cgroup memory.max",
			LimitSource::Compose => "mem_limit in compose.yaml",
			LimitSource::Fallback => "no limit found, the former 1g default",
		}
	}
}

/// The memory the mail container may use, in bytes, and where that came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerLimit {
	/// The limit in bytes.
	pub bytes: u64,
	/// Where it was read.
	pub source: LimitSource,
}

impl ContainerLimit {
	/// The limit used when nothing could be read.
	pub fn fallback() -> Self {
		ContainerLimit {
			bytes: FALLBACK_LIMIT,
			source: LimitSource::Fallback,
		}
	}
}

/// The files the limit is read from, injectable so tests never read the
/// host's.
#[derive(Debug, Clone)]
pub struct LimitPaths {
	/// `/proc/self/cgroup`.
	pub proc_self_cgroup: PathBuf,
	/// The cgroup v2 mount, `/sys/fs/cgroup`.
	pub cgroup_root: PathBuf,
	/// The compose file `epistle init` wrote under `data_dir`.
	pub compose: PathBuf,
}

impl LimitPaths {
	/// The real files for a server whose `data_dir` is `data_dir`.
	pub fn system(data_dir: &Path) -> Self {
		LimitPaths {
			proc_self_cgroup: PathBuf::from("/proc/self/cgroup"),
			cgroup_root: PathBuf::from("/sys/fs/cgroup"),
			compose: data_dir.join("compose").join("compose.yaml"),
		}
	}
}

/// The budget in effect and how it was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
	/// The cap in bytes; `0` is no cap.
	pub bytes: u64,
	/// `true` when `message_memory_budget` was not set and the cap was
	/// derived from the limit.
	pub derived: bool,
	/// The container limit it was judged against.
	pub limit: ContainerLimit,
}

/// A memory size as compose writes it: a whole number followed by `k`, `m`
/// or `g` (any case), in bytes. `None` for anything else or an overflow.
pub fn parse_memory(value: &str) -> Option<u64> {
	let (digits, unit) = value.split_at_checked(value.len().checked_sub(1)?)?;
	let scale: u64 = match unit {
		"k" | "K" => 1024,
		"m" | "M" => 1024 * 1024,
		"g" | "G" => 1024 * 1024 * 1024,
		_ => return None,
	};
	if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
		return None;
	}
	digits
		.parse::<u64>()
		.ok()
		.and_then(|number| number.checked_mul(scale))
		.filter(|bytes| *bytes > 0)
}

/// The lowest cgroup v2 `memory.max` from the process's cgroup (named in
/// `proc_self_cgroup`) up to `cgroup_root`. `None` when the process is not
/// in a cgroup v2 hierarchy or no level sets a limit (`max`).
pub fn read_cgroup_limit(proc_self_cgroup: &Path, cgroup_root: &Path) -> Option<u64> {
	let listing = read_bounded(proc_self_cgroup)?;
	let relative = listing.lines().find_map(|line| line.strip_prefix("0::"))?;
	// Only plain names are followed: a `..` would leave the cgroup mount.
	let levels: Vec<&str> = relative
		.split('/')
		.filter(|name| !name.is_empty() && *name != "." && *name != "..")
		.collect();
	if levels.len() > MAX_CGROUP_DEPTH {
		return None;
	}
	let mut lowest: Option<u64> = None;
	for depth in (0..=levels.len()).rev() {
		let mut level = cgroup_root.to_path_buf();
		level.extend(&levels[..depth]);
		let Some(value) = read_bounded(&level.join("memory.max")) else {
			continue;
		};
		if let Ok(bytes) = value.trim().parse::<u64>() {
			lowest = Some(lowest.map_or(bytes, |current| current.min(bytes)));
		}
	}
	lowest
}

/// The `mem_limit` of the `mail` service in the compose file at `compose`.
pub fn read_compose_limit(compose: &Path) -> Option<u64> {
	let text = read_bounded(compose)?;
	let document: serde_json::Value = serde_json::from_str(&text).ok()?;
	parse_memory(document["services"]["mail"]["mem_limit"].as_str()?)
}

/// The mail container's limit as the host sees it, from outside the
/// container's cgroup: the compose file's, else [`FALLBACK_LIMIT`]. What
/// `epistle status` and `epistle limits show` judge the budget against.
pub fn compose_or_fallback(compose: &Path) -> ContainerLimit {
	match read_compose_limit(compose) {
		Some(bytes) => ContainerLimit {
			bytes,
			source: LimitSource::Compose,
		},
		None => ContainerLimit::fallback(),
	}
}

/// The largest message a server accepts: `max_message_size`, or the
/// built-in default when it is unset or `0`.
pub fn largest_message(max_message_size: Option<u64>) -> u64 {
	max_message_size
		.filter(|size| *size > 0)
		.unwrap_or(crate::smtp::session::MAX_MESSAGE_SIZE as u64)
}

/// The mail container's limit: the cgroup's, else the compose file's, else
/// [`FALLBACK_LIMIT`].
pub fn container_limit(paths: &LimitPaths) -> ContainerLimit {
	if let Some(bytes) = read_cgroup_limit(&paths.proc_self_cgroup, &paths.cgroup_root) {
		return ContainerLimit {
			bytes,
			source: LimitSource::Cgroup,
		};
	}
	compose_or_fallback(&paths.compose)
}

/// The budget derived from a container limit of `limit` bytes for a server
/// whose largest message is `max_message_size` bytes.
pub fn derive(limit: u64, max_message_size: u64) -> u64 {
	const MIB: u64 = 1024 * 1024;
	// The config refuses a max_message_size above the ceiling when the
	// budget is derived, so the floor never passes the ceiling.
	(limit / LIMIT_DIVISOR / MIB * MIB)
		.clamp(max_message_size.min(MAX_DERIVED_BUDGET), MAX_DERIVED_BUDGET)
}

/// The budget in effect: the configured one when set, else the one derived
/// from `limit`.
pub fn effective(configured: Option<u64>, max_message_size: u64, limit: ContainerLimit) -> Budget {
	Budget {
		bytes: configured.unwrap_or_else(|| derive(limit.bytes, max_message_size)),
		derived: configured.is_none(),
		limit,
	}
}

/// The warning start-up and `epistle status` give when a full budget would
/// cost more than [`WARN_PERCENT`] of the container limit at the peak.
pub fn warning(budget: &Budget) -> Option<String> {
	let peak = u128::from(budget.bytes) * u128::from(PEAK_FACTOR);
	let over = peak * 100 > u128::from(budget.limit.bytes) * u128::from(WARN_PERCENT);
	// A derived budget only passes the line when the largest message raised
	// it above a fifth of the limit (3 x 20% = 60%).
	if budget.bytes == 0 || !over {
		return None;
	}
	let (subject, remedy) = if budget.derived {
		(
			format!(
				"max_message_size raised the message memory budget to {} MiB",
				mib(budget.bytes)
			),
			"max_message_size",
		)
	} else {
		(
			format!("message_memory_budget is {} MiB", mib(budget.bytes)),
			"message_memory_budget",
		)
	};
	Some(format!(
		"{subject}: a full budget takes about {PEAK_FACTOR} times that ({} MiB) while the \
		 messages arrive, more than {WARN_PERCENT}% of the {} MiB the mail container may use \
		 ({}); lower {remedy} or give the mail container more memory",
		mib(budget.bytes.saturating_mul(PEAK_FACTOR)),
		mib(budget.limit.bytes),
		budget.limit.source.describe(),
	))
}

/// A byte count in whole MiB, rounded down.
pub fn mib(bytes: u64) -> u64 {
	bytes / (1024 * 1024)
}

/// Read at most [`MAX_FILE_BYTES`] of `path` as text.
fn read_bounded(path: &Path) -> Option<String> {
	read_regular(path, MAX_FILE_BYTES).ok()
}

/// Read at most `max` bytes of the regular file at `path` as text.
///
/// The server reads the compose file before it drops its privileges, from
/// a directory the service account writes, so a symlink at `path` is
/// refused (`O_NOFOLLOW`) rather than followed to a file root may read, and
/// the open never waits (`O_NONBLOCK`): a FIFO there would hold start-up
/// until a writer came. Anything but a regular file, judged on the open
/// descriptor, is refused, so a device is never read either.
pub(crate) fn read_regular(path: &Path, max: u64) -> std::io::Result<String> {
	use std::io::Read;
	let mut options = std::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let file = options.open(path)?;
	if !file.metadata()?.is_file() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::InvalidInput,
			"not a regular file",
		));
	}
	let mut text = String::new();
	file.take(max).read_to_string(&mut text)?;
	Ok(text)
}

#[cfg(test)]
#[path = "memory_fit_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "memory_fit_tests_hostile.rs"]
mod tests_hostile;
