//! Memory and process limits of the generated services.

use serde::{Deserialize, Serialize};

/// One `[resources.<service>]` table of the answers file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceResources {
	/// The memory limit, as compose writes it (`512m`, `2g`).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub memory: Option<String>,
	/// The most processes and threads the service may run at once.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub pids: Option<u32>,
}

/// Each service with its default memory and process limits, in the order an
/// error lists them. Measured on a local stack under 64 parallel SMTP
/// sessions of ten 54 KB messages each plus 32 IMAP sessions (memory.peak
/// and pids.peak of each container's cgroup):
///
/// - mail: 47 MB anonymous memory and 62 tasks at the peak. tokio may grow
///   its blocking pool to 512 threads, and a thread it cannot spawn is a
///   panic, so the process limit stays well above that.
/// - db: 113 MB anonymous plus 148 MB of shared buffers and 22 processes;
///   one process per connection up to the default max_connections of 100.
/// - clamav: clamd held 990 MB with the full signature set and reached
///   1.99 GB while it reloaded it, because it loads the new set before it
///   frees the old one.
/// - freshclam: 860 MB while it tested a downloaded database.
const DEFAULTS: [(&str, &str, u32); 4] = [
	("mail", "1g", 1024),
	("db", "1g", 256),
	("clamav", "3g", 128),
	("freshclam", "2g", 32),
];

/// The `mem_limit` and `pids_limit` of `service`: its answered override,
/// else its default. `None` for a service that has no default.
pub(crate) fn limits(
	overrides: &std::collections::BTreeMap<String, ServiceResources>,
	service: &str,
) -> Option<(String, u32)> {
	let (_, memory, pids) = DEFAULTS.iter().find(|(name, _, _)| *name == service)?;
	let answered = overrides.get(service);
	Some((
		answered
			.and_then(|resources| resources.memory.clone())
			.unwrap_or_else(|| (*memory).to_string()),
		answered
			.and_then(|resources| resources.pids)
			.unwrap_or(*pids),
	))
}

/// The least memory limit Podman creates a container with: 6 MiB.
const MIN_MEMORY: u64 = 6 * 1024 * 1024;

/// Every problem with the answered overrides, as `(field, reason)`.
pub(crate) fn problems(
	overrides: &std::collections::BTreeMap<String, ServiceResources>,
) -> Vec<(String, String)> {
	let mut found = Vec::new();
	for (service, resources) in overrides {
		if !DEFAULTS.iter().any(|(name, _, _)| name == service) {
			let names: Vec<&str> = DEFAULTS.iter().map(|(name, _, _)| *name).collect();
			found.push((
				format!("resources.{service}"),
				format!(
					"is not a service of the stack; use one of {}",
					names.join(", ")
				),
			));
			continue;
		}
		if let Some(memory) = &resources.memory {
			let reason = if !is_memory(memory) {
				Some("is not a whole number above 0 followed by k, m or g")
			} else {
				match crate::smtp::memory_fit::parse_memory(memory) {
					None => Some("is more than 64-bit sizes reach"),
					Some(bytes) if bytes < MIN_MEMORY => Some("is under the 6m Podman accepts"),
					Some(_) => None,
				}
			};
			if let Some(reason) = reason {
				found.push((
					format!("resources.{service}.memory"),
					format!("{memory:?} {reason}"),
				));
			}
		}
		if resources.pids == Some(0) {
			found.push((
				format!("resources.{service}.pids"),
				"must be at least 1".to_string(),
			));
		}
	}
	found
}

/// Whether `value` is a memory size podup and Podman read the same way: a
/// whole number above zero and one of the units `k`, `m` or `g`.
fn is_memory(value: &str) -> bool {
	let Some((digits, unit)) = value.split_at_checked(value.len().saturating_sub(1)) else {
		return false;
	};
	matches!(unit, "k" | "K" | "m" | "M" | "g" | "G")
		&& !digits.is_empty()
		&& digits.bytes().all(|byte| byte.is_ascii_digit())
		&& digits.bytes().any(|byte| byte != b'0')
}
