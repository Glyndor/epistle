//! The container memory limits `init` picks for a new install, from the
//! host's memory.
//!
//! The limits are ceilings, not reservations, but their sum is what the
//! host has to hold when every service peaks at once. On 8 GiB they add up
//! to 6 GiB, 75%, under the 85% `epistle status` warns at; between 4 and
//! about 7 GiB the same set passes that line, and `status` says so. `mail`
//! gets 2g from the start: a full message memory budget (a fifth of the
//! limit) costs about three times its size while a burst of large messages
//! arrives. clamav needs about 1 GiB resident and 2 GiB while it reloads its
//! signatures, so below 4 GiB it is left out.
//!
//! An existing install keeps what its compose file records; `epistle
//! status` suggests the limits this host would get.

use std::path::Path;

use super::Answers;

/// One GiB.
const GIB: u64 = 1024 * 1024 * 1024;

/// What `init` picks for a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sizing {
	/// The memory limit of each service, as compose writes it.
	pub(crate) memory: [(&'static str, &'static str); 4],
	/// Whether clamav and freshclam run.
	pub(crate) antivirus: bool,
}

/// The limits for a host whose `MemTotal` is `mem_total` bytes.
pub(crate) fn for_host(mem_total: u64) -> Sizing {
	let memory = if mem_total <= 8 * GIB {
		// 6 GiB in all: 75% of 8 GiB. clamav keeps the 2 GiB its reload
		// peaked at; freshclam tested a download in 860 MB.
		[
			("mail", "2g"),
			("db", "1g"),
			("clamav", "2g"),
			("freshclam", "1g"),
		]
	} else if mem_total <= 16 * GIB {
		// The clamav and freshclam limits of the fixed defaults, which
		// leave room for a larger signature set.
		[
			("mail", "2g"),
			("db", "1g"),
			("clamav", "3g"),
			("freshclam", "2g"),
		]
	} else {
		// The derived message budget reaches its 1 GiB ceiling at 4g.
		[
			("mail", "4g"),
			("db", "2g"),
			("clamav", "3g"),
			("freshclam", "2g"),
		]
	};
	Sizing {
		memory,
		antivirus: mem_total >= MIN_ANTIVIRUS_HOST,
	}
}

/// The least host memory clamav is started on: 4 GiB.
const MIN_ANTIVIRUS_HOST: u64 = 4 * GIB;

/// The host's `MemTotal`, in bytes, from a `/proc/meminfo` at `meminfo`.
pub(crate) fn mem_total(meminfo: &Path) -> Option<u64> {
	use std::io::Read;
	let mut text = String::new();
	std::fs::File::open(meminfo)
		.ok()?
		.take(1024 * 1024)
		.read_to_string(&mut text)
		.ok()?;
	let line = text
		.lines()
		.find_map(|line| line.strip_prefix("MemTotal:"))?;
	let kib: u64 = line.trim().strip_suffix("kB")?.trim().parse().ok()?;
	kib.checked_mul(1024).filter(|bytes| *bytes > 0)
}

/// Fill in what the operator did not answer: whether clamav runs and the
/// memory of each service. An existing compose file keeps what it records;
/// a new install gets [`for_host`]. Returns what the operator should read.
pub(super) fn fill(answers: &mut Answers, meminfo: &Path) -> Vec<String> {
	let compose = super::compose::compose_file_path(&answers.data_dir);
	if compose.exists() {
		keep_existing(answers, &compose);
		return vec![format!(
			"kept the container limits {} records; `epistle status` suggests the ones a new \
			 install on this host would get",
			compose.display()
		)];
	}
	let Some(total) = mem_total(meminfo) else {
		return vec![format!(
			"cannot read MemTotal from {}; the containers keep the fixed limits (mail 1g, db \
			 1g, clamav 3g, freshclam 2g)",
			meminfo.display()
		)];
	};
	let sizing = for_host(total);
	let answered_antivirus = answers.services.antivirus;
	let antivirus = *answers.services.antivirus.get_or_insert(sizing.antivirus);
	let mut picked = Vec::new();
	for (service, memory) in sizing.memory {
		let runs = match service {
			"db" => answers.services.database,
			"clamav" | "freshclam" => antivirus,
			_ => true,
		};
		let entry = answers.resources.entry(service.to_string()).or_default();
		if runs && entry.memory.is_none() {
			entry.memory = Some(memory.to_string());
			picked.push(format!("{service} {memory}"));
		}
		if *entry == Default::default() {
			answers.resources.remove(service);
		}
	}
	let mut notes = Vec::new();
	if !picked.is_empty() {
		notes.push(format!(
			"container memory for a host with {:.1} GiB: {}",
			total as f64 / GIB as f64,
			picked.join(", ")
		));
	}
	if answered_antivirus.is_none() && !antivirus {
		notes.push(
			"the host has under 4 GiB of memory, so clamav and freshclam are left out and \
			 incoming mail is not scanned for viruses; set antivirus = true under [services] to \
			 keep them"
				.to_string(),
		);
	}
	notes
}

/// Take what the operator did not answer from the compose file an earlier
/// `init` wrote: whether it runs clamav, and the limits it recorded.
/// Services it recorded nothing for keep the fixed defaults, as `stack
/// update` renders them.
fn keep_existing(answers: &mut Answers, compose: &Path) {
	let Some(document) = std::fs::read(compose)
		.ok()
		.and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
	else {
		return;
	};
	if answers.services.antivirus.is_none() {
		let off = document.get("x-epistle-antivirus") == Some(&serde_json::Value::Bool(false));
		answers.services.antivirus = Some(!off);
	}
	let recorded: std::collections::BTreeMap<String, super::resources::ServiceResources> =
		match document.get("x-epistle-resources") {
			Some(value) => serde_json::from_value(value.clone()).unwrap_or_default(),
			None => Default::default(),
		};
	for (service, limits) in recorded {
		let entry = answers.resources.entry(service).or_default();
		entry.memory = entry.memory.take().or(limits.memory);
		entry.pids = entry.pids.or(limits.pids);
	}
}

#[cfg(test)]
#[path = "host_sizing_tests.rs"]
mod tests;
