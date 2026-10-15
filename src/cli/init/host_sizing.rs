//! The container memory limits `init` picks for a new install, from the
//! host's memory.
//!
//! The limits are ceilings, not reservations, but their sum is what the
//! host has to hold when every service peaks at once, so every tier in
//! [`TIERS`] stays under the 85% `epistle status` warns at on the smallest
//! host it is given to. A full message memory budget (a fifth of the `mail`
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

/// One row of [`TIERS`]: what a host with at least `from` bytes gets.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tier {
	/// The least `MemTotal` the tier is given to.
	pub(crate) from: u64,
	/// The memory limit of each service, as compose writes it.
	pub(crate) memory: [(&'static str, &'static str); 4],
	/// Whether clamav and freshclam run.
	pub(crate) antivirus: bool,
}

/// The tiers in ascending order of `from`. Each one adds up to less than
/// 85% of the smallest host it is given to, the line `epistle status` warns
/// at; under 4 GiB, where only mail and db run, to at most 75% of a 2 GiB
/// host, the smallest the tiers are sized for.
pub(crate) const TIERS: [Tier; 4] = [
	// 1.5 GiB of a 2 GiB host. The clamav and freshclam limits only apply
	// when the answers ask for the antivirus anyway.
	Tier {
		from: 0,
		memory: [
			("mail", "1g"),
			("db", "512m"),
			("clamav", "1152m"),
			("freshclam", "896m"),
		],
		antivirus: false,
	},
	// 3456 MiB, 84% of 4 GiB. clamd holds about 944 MiB with the full
	// signature set and freshclam about 820 MiB while it tests a download,
	// so both keep that with some room; db takes what is left above its
	// 250 MiB measured peak. clamd reloading the signatures in place needs
	// about twice its resident size, which this tier cannot hold: the
	// reload costs a container restart.
	Tier {
		from: 4 * GIB,
		memory: [
			("mail", "1g"),
			("db", "384m"),
			("clamav", "1152m"),
			("freshclam", "896m"),
		],
		antivirus: true,
	},
	// 5.875 GiB, 84% of 7 GiB: clamav keeps the 2 GiB its reload peaked at.
	// db gives up 128 MiB of its 1 GiB so the set fits from 7 GiB on.
	Tier {
		from: 7 * GIB,
		memory: [
			("mail", "2g"),
			("db", "896m"),
			("clamav", "2g"),
			("freshclam", "1g"),
		],
		antivirus: true,
	},
	// The derived message budget reaches its 1 GiB ceiling at 5g.
	Tier {
		from: 16 * GIB + 1,
		memory: [
			("mail", "4g"),
			("db", "2g"),
			("clamav", "3g"),
			("freshclam", "2g"),
		],
		antivirus: true,
	},
];

/// The least memory any tier gives `service` where it runs: what it was
/// measured to need. `None` for a service no tier sizes.
pub(crate) fn least(service: &str) -> Option<u64> {
	TIERS
		.iter()
		.filter(|tier| tier.antivirus || !matches!(service, "clamav" | "freshclam"))
		.flat_map(|tier| tier.memory)
		.filter(|(name, _)| *name == service)
		.filter_map(|(_, memory)| crate::smtp::memory_fit::parse_memory(memory))
		.min()
}

/// The limits for a host whose `MemTotal` is `mem_total` bytes: the last
/// tier it reaches.
pub(crate) fn for_host(mem_total: u64) -> Sizing {
	let tier = TIERS
		.iter()
		.rev()
		.find(|tier| mem_total >= tier.from)
		.unwrap_or(&TIERS[0]);
	Sizing {
		memory: tier.memory,
		antivirus: tier.antivirus,
	}
}

/// The host's `MemTotal`, in bytes, from a `/proc/meminfo` at `meminfo`.
pub(crate) fn mem_total(meminfo: &Path) -> Option<u64> {
	let text = crate::smtp::memory_fit::read_regular(meminfo, 1024 * 1024).ok()?;
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
	let Some(document) = crate::smtp::memory_fit::read_regular(compose, 1024 * 1024)
		.ok()
		.and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
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
