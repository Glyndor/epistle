//! `epistle stack resources`: show and change the memory and process limits
//! of the stack's services.
//!
//! `set` records the value where `epistle init` records answered limits
//! (`x-epistle-resources` in `compose.yaml`, which `stack update` reads
//! back) and in the service's own `mem_limit` or `pids_limit`, so the file
//! stays what `stack update` renders. The running container keeps its old
//! limits until `epistle stack update` recreates it.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;
use serde::Serialize;
use serde_json::Value;

use crate::cli::init::resources::{ServiceResources, problems};
use crate::smtp::memory_fit::parse_memory;

/// The most bytes of `compose.yaml` read: the file `epistle init` writes is
/// a few KiB.
const MAX_COMPOSE_BYTES: u64 = 1024 * 1024;

/// `epistle stack resources set`.
#[derive(Debug, Clone, Subcommand)]
pub enum ResourcesCli {
	/// Change the memory or process limit of one service.
	///
	/// The new value is written to compose.yaml; `epistle stack update`
	/// recreates the service with it.
	Set {
		/// The service: mail, db, clamav or freshclam.
		#[arg(value_name = "SERVICE")]
		service: String,
		/// The memory limit: a whole number followed by k, m or g (`2g`).
		#[arg(long, value_name = "SIZE")]
		memory: Option<String>,
		/// The most processes and threads the service may run at once.
		#[arg(long, value_name = "N")]
		pids: Option<u32>,
	},
}

/// One service's limits as `compose.yaml` has them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ServiceLimit {
	/// The service name.
	pub(crate) service: String,
	/// `mem_limit` as written (`2g`); `None` when the service has none.
	pub(crate) memory: Option<String>,
	/// The same limit in bytes.
	pub(crate) memory_bytes: Option<u64>,
	/// `pids_limit`.
	pub(crate) pids: Option<u64>,
}

/// What `set` changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Change {
	/// The limits before.
	pub(crate) before: ServiceLimit,
	/// The limits written.
	pub(crate) after: ServiceLimit,
}

/// The limits of every service in `document`, in name order.
pub(crate) fn read_limits(document: &Value) -> Vec<ServiceLimit> {
	let Some(services) = document["services"].as_object() else {
		return Vec::new();
	};
	let mut limits: Vec<ServiceLimit> = services
		.iter()
		.map(|(name, service)| {
			let memory = service["mem_limit"].as_str().map(str::to_string);
			ServiceLimit {
				service: name.clone(),
				memory_bytes: memory.as_deref().and_then(parse_memory),
				memory,
				pids: service["pids_limit"].as_u64(),
			}
		})
		.collect();
	limits.sort_by(|a, b| a.service.cmp(&b.service));
	limits
}

/// A byte count as compose writes a memory size: whole GiB as `g`, else
/// whole MiB as `m`, else KiB as `k`.
pub(crate) fn compose_size(bytes: u64) -> String {
	const KIB: u64 = 1024;
	if bytes.is_multiple_of(KIB * KIB * KIB) {
		format!("{}g", bytes / (KIB * KIB * KIB))
	} else if bytes.is_multiple_of(KIB * KIB) {
		format!("{}m", bytes / (KIB * KIB))
	} else {
		format!("{}k", bytes / KIB)
	}
}

/// Apply `set` to the compose file text: the new text and what changed.
/// `Err` says what was refused, and nothing is to be written then.
pub(crate) fn set_limits(
	text: &str,
	service: &str,
	memory: Option<&str>,
	pids: Option<u32>,
) -> Result<(String, Change), String> {
	if memory.is_none() && pids.is_none() {
		return Err("give --memory, --pids or both".to_string());
	}
	let asked = ServiceResources {
		memory: memory.map(str::to_string),
		pids,
	};
	let one = BTreeMap::from([(service.to_string(), asked.clone())]);
	if let Some((field, reason)) = problems(&one).into_iter().next() {
		return Err(format!("{field} {reason}"));
	}
	let mut document: Value = serde_json::from_str(text)
		.map_err(|error| format!("compose.yaml is not the JSON epistle init writes: {error}"))?;
	let before = read_limits(&document)
		.into_iter()
		.find(|limit| limit.service == service)
		.ok_or_else(|| format!("compose.yaml has no `{service}` service"))?;
	let root = document
		.as_object_mut()
		.ok_or("compose.yaml is not a JSON object")?;
	// The recorded answers keep what was answered before for the field not
	// given now.
	let recorded = root
		.entry("x-epistle-resources")
		.or_insert_with(|| Value::Object(Default::default()));
	let mut merged: ServiceResources = match recorded.get(service) {
		Some(value) => serde_json::from_value(value.clone()).map_err(|error| {
			format!("compose.yaml has an x-epistle-resources epistle init did not write: {error}")
		})?,
		None => ServiceResources::default(),
	};
	merged.memory = asked.memory.or(merged.memory);
	merged.pids = asked.pids.or(merged.pids);
	let merged = serde_json::to_value(&merged).map_err(|error| error.to_string())?;
	recorded
		.as_object_mut()
		.ok_or("compose.yaml has an x-epistle-resources that is not a table")?
		.insert(service.to_string(), merged);
	let definition = &mut document["services"][service];
	if let Some(memory) = memory {
		definition["mem_limit"] = Value::from(memory);
	}
	if let Some(pids) = pids {
		definition["pids_limit"] = Value::from(pids);
	}
	let after = read_limits(&document)
		.into_iter()
		.find(|limit| limit.service == service)
		.ok_or_else(|| format!("compose.yaml has no `{service}` service"))?;
	let mut text = serde_json::to_string_pretty(&document).map_err(|error| error.to_string())?;
	text.push('\n');
	Ok((text, Change { before, after }))
}

/// Run `stack resources [set ...]` against the compose file at `compose`,
/// printing to `out`.
pub(super) fn run(
	compose: &Path,
	action: Option<ResourcesCli>,
	json: bool,
	out: &mut impl Write,
) -> ExitCode {
	let result = read_compose(compose).and_then(|text| match action {
		None => list(&text, json, out),
		Some(ResourcesCli::Set {
			service,
			memory,
			pids,
		}) => {
			let (written, change) = set_limits(&text, &service, memory.as_deref(), pids)?;
			crate::storage::write_secret(compose, written.as_bytes())
				.map_err(|error| format!("cannot write {}: {error}", compose.display()))?;
			report_change(&change, compose, json, out)
		}
	});
	match result {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			crate::cli::style::error(error);
			ExitCode::FAILURE
		}
	}
}

/// The compose file's text, read up to [`MAX_COMPOSE_BYTES`].
fn read_compose(compose: &Path) -> Result<String, String> {
	use std::io::Read;
	let file = std::fs::File::open(compose)
		.map_err(|error| format!("cannot read {}: {error}", compose.display()))?;
	let mut text = String::new();
	file.take(MAX_COMPOSE_BYTES + 1)
		.read_to_string(&mut text)
		.map_err(|error| format!("cannot read {}: {error}", compose.display()))?;
	if text.len() as u64 > MAX_COMPOSE_BYTES {
		return Err(format!(
			"{} is over {MAX_COMPOSE_BYTES} bytes, so epistle init did not write it",
			compose.display()
		));
	}
	Ok(text)
}

/// Print every service's limits and their sum.
fn list(text: &str, json: bool, out: &mut impl Write) -> Result<(), String> {
	let document: Value = serde_json::from_str(text)
		.map_err(|error| format!("compose.yaml is not the JSON epistle init writes: {error}"))?;
	let limits = read_limits(&document);
	let total: u64 = limits.iter().filter_map(|limit| limit.memory_bytes).sum();
	let written = if json {
		#[derive(Serialize)]
		struct Listing<'a> {
			services: &'a [ServiceLimit],
			total_bytes: u64,
		}
		serde_json::to_writer_pretty(
			&mut *out,
			&Listing {
				services: &limits,
				total_bytes: total,
			},
		)
		.map_err(std::io::Error::other)
		.and_then(|()| writeln!(out))
	} else {
		let mut lines = vec![format!("{:<10} {:<7} PIDS", "SERVICE", "MEMORY")];
		for limit in &limits {
			lines.push(format!(
				"{:<10} {:<7} {}",
				crate::cli::term::sanitize(&limit.service),
				crate::cli::term::sanitize(limit.memory.as_deref().unwrap_or("none")),
				limit
					.pids
					.map_or("none".to_string(), |pids| pids.to_string())
			));
		}
		lines.push(format!("{:<10} {}", "total", compose_size(total)));
		writeln!(out, "{}", lines.join("\n"))
	};
	written.map_err(|error| format!("cannot write the limits: {error}"))
}

/// Print what `set` changed and how to apply it.
fn report_change(
	change: &Change,
	compose: &Path,
	json: bool,
	out: &mut impl Write,
) -> Result<(), String> {
	let written = if json {
		serde_json::to_writer_pretty(&mut *out, change)
			.map_err(std::io::Error::other)
			.and_then(|()| writeln!(out))
	} else {
		let none = || "none".to_string();
		let mut parts = Vec::new();
		if change.before.memory != change.after.memory {
			parts.push(format!(
				"memory {} -> {}",
				change.before.memory.clone().unwrap_or_else(none),
				change.after.memory.clone().unwrap_or_else(none)
			));
		}
		if change.before.pids != change.after.pids {
			parts.push(format!(
				"pids {} -> {}",
				change
					.before
					.pids
					.map_or_else(none, |pids| pids.to_string()),
				change.after.pids.map_or_else(none, |pids| pids.to_string())
			));
		}
		if parts.is_empty() {
			parts.push("unchanged".to_string());
		}
		writeln!(
			out,
			"{}: {}\nwritten to {}; `epistle stack update` recreates {} with it",
			change.after.service,
			parts.join(", "),
			compose.display(),
			change.after.service
		)
	};
	written.map_err(|error| format!("cannot write the change: {error}"))
}

#[cfg(test)]
#[path = "stack_resources_tests.rs"]
mod tests;
