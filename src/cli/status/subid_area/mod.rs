//! The `subid` check: the service account's subordinate id ranges are its own.
//!
//! Rootless Podman maps a container's uids and gids onto the host ids listed
//! for the account in `/etc/subuid` and `/etc/subgid`. When another account's
//! range covers the same host ids, a process in one account's containers can
//! own files in the other's. `useradd` gives the first regular user
//! 100000-165535 by default, which is also the block older packages of epistle
//! assigned to `glyndor-epistle`, so an overlap is a real state on upgraded
//! hosts until the postinst moves it (`docs/cli.md` describes the move).

use std::path::Path;

use super::super::subid::table::{ACCOUNT, Range, parse};
use super::Ctx;
use super::report::{AreaReport, Item, Level};

/// Check the host's subordinate id tables.
pub(super) async fn check(_ctx: &Ctx) -> AreaReport {
	tokio::task::spawn_blocking(|| check_files(Path::new("/etc/subuid"), Path::new("/etc/subgid")))
		.await
		.unwrap_or_else(|_| AreaReport::single(Level::Warn, "the subordinate id check did not run"))
}

/// Judge both tables, read from the given paths.
fn check_files(subuid: &Path, subgid: &Path) -> AreaReport {
	let tables = [("subuid", subuid), ("subgid", subgid)];
	let findings: Vec<(Item, Option<String>)> = tables
		.iter()
		.map(|(name, path)| table_item(name, path))
		.collect();
	let summary = summarize(&findings);
	AreaReport::from_items(
		findings.into_iter().map(|(item, _)| item).collect(),
		summary,
	)
}

/// The `status` line: the problems when there are any, otherwise the ranges.
fn summarize(findings: &[(Item, Option<String>)]) -> String {
	let problems: Vec<String> = findings
		.iter()
		.filter(|(item, _)| item.status != Level::Ok)
		.map(|(item, _)| format!("{}: {}", item.name, item.detail))
		.collect();
	if !problems.is_empty() {
		return problems.join("; ");
	}
	match findings {
		[(_, Some(uid)), (_, Some(gid))] if uid == gid => {
			format!("{ACCOUNT} {uid} in subuid and subgid, no other account maps these ids")
		}
		_ => findings
			.iter()
			.map(|(item, _)| format!("{}: {}", item.name, item.detail))
			.collect::<Vec<_>>()
			.join("; "),
	}
}

/// The finding for one table, with the account's ranges when it holds a
/// private set. A missing file is a table without entries.
fn table_item(name: &str, path: &Path) -> (Item, Option<String>) {
	let text = match std::fs::read_to_string(path) {
		Ok(text) => text,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
		Err(error) => {
			let detail = format!("cannot read {}: {error}", path.display());
			return (Item::new(name, Level::Warn, detail), None);
		}
	};
	let (level, detail, ranges) = evaluate(&text);
	(Item::new(name, level, detail), ranges)
}

/// Judge one table: Fail when a range of [`ACCOUNT`] shares ids with a range
/// of another owner, Warn when the account has none, Ok otherwise.
fn evaluate(text: &str) -> (Level, String, Option<String>) {
	let entries = parse(text);
	let (mine, others): (Vec<&Range>, Vec<&Range>) =
		entries.iter().partition(|range| range.owner == ACCOUNT);
	if mine.is_empty() {
		let detail = format!("{ACCOUNT} has no range: rootless Podman cannot start its containers");
		return (Level::Warn, detail, None);
	}
	let ranges = mine
		.iter()
		.map(|range| format!("{}-{}", range.first, range.last))
		.collect::<Vec<_>>()
		.join(", ");
	let shared: Vec<String> = others
		.iter()
		.flat_map(|other| {
			mine.iter().filter_map(move |own| {
				let first = own.first.max(other.first);
				let last = own.last.min(other.last);
				(first <= last).then(|| format!("{} at {first}-{last}", other.owner))
			})
		})
		.collect();
	if shared.is_empty() {
		let detail = format!("{ACCOUNT} {ranges}, no other account maps these ids");
		(Level::Ok, detail, Some(ranges))
	} else {
		let detail = format!("{ACCOUNT} {ranges} overlaps {}", shared.join(", "));
		(Level::Fail, detail, None)
	}
}

#[cfg(test)]
mod tests;
