//! The journal a move writes before it rewrites the tables: enough to undo
//! it after the process was killed half way.
//!
//! One record per line: `subuid <old start> <new start> <count>` (and
//! `subgid`), `unit <name>` for each unit to start again, `container <id>`
//! for each container to start again.

use super::mover::{Pair, Plan};
use super::table::Block;

/// Render `plan` as journal text.
pub(crate) fn render(plan: &Plan) -> String {
	let mut text = String::new();
	for (name, pair) in [("subuid", plan.uid), ("subgid", plan.gid)] {
		if let Some(pair) = pair {
			text.push_str(&format!(
				"{name} {} {} {}\n",
				pair.old.start, pair.new.start, pair.old.count
			));
		}
	}
	for unit in &plan.units {
		text.push_str(&format!("unit {unit}\n"));
	}
	for id in &plan.containers {
		text.push_str(&format!("container {id}\n"));
	}
	text
}

/// Read journal text back into the plan it was rendered from.
pub(crate) fn parse(text: &str) -> Result<Plan, String> {
	let mut plan = Plan::default();
	for line in text.lines().filter(|line| !line.trim().is_empty()) {
		let fields: Vec<&str> = line.split_whitespace().collect();
		match fields.as_slice() {
			[name @ ("subuid" | "subgid"), old, new, count] => {
				let number = |value: &str| {
					value
						.parse::<u64>()
						.ok()
						.ok_or_else(|| format!("journal line {line:?} has a bad number"))
				};
				let count = number(count)?;
				if count == 0 {
					return Err(format!("journal line {line:?} moves no ids"));
				}
				let pair = Some(Pair {
					old: Block {
						start: number(old)?,
						count,
					},
					new: Block {
						start: number(new)?,
						count,
					},
				});
				if *name == "subuid" {
					plan.uid = pair;
				} else {
					plan.gid = pair;
				}
			}
			["unit", unit] => plan.units.push((*unit).to_string()),
			["container", id] => plan.containers.push((*id).to_string()),
			_ => return Err(format!("journal line {line:?} is not one I wrote")),
		}
	}
	if plan.uid.is_none() && plan.gid.is_none() {
		return Err("the journal names no table to undo".to_string());
	}
	Ok(plan)
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
