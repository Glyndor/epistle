//! The move: stop what holds the old mapping, rewrite the account's entries,
//! shift the files, start again, and undo every step on a failure.
//!
//! The order follows podman-system-migrate(1): the running containers and
//! the pause process that keeps the user namespace alive are stopped before
//! the tables change, or the old mapping survives the edit. A journal is
//! written before the tables change and removed only once the move is
//! complete or undone, so a run that was killed half way is undone by the
//! next one before it tries again.

use super::shift::{IdShift, Shift, Tally};
use super::table::{self, Block};

/// The user units that run the stack or hold its user namespace, in the
/// order they are stopped. They are started again in reverse.
pub(crate) const UNITS: [&str; 4] = [
	"podup-epistle-update.timer",
	"podup-epistle.service",
	"podman.service",
	"podman.socket",
];

/// The operations a move needs from the host. The real implementation runs
/// the commands; the tests record them.
pub(crate) trait Host {
	/// The current `/etc/subuid` and `/etc/subgid`.
	fn tables(&mut self) -> Result<(String, String), String>;
	/// Run `usermod <args> glyndor-epistle`.
	fn usermod(&mut self, args: &[String]) -> Result<(), String>;
	/// Which of [`UNITS`] are active.
	fn active_units(&mut self) -> Result<Vec<String>, String>;
	/// `systemctl --user stop` the units, as the account.
	fn stop_units(&mut self, units: &[String]) -> Result<(), String>;
	/// `systemctl --user start` the units, as the account.
	fn start_units(&mut self, units: &[String]) -> Result<(), String>;
	/// The ids of the account's running containers.
	fn running_containers(&mut self) -> Result<Vec<String>, String>;
	/// `podman start` the containers, as the account.
	fn start_containers(&mut self, ids: &[String]) -> Result<(), String>;
	/// `podman system migrate`, as the account.
	fn migrate(&mut self) -> Result<(), String>;
	/// Shift the owner of the account's files.
	fn shift(&mut self, shift: Shift) -> Result<Tally, String>;
	/// How many of the account's files have an id in the given blocks.
	fn owned(&mut self, uid: Option<Block>, gid: Option<Block>) -> Result<u64, String>;
	/// The journal of a move in progress, if there is one.
	fn journal(&mut self) -> Result<Option<String>, String>;
	/// Write the journal, or remove it with `None`.
	fn set_journal(&mut self, text: Option<&str>) -> Result<(), String>;
	/// Report one step to the operator.
	fn log(&mut self, line: &str);
}

/// Where the move goes: the first id of the new subuid and subgid blocks.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Targets {
	/// First id of the new subuid block.
	pub(crate) uid: u64,
	/// First id of the new subgid block.
	pub(crate) gid: u64,
}

/// One table's move: the block left and the block taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pair {
	/// The block the account held.
	pub(crate) old: Block,
	/// The block it moves to.
	pub(crate) new: Block,
}

/// A whole move, with what was running before it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Plan {
	/// The subuid move, when that table overlapped.
	pub(crate) uid: Option<Pair>,
	/// The subgid move, when that table overlapped.
	pub(crate) gid: Option<Pair>,
	/// The units that were active and are started again.
	pub(crate) units: Vec<String>,
	/// The containers that were running outside the podup unit.
	pub(crate) containers: Vec<String>,
}

/// Move the account off any block it shares with another account.
///
/// `Ok` carries a summary (also when there was nothing to move); `Err`
/// carries what failed and what state the host was left in.
pub(crate) fn run(host: &mut impl Host, targets: Targets) -> Result<String, String> {
	if let Some(text) = host.journal()? {
		let plan = super::journal::parse(&text)?;
		host.log("a previous move did not finish; undoing it first");
		undo(host, &plan, Stage::Shifted).map_err(|error| {
			format!("{error}; the journal of the unfinished move is kept for the next run")
		})?;
		host.set_journal(None)?;
	}
	let (subuid, subgid) = host.tables()?;
	let Some(mut plan) = plan(&subuid, &subgid, targets)? else {
		return Ok(format!(
			"{} overlaps no other account; nothing to move",
			table::ACCOUNT
		));
	};
	let shift = shift_of(&plan)?;
	let taken = host.owned(plan.uid.map(|pair| pair.new), plan.gid.map(|pair| pair.new))?;
	if taken > 0 {
		return Err(format!(
			"{taken} of the account's files already have ids in the target block; nothing was changed"
		));
	}
	plan.units = host.active_units()?;
	if !plan.units.iter().any(|unit| unit == UNITS[1]) {
		plan.containers = host.running_containers()?;
	}
	host.log(&format!("moving {}", describe(&plan)));
	let mut stage = Stage::Stopped;
	let result = (|| {
		host.stop_units(&plan.units)?;
		host.migrate()?;
		host.set_journal(Some(&super::journal::render(&plan)))?;
		stage = Stage::Rewritten;
		host.usermod(&usermod_args(&plan, false))?;
		let (uid_after, gid_after) = host.tables()?;
		verify(&plan, (&subuid, &subgid), (&uid_after, &gid_after))?;
		stage = Stage::Shifted;
		let tally = host.shift(shift)?;
		host.log(&format!(
			"shifted the owner of {} of {} files",
			tally.changed, tally.scanned
		));
		host.migrate()?;
		restart(host, &plan)
	})();
	match result {
		Ok(()) => {
			host.set_journal(None)?;
			Ok(format!("moved {}", describe(&plan)))
		}
		Err(error) => match undo(host, &plan, stage) {
			Ok(()) => {
				host.set_journal(None)?;
				Err(format!(
					"{error}; the old ranges are back in place and the stack is as it was"
				))
			}
			Err(undo_error) => Err(format!(
				"{error}; undoing it failed too ({undo_error}), so the journal is kept and the next \
				 run of `epistle move-subids` undoes it"
			)),
		},
	}
}

/// How far a move got, which decides what [`undo`] reverts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
	/// Only stopped.
	Stopped,
	/// The tables may have been rewritten.
	Rewritten,
	/// Files may have been shifted.
	Shifted,
}

/// Revert a move that reached `stage`. Each step is safe to repeat: the
/// shift back only touches ids in the new blocks, and a table already back
/// on the old block is not rewritten.
fn undo(host: &mut impl Host, plan: &Plan, stage: Stage) -> Result<(), String> {
	if stage >= Stage::Shifted {
		host.shift(shift_of(plan)?.reversed())?;
	}
	if stage >= Stage::Rewritten {
		let (subuid, subgid) = host.tables()?;
		let back = Plan {
			uid: plan.uid.filter(|pair| held(&subuid, pair.new)),
			gid: plan.gid.filter(|pair| held(&subgid, pair.new)),
			..Plan::default()
		};
		if back.uid.is_some() || back.gid.is_some() {
			host.usermod(&usermod_args(&back, true))?;
		}
		host.migrate()?;
	}
	restart(host, plan)
}

/// Start what was running before the move.
fn restart(host: &mut impl Host, plan: &Plan) -> Result<(), String> {
	let units: Vec<String> = plan.units.iter().rev().cloned().collect();
	if !units.is_empty() {
		host.start_units(&units)?;
	}
	if !plan.containers.is_empty() {
		host.start_containers(&plan.containers)?;
	}
	Ok(())
}

/// The move for both tables, or `None` when neither overlaps.
fn plan(subuid: &str, subgid: &str, targets: Targets) -> Result<Option<Plan>, String> {
	let pair = |name: &str, text: &str, start: u64| -> Result<Option<Pair>, String> {
		let Some(old) = table::overlapping(text).map_err(|error| format!("{name}: {error}"))?
		else {
			return Ok(None);
		};
		let new = Block {
			start,
			count: old.count,
		};
		if !table::is_free(text, new) {
			return Err(format!(
				"{name}: the target block {} is not free",
				new.span()
			));
		}
		Ok(Some(Pair { old, new }))
	};
	let uid = pair("subuid", subuid, targets.uid)?;
	let gid = pair("subgid", subgid, targets.gid)?;
	Ok((uid.is_some() || gid.is_some()).then(|| Plan {
		uid,
		gid,
		..Plan::default()
	}))
}

/// Whether the account holds exactly `block` in `text`.
fn held(text: &str, block: Block) -> bool {
	table::parse(text).iter().any(|range| {
		range.owner == table::ACCOUNT && range.first == block.start && range.last == block.last()
	})
}

/// Check the rewrite touched nothing but the account's moved entries.
fn verify(plan: &Plan, before: (&str, &str), after: (&str, &str)) -> Result<(), String> {
	for (name, pair, before, after) in [
		("subuid", plan.uid, before.0, after.0),
		("subgid", plan.gid, before.1, after.1),
	] {
		match pair {
			Some(pair) => table::moved(before, after, pair.old, pair.new),
			None if before == after => Ok(()),
			None => Err("the table changed although it was not moved".to_string()),
		}
		.map_err(|error| format!("usermod left /etc/{name} in an unexpected state: {error}"))?;
	}
	Ok(())
}

/// The `usermod` options for the move, or for its reverse.
fn usermod_args(plan: &Plan, reverse: bool) -> Vec<String> {
	let mut args = Vec::new();
	for (kind, pair) in [("subuids", plan.uid), ("subgids", plan.gid)] {
		if let Some(pair) = pair {
			let (from, to) = if reverse {
				(pair.new, pair.old)
			} else {
				(pair.old, pair.new)
			};
			args.extend([
				format!("--del-{kind}"),
				from.span(),
				format!("--add-{kind}"),
				to.span(),
			]);
		}
	}
	args
}

/// The file ownership shift that follows the plan.
fn shift_of(plan: &Plan) -> Result<Shift, String> {
	let id = |pair: Option<Pair>| -> Result<Option<IdShift>, String> {
		pair.map(|pair| {
			let narrow = |value: u64| {
				u32::try_from(value).map_err(|_| format!("id {value} is out of range"))
			};
			Ok(IdShift {
				from: narrow(pair.old.start)?,
				to: narrow(pair.new.start)?,
				count: narrow(pair.old.count)?,
			})
		})
		.transpose()
	};
	Ok(Shift {
		uid: id(plan.uid)?,
		gid: id(plan.gid)?,
	})
}

/// `glyndor-epistle subuid A-B to C-D, subgid ...` for the log.
fn describe(plan: &Plan) -> String {
	let mut parts = Vec::new();
	for (name, pair) in [("subuid", plan.uid), ("subgid", plan.gid)] {
		if let Some(pair) = pair {
			parts.push(format!("{name} {} to {}", pair.old.span(), pair.new.span()));
		}
	}
	format!("{} {}", table::ACCOUNT, parts.join(", "))
}

#[cfg(test)]
#[path = "mover_tests.rs"]
mod tests;
