//! Tests for the move, against a host that applies `usermod` to in-memory
//! tables and records every other call.

use super::super::super::shift::{Shift, Tally};
use super::super::super::table::Block;
use super::{Host, Targets, run};

const TESTER: &str = "tester:100000:65536\n";
const OVERLAP: &str = "tester:100000:65536\nglyndor-epistle:100000:65536\n";
const MOVED: &str = "tester:100000:65536\nglyndor-epistle:165536:65536\n";
const TARGETS: Targets = Targets {
	uid: 165536,
	gid: 165536,
};

#[derive(Default)]
struct Fake {
	subuid: String,
	subgid: String,
	calls: Vec<String>,
	/// The call (by its recorded name) that fails the first time it runs.
	fail: Option<&'static str>,
	/// Files the account owns in the target block before the move.
	taken: u64,
	units: Vec<String>,
	journal: Option<String>,
	/// usermod applies the subuid change, then fails on subgid.
	torn_usermod: bool,
	/// What the process probe reports once the account was stopped.
	processes: Vec<String>,
}

impl Fake {
	fn new(subuid: &str, subgid: &str) -> Self {
		Self {
			subuid: subuid.to_string(),
			subgid: subgid.to_string(),
			units: vec!["podup-epistle.service".into(), "podman.socket".into()],
			..Self::default()
		}
	}

	fn call(&mut self, name: &'static str, detail: String) -> Result<(), String> {
		self.calls.push(format!("{name}{detail}"));
		if self.fail == Some(name) {
			self.fail = None;
			return Err(format!("{name} failed"));
		}
		Ok(())
	}
}

/// Apply `--del-subuids A-B --add-subuids C-D ...` the way shadow does:
/// drop the account's matching line, append the new one.
fn apply(table: &mut String, del: &str, add: &str) {
	let line = |span: &str| {
		let (first, last) = span.split_once('-').unwrap();
		let first: u64 = first.parse().unwrap();
		let last: u64 = last.parse().unwrap();
		format!("glyndor-epistle:{first}:{}\n", last - first + 1)
	};
	*table = table.replace(&line(del), "");
	table.push_str(&line(add));
}

impl Host for Fake {
	fn tables(&mut self) -> Result<(String, String), String> {
		Ok((self.subuid.clone(), self.subgid.clone()))
	}
	fn usermod(&mut self, args: &[String]) -> Result<(), String> {
		self.call("usermod", format!(" {}", args.join(" ")))?;
		for pair in args.chunks(4) {
			let table = if pair[0] == "--del-subuids" {
				&mut self.subuid
			} else {
				if self.torn_usermod {
					self.torn_usermod = false;
					return Err("usermod failed on subgid".into());
				}
				&mut self.subgid
			};
			apply(table, &pair[1], &pair[3]);
		}
		Ok(())
	}
	fn active_units(&mut self) -> Result<Vec<String>, String> {
		Ok(self.units.clone())
	}
	fn stop_units(&mut self, units: &[String]) -> Result<(), String> {
		self.call("stop", format!(" {}", units.join(" ")))
	}
	fn start_units(&mut self, units: &[String]) -> Result<(), String> {
		self.call("start", format!(" {}", units.join(" ")))
	}
	fn running_containers(&mut self) -> Result<Vec<String>, String> {
		Ok(vec!["c1".to_string()])
	}
	fn start_containers(&mut self, ids: &[String]) -> Result<(), String> {
		self.call("podman-start", format!(" {}", ids.join(" ")))
	}
	fn stop_account(&mut self) -> Result<(), String> {
		self.call("stop-account", String::new())
	}
	fn start_account(&mut self) -> Result<(), String> {
		self.call("start-account", String::new())
	}
	fn account_processes(&mut self) -> Vec<String> {
		self.processes.clone()
	}
	fn migrate(&mut self) -> Result<(), String> {
		self.call("migrate", String::new())
	}
	fn shift(&mut self, shift: Shift) -> Result<Tally, String> {
		let uid = shift.uid.map(|s| format!(" uid {}->{}", s.from, s.to));
		let gid = shift.gid.map(|s| format!(" gid {}->{}", s.from, s.to));
		self.call(
			"shift",
			format!("{}{}", uid.unwrap_or_default(), gid.unwrap_or_default()),
		)?;
		Ok(Tally {
			scanned: 10,
			changed: 4,
		})
	}
	fn owned(&mut self, _: Option<Block>, _: Option<Block>) -> Result<u64, String> {
		Ok(self.taken)
	}
	fn journal(&mut self) -> Result<Option<String>, String> {
		Ok(self.journal.clone())
	}
	fn set_journal(&mut self, text: Option<&str>) -> Result<(), String> {
		self.journal = text.map(str::to_string);
		Ok(())
	}
	fn log(&mut self, _: &str) {}
}

const FORWARD: &str = "usermod --del-subuids 100000-165535 --add-subuids 165536-231071 \
	--del-subgids 100000-165535 --add-subgids 165536-231071";
const BACKWARD: &str = "usermod --del-subuids 165536-231071 --add-subuids 100000-165535 \
	--del-subgids 165536-231071 --add-subgids 100000-165535";

#[test]
fn no_overlap_touches_nothing() {
	let mut host = Fake::new(MOVED, MOVED);
	let summary = run(&mut host, TARGETS).expect("nothing to do is a success");
	assert!(summary.contains("nothing to move"), "{summary}");
	assert!(host.calls.is_empty(), "{:?}", host.calls);
}

#[test]
fn an_overlap_is_moved_in_order_and_the_stack_comes_back() {
	let mut host = Fake::new(OVERLAP, OVERLAP);
	let summary = run(&mut host, TARGETS).expect("the move succeeds");
	assert_eq!(
		host.calls,
		[
			"stop podup-epistle.service podman.socket",
			"migrate",
			"stop-account",
			FORWARD,
			"shift uid 100000->165536 gid 100000->165536",
			"start-account",
			"start podman.socket podup-epistle.service",
		]
	);
	assert_eq!((host.subuid.as_str(), host.subgid.as_str()), (MOVED, MOVED));
	assert_eq!(host.journal, None, "a finished move leaves no journal");
	assert!(
		summary.contains("subuid 100000-165535 to 165536-231071"),
		"{summary}"
	);
}

#[test]
fn only_the_overlapping_table_moves() {
	let mut host = Fake::new(OVERLAP, MOVED);
	run(&mut host, TARGETS).unwrap();
	assert!(
		host.calls.contains(
			&"usermod --del-subuids 100000-165535 --add-subuids 165536-231071".to_string()
		),
		"{:?}",
		host.calls
	);
	assert!(host.calls.contains(&"shift uid 100000->165536".to_string()));
	assert_eq!(host.subgid, MOVED);
}

#[test]
fn containers_started_by_hand_are_started_again_by_id() {
	let mut host = Fake::new(OVERLAP, OVERLAP);
	host.units = vec!["podman.socket".into()];
	run(&mut host, TARGETS).unwrap();
	assert_eq!(
		host.calls.last().map(String::as_str),
		Some("podman-start c1")
	);
}

#[test]
fn a_target_in_use_is_refused_before_anything_stops() {
	let mut host = Fake::new(OVERLAP, OVERLAP);
	let busy = Targets {
		uid: 100000,
		gid: 165536,
	};
	let error = run(&mut host, busy).expect_err("the target overlaps");
	assert!(error.contains("not free"), "{error}");
	let mut host = Fake::new(OVERLAP, OVERLAP);
	host.taken = 3;
	let error = run(&mut host, TARGETS).expect_err("files hold target ids");
	assert!(error.contains("nothing was changed"), "{error}");
	assert!(host.calls.is_empty(), "{:?}", host.calls);
}

/// Fail `step` and check the tables, the stack and the journal end where
/// they started.
fn fails_and_restores(step: &'static str, expected_tail: &[&str]) {
	let mut host = Fake::new(OVERLAP, OVERLAP);
	host.fail = Some(step);
	let error = run(&mut host, TARGETS).expect_err("the step fails");
	assert!(
		error.contains("old ranges are back in place"),
		"{step}: {error}"
	);
	assert_eq!(
		(host.subuid.as_str(), host.subgid.as_str()),
		(OVERLAP, OVERLAP),
		"{step}: the account must end on its old block"
	);
	assert_eq!(host.journal, None, "{step}");
	let tail: Vec<&str> = host.calls[host.calls.len() - expected_tail.len()..]
		.iter()
		.map(String::as_str)
		.collect();
	assert_eq!(tail, expected_tail, "{step}: {:?}", host.calls);
}

#[test]
fn every_failure_is_undone() {
	let start = "start podman.socket podup-epistle.service";
	let back_shift = "shift uid 165536->100000 gid 165536->100000";
	fails_and_restores(
		"stop",
		&[
			"stop podup-epistle.service podman.socket",
			"start-account",
			start,
		],
	);
	fails_and_restores("migrate", &["migrate", "start-account", start]);
	fails_and_restores("stop-account", &["stop-account", "start-account", start]);
	fails_and_restores("usermod", &[FORWARD, "start-account", start]);
	fails_and_restores(
		"shift",
		&[back_shift, "stop-account", BACKWARD, "start-account", start],
	);
	fails_and_restores(
		"start-account",
		&[back_shift, "stop-account", BACKWARD, "start-account", start],
	);
	fails_and_restores(
		"start",
		&[back_shift, "stop-account", BACKWARD, "start-account", start],
	);
}

#[test]
fn usermod_is_refused_while_the_account_has_processes() {
	let mut host = Fake::new(OVERLAP, OVERLAP);
	host.processes = vec!["4242 catatonit".to_string(), "4250 conmon".to_string()];
	let error = run(&mut host, TARGETS).expect_err("processes are left");
	assert!(
		!host.calls.iter().any(|call| call.starts_with("usermod")),
		"usermod must not run while the account has processes: {:?}",
		host.calls
	);
	assert!(
		error.contains("4242 catatonit") && error.contains("still has 2 processes"),
		"{error}"
	);
	assert!(error.contains("old ranges are back in place"), "{error}");
	assert_eq!(
		(host.subuid.as_str(), host.subgid.as_str()),
		(OVERLAP, OVERLAP)
	);
	assert_eq!(
		host.calls.last().map(String::as_str),
		Some("start podman.socket podup-epistle.service"),
		"{:?}",
		host.calls
	);
}

#[test]
fn a_usermod_that_moved_one_table_is_put_back() {
	let mut host = Fake::new(OVERLAP, OVERLAP);
	host.torn_usermod = true;
	let error = run(&mut host, TARGETS).expect_err("usermod failed half way");
	assert!(error.contains("old ranges are back"), "{error}");
	assert_eq!(
		(host.subuid.as_str(), host.subgid.as_str()),
		(OVERLAP, OVERLAP)
	);
	assert!(
		host.calls.contains(
			&"usermod --del-subuids 165536-231071 --add-subuids 100000-165535".to_string()
		),
		"only the table that moved is moved back: {:?}",
		host.calls
	);
}

#[test]
fn an_unfinished_move_is_undone_before_trying_again() {
	let mut host = Fake::new(MOVED, OVERLAP);
	host.journal =
		Some("subuid 100000 165536 65536\nsubgid 100000 165536 65536\nunit podman.socket\n".into());
	run(&mut host, TARGETS).unwrap();
	assert_eq!(
		&host.calls[..5],
		[
			"shift uid 165536->100000 gid 165536->100000",
			"stop-account",
			"usermod --del-subuids 165536-231071 --add-subuids 100000-165535",
			"start-account",
			"start podman.socket",
		],
		"the journal is undone first"
	);
	assert_eq!((host.subuid.as_str(), host.subgid.as_str()), (MOVED, MOVED));
	assert_eq!(host.journal, None);
}

#[test]
fn the_tester_line_is_never_rewritten() {
	let mut host = Fake::new(OVERLAP, OVERLAP);
	run(&mut host, TARGETS).unwrap();
	assert!(host.subuid.starts_with(TESTER) && host.subgid.starts_with(TESTER));
	assert!(
		host.calls
			.iter()
			.all(|call| !call.starts_with("usermod") || !call.contains("tester")),
		"{:?}",
		host.calls
	);
}
