//! Tests for the database upgrade, against a fake stack.

use super::fake::{Fake, NEW, OLD};
use super::upgrade;

#[test]
fn the_data_moves_to_the_new_major_and_the_counts_are_compared() {
	let mut stack = Fake::new();
	upgrade(&mut stack, NEW).expect("upgrade");
	assert_eq!(
		stack.calls,
		[
			"counts",
			"datadir",
			"podup stop mail",
			"dump",
			"keep pre-db-upgrade-18-to-19",
			"podup stop db",
			"write 19",
			"podup up -d db",
			"healthy db",
			"load",
			"counts",
			"podup up -d",
			"healthy mail",
			"checks",
			"datadir",
			"rm /var/lib/postgresql/18/docker",
			"rmdir /var/lib/postgresql/18",
			"rmdump /data/backups/pre-db-upgrade-18-to-19.sql.gz",
			&format!("images {OLD}"),
		]
	);
	assert!(stack.compose.contains(NEW));
}

#[test]
fn the_same_major_is_left_alone() {
	let mut stack = Fake::new();
	upgrade(&mut stack, "docker.io/library/postgres:18@sha256:cccc").unwrap();
	assert_eq!(
		stack.logged,
		["the stack already runs PostgreSQL 18; nothing to upgrade"]
	);
	assert!(stack.calls.is_empty());
}

#[test]
fn a_downgrade_is_refused() {
	let mut stack = Fake::new();
	let error = upgrade(&mut stack, "docker.io/library/postgres:17@sha256:dddd").unwrap_err();
	assert!(error.contains("17"), "{error}");
	assert!(stack.calls.is_empty());
}

fn fails_back_to_the_old_major(step: &'static str, lossy: bool) {
	let mut stack = Fake::new();
	stack.fail = (!lossy).then_some(step);
	stack.lossy = lossy;
	let error = upgrade(&mut stack, NEW).expect_err("the upgrade fails");
	assert!(
		error.contains("PostgreSQL 18 is running again"),
		"{step}: {error}"
	);
	assert!(
		stack.compose.contains(OLD),
		"{step}: the compose file is back on 18"
	);
	assert_eq!(
		stack.calls.last().map(String::as_str),
		Some("podup up -d"),
		"{step}: the stack, mail included, is started again: {:?}",
		stack.calls
	);
	assert!(
		!stack.removed_anything(),
		"{step}: a failed move keeps the old cluster, the dump and the image: {:?}",
		stack.calls
	);
}

#[test]
fn every_failure_after_the_stop_brings_the_old_major_back() {
	for step in ["dump", "keep", "write", "healthy", "load"] {
		fails_back_to_the_old_major(step, false);
	}
	fails_back_to_the_old_major("counts", true);
}
