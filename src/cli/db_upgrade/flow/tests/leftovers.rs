//! What a database upgrade leaves of the major it moved away from: nothing
//! once the stack is verified on the new one, everything while it is not.

use super::fake::{Fake, NEW, OLD, OLD_DIR};
use super::upgrade;

/// The calls a verified move makes once the new major is healthy.
const REMOVALS: [&str; 3] = [
	"rm /var/lib/postgresql/18/docker",
	"rmdir /var/lib/postgresql/18",
	"rmdump /data/backups/pre-db-upgrade-18-to-19.sql.gz",
];

#[test]
fn a_verified_move_leaves_nothing_of_the_old_major_and_says_so() {
	let mut stack = Fake::new();
	upgrade(&mut stack, NEW).expect("upgrade");
	for removal in REMOVALS {
		assert!(
			stack.calls.iter().any(|call| call == removal),
			"{removal}: {:?}",
			stack.calls
		);
	}
	assert!(
		stack.calls.contains(&format!("images {OLD}")),
		"the old image is handed to the image cleanup: {:?}",
		stack.calls
	);
	for said in [
		"mail is healthy and config, ports, db pass",
		"removed the PostgreSQL 18 cluster at /var/lib/postgresql/18/docker",
		"removed the dump /data/backups/pre-db-upgrade-18-to-19.sql.gz",
		&format!("removed the image {OLD}"),
	] {
		assert!(stack.said(said), "{said}: {:?}", stack.logged);
	}
}

/// The removals come only after mail and the checks pass on the new major.
#[test]
fn nothing_is_removed_before_the_new_major_is_verified() {
	let mut stack = Fake::new();
	upgrade(&mut stack, NEW).expect("upgrade");
	let checked = stack.calls.iter().position(|call| call == "checks");
	let first_removal = stack
		.calls
		.iter()
		.position(|call| call.starts_with("rm") || call.starts_with("images"));
	assert!(
		matches!((checked, first_removal), (Some(checked), Some(removal)) if checked < removal),
		"{:?}",
		stack.calls
	);
}

fn kept_after(stack: &mut Fake, why: &str) {
	let error = upgrade(stack, NEW).expect_err("an unverified move fails");
	assert!(error.contains(why), "{error}");
	assert!(
		error.contains("PostgreSQL 19 with every table's row count unchanged"),
		"the operator is told the data did move: {error}"
	);
	assert!(
		error.contains("Nothing of PostgreSQL 18 was removed")
			&& error.contains(OLD_DIR)
			&& error.contains("pre-db-upgrade-18-to-19"),
		"the operator is told what stays and where: {error}"
	);
	assert!(
		!stack.removed_anything(),
		"an unverified move keeps the old cluster, the dump and the image: {:?}",
		stack.calls
	);
	assert!(
		stack.compose.contains(NEW),
		"the verified data is not rolled back over: {}",
		stack.compose
	);
}

#[test]
fn mail_that_does_not_come_back_healthy_keeps_the_old_major() {
	let mut stack = Fake::new();
	stack.fail = Some("healthy mail");
	kept_after(&mut stack, "mail did not come back healthy");
}

#[test]
fn a_failing_status_check_keeps_the_old_major() {
	let mut stack = Fake::new();
	stack.failing = vec![("db".to_string(), "the role has SUPERUSER".to_string())];
	kept_after(&mut stack, "status fails (db: the role has SUPERUSER)");
}

/// The directory removed is the one the old server reported, so a cluster
/// the old server did not report as its own is never touched.
#[test]
fn a_cluster_the_new_major_overlaps_or_outside_the_volume_is_kept() {
	for (old_dir, new_dir) in [
		(
			"/var/lib/postgresql/18/docker",
			"/var/lib/postgresql/18/docker",
		),
		("/var/lib/postgresql/18", "/var/lib/postgresql/18/docker"),
		("/srv/postgres/18", "/var/lib/postgresql/19/docker"),
	] {
		let mut stack = Fake::new();
		stack.old_dir = old_dir.to_string();
		stack.new_dir = new_dir.to_string();
		upgrade(&mut stack, NEW).expect("upgrade");
		assert!(
			!stack
				.calls
				.iter()
				.any(|call| call.starts_with("rm ") || call.starts_with("rmdir")),
			"{old_dir}: {:?}",
			stack.calls
		);
		assert!(
			stack.said(&format!("kept the PostgreSQL 18 cluster at {old_dir}")),
			"{old_dir}: {:?}",
			stack.logged
		);
		assert!(
			stack.calls.iter().any(|call| call.starts_with("rmdump")),
			"{old_dir}: the dump still goes: {:?}",
			stack.calls
		);
	}
}

/// A removal that fails is a leftover the operator is told about; the
/// upgrade still succeeded and the other removals still run.
#[test]
fn a_removal_that_fails_is_reported_and_the_rest_still_goes() {
	for (step, said) in [
		(
			"rm",
			"could not remove the PostgreSQL 18 cluster at /var/lib/postgresql/18/docker",
		),
		(
			"rmdump",
			"could not remove the dump /data/backups/pre-db-upgrade-18-to-19.sql.gz",
		),
		(
			"images",
			"could not tell whether the PostgreSQL 18 image is still used",
		),
	] {
		let mut stack = Fake::new();
		stack.fail = Some(step);
		upgrade(&mut stack, NEW).unwrap_or_else(|error| panic!("{step}: {error}"));
		assert!(stack.said(said), "{step}: {:?}", stack.logged);
		for other in ["rmdump", "images"] {
			assert!(
				stack.calls.iter().any(|call| call.starts_with(other)),
				"{step}: {other} still runs: {:?}",
				stack.calls
			);
		}
	}
}

/// A cluster that could not be removed leaves its parent alone too.
#[test]
fn the_parent_is_left_when_the_cluster_stays() {
	let mut stack = Fake::new();
	stack.fail = Some("rm");
	upgrade(&mut stack, NEW).expect("upgrade");
	assert!(
		!stack.calls.iter().any(|call| call.starts_with("rmdir")),
		"{:?}",
		stack.calls
	);
}

/// Without the old server's own answer there is nothing to remove later, so
/// the move does not start.
#[test]
fn an_old_server_that_does_not_say_where_its_cluster_is_is_not_moved() {
	let mut stack = Fake::new();
	stack.fail = Some("datadir");
	upgrade(&mut stack, NEW).expect_err("the move does not start");
	assert_eq!(stack.calls, ["counts", "datadir"]);
	assert!(stack.compose.contains(OLD));
}
