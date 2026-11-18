//! The database dump taken before an update and removed once it is verified.

use super::*;

#[test]
fn the_database_is_dumped_before_anything_changes() {
	let mut host = Fake {
		database: true,
		..Fake::default()
	};
	execute(&mut host, &plan(true)).unwrap();
	assert_eq!(
		host.calls,
		[
			"dump",
			"keep",
			"keys",
			"write",
			"podup up -d",
			"podup restart mail",
			"harden",
			"healthy mail",
			"status",
			"discard",
			"images ghcr.io/glyndor/epistle:0.12.5"
		]
	);
}

#[test]
fn a_failed_dump_stops_the_update_before_it_changes_anything() {
	for step in ["dump", "keep"] {
		let mut host = Fake {
			database: true,
			fail: Some(step),
			..Fake::default()
		};
		let error = execute(&mut host, &plan(true)).expect_err(step);
		assert!(error.contains("nothing was changed"), "{step}: {error}");
		assert!(
			!host
				.calls
				.iter()
				.any(|call| call == "write" || call.starts_with("podup")),
			"{step}: {:?}",
			host.calls
		);
	}
}

#[test]
fn a_stack_without_its_own_database_is_not_dumped() {
	let mut host = Fake::default();
	execute(&mut host, &plan(false)).unwrap();
	assert_eq!(
		host.calls,
		[
			"keys",
			"podup up -d",
			"podup restart mail",
			"healthy mail",
			"status",
			"images ghcr.io/glyndor/epistle:0.12.5"
		]
	);
}

#[test]
fn the_dumps_go_only_once_the_update_is_verified() {
	let mut host = Fake {
		database: true,
		..Fake::default()
	};
	execute(&mut host, &plan(true)).unwrap();
	let at = |name: &str| host.calls.iter().position(|call| call == name).unwrap();
	assert!(
		at("healthy mail") < at("status") && at("status") < at("discard"),
		"{:?}",
		host.calls
	);
	assert!(
		host.logged
			.iter()
			.any(|line| line.contains("removed 1 dump(s)")),
		"{:?}",
		host.logged
	);
}

#[test]
fn an_update_that_does_not_verify_keeps_its_dumps() {
	for (fail, failing) in [
		(Some("healthy"), Vec::new()),
		(None, vec![("db".to_string(), "refused".to_string())]),
		(Some("harden"), Vec::new()),
		(Some("podup"), Vec::new()),
	] {
		let mut host = Fake {
			database: true,
			fail,
			failing,
			..Fake::default()
		};
		execute(&mut host, &plan(true)).expect_err("the update fails");
		assert!(
			!host.calls.iter().any(|call| call == "discard"),
			"{fail:?}: {:?}",
			host.calls
		);
	}
}

#[test]
fn a_stack_without_a_database_has_no_dumps_to_remove() {
	let mut host = Fake::default();
	execute(&mut host, &plan(false)).unwrap();
	assert!(!host.calls.iter().any(|call| call == "discard"));
}

#[test]
fn dumps_that_cannot_be_removed_do_not_fail_a_verified_update() {
	let mut host = Fake {
		database: true,
		fail: Some("discard"),
		..Fake::default()
	};
	execute(&mut host, &plan(true)).unwrap();
	assert!(
		host.logged
			.iter()
			.any(|line| line.contains("could not remove the dumps")),
		"{:?}",
		host.logged
	);
}
