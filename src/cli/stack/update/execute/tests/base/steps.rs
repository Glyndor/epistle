//! The steps around the restart: health, keys, the superuser and the harden.

use super::*;

#[test]
fn an_unhealthy_mail_names_the_rollback() {
	let mut host = Fake {
		fail: Some("healthy"),
		..Fake::default()
	};
	let error = execute(&mut host, &plan(false)).expect_err("mail never got healthy");
	assert!(
		error.contains("healthy failed") && error.contains("sudo epistle stack rollback"),
		"{error}"
	);
}

#[test]
fn a_failing_status_area_is_named_with_the_rollback() {
	let mut host = Fake {
		failing: vec![("db".into(), "connection refused".into())],
		..Fake::default()
	};
	let error = execute(&mut host, &plan(false)).expect_err("db fails after the restart");
	assert!(
		error.contains("db: connection refused") && error.contains("sudo epistle stack rollback"),
		"{error}"
	);
}

#[test]
fn the_keys_move_out_of_data_dir_before_the_compose_file_names_them() {
	let mut host = Fake {
		database: true,
		..Fake::default()
	};
	execute(&mut host, &plan(true)).unwrap();
	let at = |name: &str| host.calls.iter().position(|call| call == name).unwrap();
	assert!(
		at("keep") < at("keys") && at("keys") < at("write"),
		"{:?}",
		host.calls
	);
	assert!(
		host.logged.iter().any(|line| line == "moved a key"),
		"{:?}",
		host.logged
	);
}

#[test]
fn a_key_that_cannot_move_stops_the_update_before_the_compose_file_changes() {
	let mut host = Fake {
		database: true,
		fail: Some("keys"),
		..Fake::default()
	};
	let error = execute(&mut host, &plan(true)).expect_err("keys");
	assert!(error.contains("keys failed"), "{error}");
	assert!(
		!host
			.calls
			.iter()
			.any(|call| call == "write" || call.starts_with("podup")),
		"{:?}",
		host.calls
	);
}

#[test]
fn an_epistle_superuser_is_taken_apart_and_mail_reconnects() {
	let mut host = Fake {
		database: true,
		superuser: true,
		..Fake::default()
	};
	execute(&mut host, &plan(true)).unwrap();
	assert_eq!(
		host.calls[host.calls.len() - 7..],
		[
			"podup restart mail",
			"harden",
			"podup restart mail",
			"healthy mail",
			"status",
			"discard",
			"images ghcr.io/glyndor/epistle:0.12.5"
		],
		"mail's pooled sessions still carry the renamed superuser until it restarts"
	);
}

#[test]
fn a_failed_harden_names_the_rollback() {
	let mut host = Fake {
		database: true,
		fail: Some("harden"),
		..Fake::default()
	};
	let error = execute(&mut host, &plan(true)).expect_err("harden");
	assert!(
		error.contains("harden failed") && error.contains("sudo epistle stack rollback"),
		"{error}"
	);
	assert!(!host.calls.iter().any(|call| call.starts_with("healthy")));
}
