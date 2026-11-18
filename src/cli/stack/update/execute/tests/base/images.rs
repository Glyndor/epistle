//! The images and the certs container an update waits on.

use super::*;

#[test]
fn the_images_go_only_once_the_update_is_verified() {
	let mut host = Fake::default();
	execute(&mut host, &plan(true)).unwrap();
	let at = |name: &str| {
		host.calls
			.iter()
			.position(|call| call.starts_with(name))
			.unwrap()
	};
	assert!(
		at("healthy mail") < at("status") && at("status") < at("images"),
		"{:?}",
		host.calls
	);
	assert!(
		host.logged.iter().any(|line| line
			== "removed the image docker.io/clamav/clamav:1.5@sha256:old, which the update stopped using"),
		"{:?}",
		host.logged
	);
	assert!(
		host.logged.iter().any(|line| line
			== "kept the image ghcr.io/glyndor/epistle:0.12.5: a container still uses it"),
		"{:?}",
		host.logged
	);
}

#[test]
fn an_update_that_does_not_verify_keeps_its_images() {
	for (fail, failing) in [
		(Some("healthy"), Vec::new()),
		(None, vec![("config".to_string(), "refused".to_string())]),
		(Some("podup"), Vec::new()),
		(Some("write"), Vec::new()),
	] {
		let mut host = Fake {
			fail,
			failing,
			..Fake::default()
		};
		execute(&mut host, &plan(true)).expect_err("the update fails");
		assert!(
			!host.calls.iter().any(|call| call.starts_with("images")),
			"{fail:?}: {:?}",
			host.calls
		);
	}
}

#[test]
fn images_that_cannot_be_removed_do_not_fail_a_verified_update() {
	let mut host = Fake {
		fail: Some("images"),
		..Fake::default()
	};
	execute(&mut host, &plan(true)).unwrap();
	assert!(
		host.logged
			.iter()
			.any(|line| line.contains("so none was removed: images failed")),
		"{:?}",
		host.logged
	);
}

/// A split stack renews the certificate in the `certs` container, and the
/// update just recreated it: the update waits for it, and fails when it does
/// not settle.
#[test]
fn a_certs_container_that_does_not_settle_fails_the_update() {
	let mut host = Fake {
		certs: true,
		fail: Some("steady"),
		..Fake::default()
	};
	let error = execute(&mut host, &plan(false)).expect_err("certs never settled");
	assert!(error.contains("certs"), "{error}");
	assert!(error.contains("sudo epistle stack rollback"), "{error}");
	assert!(
		!host.calls.iter().any(|call| call == "status"),
		"the areas are judged only after the container settles: {:?}",
		host.calls
	);
}

#[test]
fn a_split_stack_waits_for_the_certs_container_after_the_restart() {
	let mut host = Fake {
		certs: true,
		..Fake::default()
	};
	execute(&mut host, &plan(false)).unwrap();
	let at = |name: &str| host.calls.iter().position(|call| call == name).unwrap();
	assert!(at("healthy mail") < at("steady certs"), "{:?}", host.calls);
	assert!(at("steady certs") < at("status"), "{:?}", host.calls);
}

/// The TLS area is the one that reports the certificates container, and the
/// restart is what decides whether it is up: a split stack judges it, a
/// stack without the container does not.
#[test]
fn the_tls_area_judges_the_restart_only_on_a_split_stack() {
	let mut host = Fake {
		certs: true,
		..Fake::default()
	};
	execute(&mut host, &plan(false)).unwrap();
	assert!(
		host.judged.contains(&crate::cli::status::CheckArea::Tls),
		"{:?}",
		host.judged
	);

	let mut host = Fake::default();
	execute(&mut host, &plan(false)).unwrap();
	assert!(
		!host.judged.contains(&crate::cli::status::CheckArea::Tls),
		"{:?}",
		host.judged
	);
}
