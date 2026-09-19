//! Tests for `local/config.rs`: port-base range, loopback binding, and
//! the `hold_outbound` invariant that the TOML loader cannot set.

use super::test_support::{LISTENERS_FOR_TEST, build_config_for_test, fresh_dir, load_for_test};
use super::{DEFAULT_PORT_BASE, LocalError, prepare};

/// Pin: every listener address in the generated `Config` is the loopback
/// IPv4 address; the six expected ports appear for `--port-base 10000`
/// and for `--port-base 20000`.
#[test]
fn loopback_every_listener_is_127_and_six_ports_match() {
	for port_base in [DEFAULT_PORT_BASE, 20_000] {
		let config = build_config_for_test(port_base).expect("build config");
		assert_eq!(config.listeners.len(), LISTENERS_FOR_TEST.len());
		let mut seen: Vec<(std::net::IpAddr, u16)> = Vec::new();
		for listener in &config.listeners {
			assert!(
				listener.addr.is_loopback(),
				"listener {:?} bound to non-loopback {}",
				listener.kind,
				listener.addr
			);
			seen.push((
				listener.addr,
				listener.port.unwrap_or(listener.kind.default_port()),
			));
		}
		let expected: std::collections::HashSet<u16> = LISTENERS_FOR_TEST
			.iter()
			.map(|(_, off)| port_base + off)
			.collect();
		let actual: std::collections::HashSet<u16> = seen.iter().map(|(_, p)| *p).collect();
		assert_eq!(
			actual, expected,
			"the six endpoints must match the contract"
		);
	}
}

/// Pin: `--port-base 65000` is refused naming the first computed port
/// that falls outside `1024..=65535`; the nearest base that keeps the
/// API listener inside the range is accepted.
#[test]
fn port_range_upper_bound_refused_with_named_port_nearest_passes() {
	let upper = prepare(tempfile::tempdir().expect("tempdir").path(), 65000);
	match upper {
		Err(LocalError::PortOutOfRange(port)) => {
			// First offset to fall outside the range: 65000 + 587 = 65587
			// (the submission port). The exact value is what the
			// operator needs to fix the offset.
			assert_eq!(port, 65_587_u32, "first out-of-range port must be 65587");
		}
		other => panic!("expected PortOutOfRange, got {other:?}"),
	}

	// Nearest port-base that passes the upper bound: 57510 keeps the API
	// listener at exactly 65535.
	let upper_dir = tempfile::tempdir().expect("tempdir");
	prepare(upper_dir.path(), 57_510).expect("57510 passes the upper bound");
}

/// Pin: a base that puts the smallest offset under `1024` is refused
/// with the offending port; the nearest base that passes is accepted.
#[test]
fn port_range_lower_bound_refused_with_named_port_nearest_passes() {
	let failing = prepare(tempfile::tempdir().expect("tempdir").path(), 998);
	match failing {
		Err(LocalError::PortOutOfRange(port)) => {
			// 998 + 25 = 1023, the SMTP port. First offset to fall
			// below 1024.
			assert_eq!(port, 1023_u32, "first under-range port must be 1023");
		}
		other => panic!("expected PortOutOfRange, got {other:?}"),
	}

	// 999 keeps +25 at exactly 1024, the inclusive lower bound.
	let passing = prepare(tempfile::tempdir().expect("tempdir").path(), 999);
	assert!(passing.is_ok(), "999 must pass: {passing:?}");
}

/// Pin: the generated `Config` has `hold_outbound == true`; the
/// `start_queue_worker()` decision is `false` for the local config and
/// `true` for an ordinary one; a `mail.toml` carrying
/// `hold_outbound = true` is rejected by `Config::load` as an unknown
/// field (with `#[serde(skip)]` + `deny_unknown_fields`).
#[test]
fn held_outbound_config_is_true_loader_rejects_toml_field_decision_pure() {
	let dir = fresh_dir("held");
	let prepared = prepare(dir.path(), DEFAULT_PORT_BASE).expect("prepare");
	assert!(
		prepared.config.hold_outbound,
		"local config must hold outbound"
	);
	assert!(
		!prepared.config.start_queue_worker(),
		"local config must NOT start the queue worker"
	);

	// Ordinary config: same struct, default `hold_outbound == false`.
	let ordinary: crate::config::Config =
		toml::from_str("hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n")
			.expect("ordinary config parses");
	assert!(
		ordinary.start_queue_worker(),
		"ordinary config must start the queue worker"
	);
	// Sanity: ordinary has hold_outbound false.
	assert!(!ordinary.hold_outbound);

	// A mail.toml carrying `hold_outbound = true` is rejected as an
	// unknown field (the field is `#[serde(skip)]` so serde never sees
	// it; `deny_unknown_fields` rejects the key).
	let bogus_path = dir.path().join("bogus.toml");
	std::fs::write(
		&bogus_path,
		"hostname = \"mail.local.test\"\ndata_dir = \"/tmp/never-read\"\nhold_outbound = true\n",
	)
	.expect("write bogus");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let permissions = std::fs::Permissions::from_mode(0o600);
		std::fs::set_permissions(&bogus_path, permissions).expect("chmod 0600");
	}
	let bogus = crate::config::Config::load(&bogus_path);
	assert!(
		matches!(bogus, Err(crate::config::ConfigError::Parse { .. })),
		"hold_outbound in TOML must be rejected as an unknown field, got {bogus:?}"
	);

	// Sanity: the marker directory we just built loads cleanly.
	let reloaded = load_for_test(&dir.path().join("mail.toml")).expect("reloads");
	assert!(
		reloaded.hold_outbound,
		"reload must restore hold_outbound = true"
	);
	assert!(!reloaded.start_queue_worker());
}

/// Pin: the generated `mail.toml` names `<dir>/data` as its `data_dir`,
/// and that path is an existing directory on disk. The previous
/// `write_mail_toml` took the future `mail.toml` path as `dir` and computed
/// `path.join("data")`, which produced `data_dir = "<dir>/mail.toml/data"`,
/// a directory under a regular file. `serve` then asked
/// `FsSpool::open_with_crypto` to create the spool under that path and
/// `create_dir_all` returned `Not a directory (os error 20)`, so the
/// process exited before any listener bound. The test loads the file back
/// through `Config::load` (the same path `serve` walks) and asserts the
/// two halves of the invariant: the path the config names and the
/// filesystem state under it.
#[test]
fn data_dir_is_sibling_of_mail_toml_not_under_it() {
	let dir = fresh_dir("datadir");
	prepare(dir.path(), DEFAULT_PORT_BASE).expect("prepare");

	let config = load_for_test(&dir.path().join("mail.toml")).expect("reloads");
	assert_eq!(
		config.data_dir,
		dir.path().join("data"),
		"data_dir must point at <dir>/data, not at any path under mail.toml"
	);
	assert!(
		dir.path().join("data").is_dir(),
		"<dir>/data must be the existing directory the spool opens under, not a path inside mail.toml"
	);
}
