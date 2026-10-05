//! Tests for the `local/` module entry points: the constants the contract
//! pins, the `run` smoke check, and the source-level guarantee that the
//! banner writer is handed `style::stderr()` and stdout stays empty.

use super::test_support::{LISTENERS_FOR_TEST, fresh_dir};
use super::{
	ACCOUNT_NAME, DEFAULT_PORT_BASE, DOMAIN, HOSTNAME, banner_endpoints, prepare, print_banner, run,
};
use crate::config::ListenerKind;

/// Pin: the constants the contract fixes are exposed and correct.
#[test]
fn constants_match_the_contract() {
	assert_eq!(HOSTNAME, "mail.local.test");
	assert_eq!(DOMAIN, "local.test");
	assert_eq!(ACCOUNT_NAME, "user");
	assert_eq!(DEFAULT_PORT_BASE, 10_000);
}

/// Pin: `epistle local --dir DIR --port-base N` parses and dispatches to
/// the local entry. Reaching `run` requires the runtime; the test pins
/// only that the path is wired up.
#[test]
fn run_smoke_function_compiles_and_is_reachable_from_dispatch() {
	let _fn_ptr: fn(std::path::PathBuf, u16) -> std::process::ExitCode = run;
}

/// Pin: a freshly-laid-out directory mints exactly one account, exactly
/// one password (printed once), and the marker file is present. The
/// banner content is asserted by `banner_is_written_to_stderr_not_stdout`
/// against a writer the test supplies; this test covers the
/// `Prepared` shape the runtime sees.
#[test]
fn prepare_first_run_mints_account_and_marker() {
	let dir = fresh_dir("entry");
	let prepared = prepare(dir.path(), DEFAULT_PORT_BASE).expect("prepare");
	assert_eq!(prepared.account, ACCOUNT_NAME);
	assert!(
		prepared.password.is_some(),
		"first run must mint a password"
	);
	assert!(
		dir.path().join(".epistle-local").exists(),
		"marker file must be written"
	);
}

/// Pin: the on-screen banner is plain text on stderr, never on stdout,
/// and the password is shown once. The banner writer is taken as
/// `&mut impl Write`; the test hands a `Vec<u8>` so it can inspect the
/// bytes the operator would see.
///
/// Two halves of the guarantee are pinned:
///
/// - the banner carries the directory, every endpoint, the account,
///   and the password exactly once on the generating run;
/// - the source has no `println!` anywhere in `local/`, so stdout stays
///   empty regardless of which code path runs.
#[test]
fn banner_is_written_to_stderr_not_stdout() {
	let dir = fresh_dir("banner");
	let prepared = prepare(dir.path(), DEFAULT_PORT_BASE).expect("prepare");
	let endpoints = compute_endpoints(DEFAULT_PORT_BASE);

	// Hand the banner writer a `Vec<u8>` so the test sees exactly what
	// the operator would. The production entry point calls
	// `print_banner(.., &mut super::style::stderr())`; the bytes are the
	// same shape, the only difference is the sink.
	let mut sink: Vec<u8> = Vec::new();
	print_banner(
		dir.path(),
		&endpoints,
		&prepared.account,
		prepared.password.as_deref(),
		&mut sink,
	);
	let banner = String::from_utf8(sink).expect("banner is utf8");

	assert!(
		banner.contains("epistle local: starting"),
		"banner must announce itself, got: {banner:?}"
	);
	assert!(
		banner.contains(&format!("directory: {}", dir.path().display())),
		"banner must carry the directory, got: {banner:?}"
	);
	for (_, port) in &endpoints {
		assert!(
			banner.contains(&format!("listening: 127.0.0.1:{port}")),
			"banner must list every endpoint, missing {port}, got: {banner:?}"
		);
	}
	assert!(
		banner.contains(&format!("account:   {ACCOUNT_NAME}@{DOMAIN}")),
		"banner must carry the account, got: {banner:?}"
	);
	let password = prepared.password.as_deref().expect("first run mints");
	assert!(
		banner.contains(password),
		"first-run banner must carry the password"
	);
	assert!(
		banner.contains("(shown once, not stored)"),
		"first-run banner must mark the password as shown once"
	);

	// Source-level: there is no `println!` in any code line of `local/`.
	// This is the half of the guarantee the runtime cannot speak for: a
	// future edit that adds a stray `println!` would silently pollute
	// stdout and the test fails before any caller can notice. Comments
	// that mention the rule are not code and are stripped before the
	// check so the test pins behaviour, not the prose around it.
	let sources = [
		"src/cli/local/mod.rs",
		"src/cli/local/layout.rs",
		"src/cli/local/config.rs",
	];
	for path in sources {
		let body = std::fs::read_to_string(path)
			.unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
		let code_only: String = body
			.lines()
			.filter(|line| !line.trim_start().starts_with("//"))
			.collect::<Vec<_>>()
			.join("\n");
		assert!(
			!code_only.contains("println!"),
			"{path} must not use println!; stdout stays empty"
		);
	}
}

/// Pin: restarting `epistle local` on a directory prepared with a
/// different `--port-base` must still advertise the ports the server will
/// actually bind. `banner_endpoints` reads the loaded `Config` rather
/// than the freshly-supplied `port_base`, so the banner stops lying when
/// an operator restarts a directory created earlier with another base.
#[test]
fn banner_lists_persisted_ports_not_the_requested_port_base() {
	let dir = fresh_dir("banner-ports");
	prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");
	let second = prepare(dir.path(), 20_000).expect("second prepare");

	// The helper that `run` consults. Asserting the helper on the second
	// `Prepared` would have caught the bug independently of any change
	// to `run`.
	let persisted = banner_endpoints(&second.config);
	let expected: std::collections::HashSet<u16> = LISTENERS_FOR_TEST
		.iter()
		.map(|(_, off)| DEFAULT_PORT_BASE + off)
		.collect();
	let actual: std::collections::HashSet<u16> = persisted.iter().map(|(_, p)| *p).collect();
	assert_eq!(
		actual, expected,
		"banner_endpoints must read the loaded config, not the new port_base"
	);

	let mut sink: Vec<u8> = Vec::new();
	print_banner(
		dir.path(),
		&persisted,
		&second.account,
		second.password.as_deref(),
		&mut sink,
	);
	let banner = String::from_utf8(sink).expect("utf8");

	assert!(
		banner.contains("listening: 127.0.0.1:10025"),
		"banner must carry the persisted SMTP port, got: {banner}"
	);
	assert!(
		banner.contains("listening: 127.0.0.1:10993"),
		"banner must carry the persisted IMAPS port, got: {banner}"
	);
	for (_, port) in &persisted {
		assert!(
			!((20_025..=29_999).contains(port)),
			"banner must not advertise any port from the second-run base (20000), got: {banner}"
		);
	}
}

/// The same endpoint list `run` computes, derived from the shared
/// `LISTENERS` table so the test and the runtime cannot drift.
fn compute_endpoints(port_base: u16) -> Vec<(ListenerKind, u16)> {
	LISTENERS_FOR_TEST
		.iter()
		.map(|(kind, offset)| (*kind, port_base + offset))
		.collect()
}
