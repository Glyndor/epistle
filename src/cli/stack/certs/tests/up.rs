//! `stack up` on a split stack: the account key has to be where the
//! certificates container reads it, and the container has to be up when the
//! command returns.
//!
//! The stub `podup` answers `ps` with the rows it is given and records
//! every argv it receives, so the test sees both what the command asked
//! podup to do and what it decided about the container. No podman runs
//! here: the container is what the stub says it is.

use super::*;

/// The rows `podup ps` answers with: `mail` running, and `certs` in the
/// state and with the start the test needs.
fn rows(state: &str, started: &str) -> String {
	format!(
		r#"[{{"Service":"mail","State":"running"}},{{"Service":"certs","State":"{state}","StartedAt":"{started}"}}]"#
	)
}

/// A stub `podup` that answers `ps` with `first` the first time and `second`
/// from the second time on, and records every argv it receives in the file
/// `dir/podup.argv`.
fn podup_stub(dir: &std::path::Path, first: &str, second: &str) -> String {
	let counter = dir.join("podup.calls").display().to_string();
	let log = dir.join("podup.argv").display().to_string();
	let podup = dir.join("podup");
	std::fs::write(
		&podup,
		format!(
			"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{log}\"\nfor a in \"$@\"; do\n\
			 \tif [ \"$a\" = \"ps\" ]; then\n\
			 \t\tn=0\n\t\tif [ -f \"{counter}\" ]; then n=$(cat \"{counter}\"); fi\n\
			 \t\tn=$((n + 1))\n\t\tprintf '%s' \"$n\" > \"{counter}\"\n\
			 \t\tif [ \"$n\" -eq 1 ]; then printf '%s' '{first}'; else printf '%s' '{second}'; fi\n\
			 \t\tbreak\n\tfi\ndone\nexit 0\n"
		),
	)
	.expect("podup");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&podup, std::fs::Permissions::from_mode(0o755)).expect("mode");
	podup.display().to_string()
}

/// The argv the stub podup received, one per line.
fn argv(dir: &std::path::Path) -> String {
	std::fs::read_to_string(dir.join("podup.argv")).unwrap_or_default()
}

/// Whether the stub podup was asked for `ps`.
fn asked_for_ps(dir: &std::path::Path) -> bool {
	argv(dir)
		.lines()
		.flat_map(|line| line.split_whitespace())
		.any(|argument| argument == "ps")
}

/// A split stack: the compose file names the certificates container, and
/// the data_dir is where the account key lives.
fn split_stack(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
	let data_dir = dir.join("data");
	std::fs::create_dir_all(&data_dir).expect("data_dir");
	let compose = dir.join("compose.yaml");
	std::fs::write(&compose, Recorder::split_layout(true).compose).expect("compose");
	(data_dir, compose)
}

/// The account key, where `mail` reads it, under data_dir.
fn key_under_data_dir(data_dir: &std::path::Path) -> std::path::PathBuf {
	crate::acme::renew::load_or_create_account_key(data_dir).expect("key");
	crate::acme::renew::account_key_path(data_dir)
}

/// The account key is nowhere: the container cannot read the key it needs,
/// so `up` stops before it brings the stack up.
#[test]
fn up_stops_when_the_account_key_cannot_be_placed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (data_dir, compose) = split_stack(dir.path());
	let podup = podup_stub(dir.path(), &rows("running", "2026-11-02T06:30:01Z"), "[]");
	let error = up_with(
		&data_dir,
		&compose,
		&podup,
		std::time::Duration::ZERO,
		&mut inherited(&podup, &compose),
	)
	.expect_err("the account key is nowhere");
	assert!(error.contains("there is no ACME account key"), "{error}");
	assert!(
		!argv(dir.path()).contains("up -d"),
		"the stack must not come up with a container that cannot renew: {}",
		argv(dir.path())
	);
}

/// The account key is only under data_dir, where `mail` reads it: it is put
/// where the certificates container reads it, and the copy `mail` could read
/// goes once the container is up.
#[test]
fn up_puts_the_account_key_where_the_container_reads_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (data_dir, compose) = split_stack(dir.path());
	let copy = key_under_data_dir(&data_dir);
	let podup = podup_stub(
		dir.path(),
		&rows("running", "2026-11-02T06:30:01Z"),
		&rows("running", "2026-11-02T06:30:01Z"),
	);
	let code = up_with(
		&data_dir,
		&compose,
		&podup,
		std::time::Duration::ZERO,
		&mut inherited(&podup, &compose),
	)
	.expect("up");
	assert_eq!(code, ExitCode::SUCCESS);
	let placed = crate::cli::init::host_secrets::acme_account_key(&data_dir);
	assert!(
		placed.exists(),
		"the container reads the key at {}, and it has to be there",
		placed.display()
	);
	assert!(
		!copy.exists(),
		"the copy under data_dir, where mail reads it, has to go"
	);
}

/// A container that restarts between the two looks is not up: `up` says
/// what it saw and fails, so the operator does not read a stack that renews
/// nothing as one that came up.
#[test]
fn up_fails_when_the_certificates_container_does_not_stay_up() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (data_dir, compose) = split_stack(dir.path());
	let _copy = key_under_data_dir(&data_dir);
	let podup = podup_stub(
		dir.path(),
		&rows("running", "2026-11-02T06:30:01Z"),
		&rows("running", "2026-11-02T06:30:13Z"),
	);
	let error = up_with(
		&data_dir,
		&compose,
		&podup,
		std::time::Duration::ZERO,
		&mut inherited(&podup, &compose),
	)
	.expect_err("the container restarted");
	assert!(error.contains("did not stay up"), "{error}");
	assert!(error.contains("certs"), "{error}");
}

/// A compose file that cannot be read stops `up`: the stack is not brought
/// up on a guess about which layout runs.
#[test]
fn up_stops_when_the_compose_file_cannot_be_read() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (data_dir, compose) = split_stack(dir.path());
	std::fs::write(&compose, "not json").expect("garbage");
	let podup = podup_stub(dir.path(), &rows("running", "2026-11-02T06:30:01Z"), "[]");
	let error = up_with(
		&data_dir,
		&compose,
		&podup,
		std::time::Duration::ZERO,
		&mut inherited(&podup, &compose),
	)
	.expect_err("garbage");
	assert!(
		error.contains("is not the JSON epistle init writes"),
		"{error}"
	);
	assert!(
		!argv(dir.path()).contains("up -d"),
		"the stack must not come up on a guess about the layout: {}",
		argv(dir.path())
	);
}

/// A stack without the certificates container is brought up as it always
/// was: nothing waits for a container that does not run, and the account key
/// stays where `mail` reads it.
#[test]
fn up_without_the_certificates_container_waits_for_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data_dir");
	let compose = dir.path().join("compose.yaml");
	std::fs::write(&compose, Recorder::split_layout(false).compose).expect("compose");
	let copy = key_under_data_dir(&data_dir);
	let podup = podup_stub(dir.path(), &rows("running", "2026-11-02T06:30:01Z"), "[]");
	let code = up_with(
		&data_dir,
		&compose,
		&podup,
		std::time::Duration::ZERO,
		&mut inherited(&podup, &compose),
	)
	.expect("up");
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(copy.exists(), "mail renews with it without the split");
	assert!(
		!asked_for_ps(dir.path()),
		"nothing waits for a container that does not run: {}",
		argv(dir.path())
	);
}

/// The steps of `up` as the tests run them: podup inherits the streams.
fn inherited<'a>(
	podup: &'a str,
	compose: &'a std::path::Path,
) -> impl FnMut(&[&[&str]]) -> ExitCode + 'a {
	move |steps| crate::cli::stack::run_sequence(podup, compose, steps)
}
