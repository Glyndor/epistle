//! The steps of `postinst configure` that run before the user manager is
//! involved: the account, its directories and its subordinate id ranges.
//! Each one depends on something another process may still be doing (a lock
//! on `/etc/subuid`, a name service that has not caught up), so a stub fails
//! its first calls and the script must ask again, and when it never works the
//! script must say what failed and still exit 0.

use super::races::{Host, Setup, flaky};

const MARK_ACCOUNT: &str = "touch \"$STUB_STATE/account\"";

fn setup_without_account(adduser: String) -> Setup {
	Setup {
		stubs: vec![
			("getent", "[ -e \"$STUB_STATE/account\" ]".to_string()),
			("adduser", adduser),
		],
		..Setup::default()
	}
}

#[test]
fn adduser_that_fails_twice_is_asked_again() {
	let host = Host::new(setup_without_account(flaky("adduser", 2, MARK_ACCOUNT)));
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(host.calls("adduser").len(), 3);
	assert!(!run.stderr.contains("could not create"), "{}", run.stderr);
}

#[test]
fn an_attempt_that_created_the_account_before_failing_is_not_repeated() {
	let host = Host::new(setup_without_account(flaky(
		"adduser",
		0,
		&format!("{MARK_ACCOUNT}\nexit 1"),
	)));
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(
		host.calls("adduser").len(),
		1,
		"the lookup that precedes each attempt sees the account and stops"
	);
}

#[test]
fn an_account_that_cannot_be_created_does_not_abort_the_package() {
	let host = Host::new(setup_without_account(flaky("adduser", 99, "exit 0")));
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(host.calls("adduser").len(), 5, "bounded: five attempts");
	assert!(
		run.stderr
			.contains("could not create the glyndor-epistle account")
			&& run.stderr.contains("sudo dpkg-reconfigure epistle"),
		"{}",
		run.stderr
	);
}

#[test]
fn install_that_fails_twice_is_asked_again_for_each_directory() {
	let host = Host::new(Setup {
		state: false,
		stubs: vec![(
			"install",
			flaky(
				"install",
				2,
				"for arg do last=$arg; done\nmkdir -p \"$last\"",
			),
		)],
		..Setup::default()
	});
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(
		host.calls("install").len(),
		4,
		"three attempts for the state directory, which also holds data, and one for the configuration"
	);
	for dir in ["state", "state/data", "config"] {
		assert!(host.root().join(dir).is_dir(), "{dir} was not created");
	}
	assert!(!run.stderr.contains("could not create"), "{}", run.stderr);
}

#[test]
fn a_directory_that_cannot_be_created_is_named_and_does_not_abort() {
	let host = Host::new(Setup {
		state: false,
		stubs: vec![("install", flaky("install", 99, "exit 0"))],
		..Setup::default()
	});
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	let state = format!("could not create {}", host.root().join("state").display());
	assert!(run.stderr.contains(&state), "{}", run.stderr);
	assert!(run.stderr.contains("sudo dpkg-reconfigure epistle"));
}

#[test]
fn a_locked_subid_table_is_waited_for_and_the_runtime_is_migrated_afterwards() {
	let host = Host::new(Setup {
		ranges: false,
		stubs: vec![(
			"usermod",
			flaky(
				"usermod",
				2,
				"printf 'glyndor-epistle:100000:65536\\n' | tee -a \"$HOST_ROOT/subuid\" >> \"$HOST_ROOT/subgid\"",
			),
		)],
		..Setup::default()
	});
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	let calls = host.calls("usermod");
	assert_eq!(calls.len(), 3, "{calls:?}");
	assert_eq!(
		calls[2], "--add-subuids 100000-165535 --add-subgids 100000-165535 glyndor-epistle",
		"every attempt asks for the same two ranges"
	);
	assert!(
		host.calls("runuser")
			.iter()
			.any(|call| call.ends_with("podman system migrate")),
		"the ranges were added, so the runtime is migrated: {:?}",
		host.calls("runuser")
	);
	assert!(!run.stderr.contains("could not add"), "{}", run.stderr);
}

#[test]
fn ranges_that_cannot_be_added_are_reported_and_never_migrated() {
	let host = Host::new(Setup {
		ranges: false,
		stubs: vec![("usermod", flaky("usermod", 99, "exit 0"))],
		..Setup::default()
	});
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(host.calls("usermod").len(), 5);
	assert!(
		run.stderr
			.contains("could not add the subuid/subgid ranges")
			&& run.stderr.contains("locked")
			&& run.stderr.contains("sudo dpkg-reconfigure epistle"),
		"{}",
		run.stderr
	);
	assert!(host.calls("runuser").is_empty());
}

#[test]
fn a_second_run_does_only_what_is_still_missing() {
	let host = Host::new(Setup {
		ranges: false,
		state: false,
		stubs: vec![
			("getent", "[ -e \"$STUB_STATE/account\" ]".to_string()),
			("adduser", flaky("adduser", 1, MARK_ACCOUNT)),
			(
				"install",
				flaky(
					"install",
					1,
					"for arg do last=$arg; done\nmkdir -p \"$last\"",
				),
			),
			(
				"usermod",
				flaky(
					"usermod",
					1,
					"printf 'glyndor-epistle:100000:65536\\n' | tee -a \"$HOST_ROOT/subuid\" >> \"$HOST_ROOT/subgid\"",
				),
			),
		],
		..Setup::default()
	});
	assert_eq!(host.configure(None).code, Some(0));
	let before = (
		host.calls("adduser").len(),
		host.calls("install").len(),
		host.calls("usermod").len(),
	);
	let again = host.configure(Some("0.12.3"));
	assert_eq!(again.code, Some(0), "{}", again.stderr);
	assert_eq!(
		before,
		(
			host.calls("adduser").len(),
			host.calls("install").len(),
			host.calls("usermod").len()
		),
		"the account, the directories and the ranges exist, so nothing is asked for again"
	);
	assert!(host.root().join("state/data").is_dir());
}
