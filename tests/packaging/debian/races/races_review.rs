//! What the postinst does when the account never appears, when a directory it
//! would create already exists, when it runs again as a reconfigure, and when
//! another tool takes the chosen id block between two attempts.

use super::races::{Host, Setup, flaky};

/// A `stat` that reports `owner` and `mode` for the directories under the
/// fixture root and defers to the real one for everything else.
fn stat_reporting(owner: &str, mode: &str) -> (&'static str, String) {
	(
		"stat",
		format!(
			"for arg do last=$arg; done\n\
			 case \"$last\" in\n\
			 \"$HOST_ROOT\"/state*|\"$HOST_ROOT\"/config)\n\
			 case \"$*\" in *%U:%G*) echo {owner} ;; *%a*) echo {mode} ;; esac ;;\n\
			 *) exec /usr/bin/stat \"$@\" ;;\n\
			 esac"
		),
	)
}

const OWNED: &str = "glyndor-epistle:glyndor-epistle";

fn no_account() -> Host {
	Host::new(Setup {
		systemd: true,
		unit: true,
		ranges: false,
		stubs: vec![
			("getent", "exit 2".into()),
			("adduser", flaky("adduser", 99, "exit 0")),
			("loginctl", flaky("loginctl", 0, "exit 0")),
			("usermod", flaky("usermod", 0, "exit 0")),
			("install", flaky("install", 0, "exit 0")),
		],
		..Setup::default()
	})
}

#[test]
fn without_the_account_the_steps_that_need_it_are_skipped_not_retried() {
	let host = no_account();
	let run = host.configure(Some("0.12.0"));
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(host.calls("adduser").len(), 5);
	for step in ["usermod", "loginctl", "runuser", "install"] {
		assert!(
			host.calls(step).is_empty(),
			"{step}: {:?}",
			host.calls(step)
		);
	}
	assert_eq!(host.sleeps(), 4, "only the account was waited for");
	assert!(
		run.stderr
			.contains("so its directories, subordinate ids, linger")
			&& run
				.stderr
				.contains("the package is configured without them")
			&& run.stderr.contains("sudo dpkg-reconfigure epistle"),
		"{}",
		run.stderr
	);
}

#[test]
fn a_directory_with_the_wrong_owner_or_mode_is_named_with_the_repair() {
	for (owner, mode, warns) in [
		("root:root", "700", true),
		(OWNED, "755", true),
		(OWNED, "700", false),
		(OWNED, "500", false),
	] {
		let host = Host::new(Setup {
			stubs: vec![stat_reporting(owner, mode)],
			..Setup::default()
		});
		let run = host.configure(None);
		assert_eq!(run.code, Some(0), "{}", run.stderr);
		let state = host.root().join("state");
		let repair = format!(
			"sudo chown glyndor-epistle:glyndor-epistle {0} && sudo chmod 0700 {0}",
			state.display()
		);
		assert_eq!(
			run.stderr.contains(&repair),
			warns,
			"{owner} {mode}: {}",
			run.stderr
		);
	}
}

#[test]
fn the_configuration_directory_may_be_stricter_than_0750_but_not_looser() {
	let loose = Host::new(Setup {
		stubs: vec![stat_reporting(OWNED, "755")],
		..Setup::default()
	});
	let run = loose.configure(None);
	let config = loose.root().join("config");
	assert!(
		run.stderr
			.contains(&format!("sudo chmod 0750 {}", config.display())),
		"{}",
		run.stderr
	);
	let strict = Host::new(Setup {
		stubs: vec![stat_reporting(OWNED, "700")],
		..Setup::default()
	});
	assert!(!strict.configure(None).stderr.contains("chmod 0750"));
}

#[test]
fn a_reconfigure_after_a_range_failure_migrates_and_does_not_update_the_stack() {
	let host = Host::new(Setup {
		ranges: false,
		unit: true,
		stubs: vec![(
			"usermod",
			flaky(
				"usermod",
				0,
				"printf 'glyndor-epistle:100000:65536\\n' | tee -a \"$HOST_ROOT/subuid\" >> \"$HOST_ROOT/subgid\"",
			),
		)],
		..Setup::default()
	});
	let run = host.configure(Some("0.12.3"));
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	let calls = host.calls("runuser");
	assert!(
		calls
			.iter()
			.any(|call| call.ends_with("podman system migrate")),
		"{calls:?}"
	);
	assert!(
		!calls.iter().any(|call| call.contains("stack update")),
		"{calls:?}"
	);
}

#[test]
fn the_block_is_chosen_again_when_another_tool_takes_it_between_attempts() {
	let host = Host::new(Setup {
		ranges: false,
		// The first attempt fails, and by then another account holds 100000.
		stubs: vec![(
			"usermod",
			flaky(
				"usermod",
				1,
				"printf 'glyndor-epistle:165536:65536\\n' | tee -a \"$HOST_ROOT/subuid\" >> \"$HOST_ROOT/subgid\"",
			)
			.replace(
				"echo \"usermod: simulated failure $n\" >&2;",
				"printf 'tester:100000:65536\\n' | tee -a \"$HOST_ROOT/subuid\" >> \"$HOST_ROOT/subgid\"; echo \"usermod: simulated failure $n\" >&2;",
			),
		)],
		..Setup::default()
	});
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	let calls = host.calls("usermod");
	assert_eq!(calls.len(), 2, "{calls:?}");
	assert!(calls[0].starts_with("--add-subuids 100000-"), "{calls:?}");
	assert!(calls[1].starts_with("--add-subuids 165536-"), "{calls:?}");
}

#[test]
fn no_free_block_is_reported_once_and_not_waited_for() {
	let host = Host::new(Setup {
		ranges: false,
		..Setup::default()
	});
	std::fs::write(
		host.root().join("login.defs"),
		"SUB_UID_MAX 100000\nSUB_GID_MAX 100000\n",
	)
	.unwrap();
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert!(host.calls("usermod").is_empty());
	assert_eq!(host.sleeps(), 0);
	assert_eq!(run.stderr.matches("no free block of 65536").count(), 1);
	assert!(!run.stderr.contains("could not add"), "{}", run.stderr);
}
