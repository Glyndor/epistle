//! The steps of `postinst configure` that need the account's user manager:
//! `enable-linger` starts it in the background, so `/run/user/<uid>` and the
//! bus appear a moment later, and `epistle move-subids` stops and starts it
//! again. The script must wait for it, bounded, and when it never answers say
//! which command finishes the job. None of this may fail the package.

use super::races::{Host, Setup, flaky};

const SYSTEMD: Setup = Setup {
	stubs: Vec::new(),
	systemd: true,
	runtime: true,
	ranges: true,
	state: true,
	unit: false,
};

fn systemd(stubs: Vec<(&'static str, String)>, runtime: bool) -> Host {
	Host::new(Setup {
		stubs,
		runtime,
		..SYSTEMD
	})
}

/// A `sleep` that makes the user manager's runtime directory appear on its
/// `n`th call, as linger does a moment after `enable-linger` returns.
fn manager_up_after(n: u32) -> String {
	format!(
		"echo \"$*\" >> \"$STUB_STATE/sleep.log\"\n\
		 [ \"$(wc -l < \"$STUB_STATE/sleep.log\")\" -lt {n} ] || mkdir -p \"$HOST_ROOT/run/user/103\""
	)
}

fn socket_calls(host: &Host) -> Vec<String> {
	host.calls("runuser")
		.into_iter()
		.filter(|call| call.ends_with("enable --now podman.socket"))
		.collect()
}

#[test]
fn linger_that_fails_twice_is_asked_again() {
	let host = systemd(vec![("loginctl", flaky("loginctl", 2, "exit 0"))], true);
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(host.calls("loginctl").len(), 3);
	assert!(!run.stderr.contains("enable-linger"), "{}", run.stderr);
}

#[test]
fn linger_that_never_works_names_the_command_to_run() {
	let host = systemd(vec![("loginctl", flaky("loginctl", 99, "exit 0"))], true);
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert!(
		run.stderr
			.contains("sudo loginctl enable-linger glyndor-epistle"),
		"{}",
		run.stderr
	);
}

#[test]
fn the_socket_is_enabled_once_the_runtime_directory_appears() {
	let host = systemd(vec![("sleep", manager_up_after(2))], false);
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(socket_calls(&host).len(), 1, "{:?}", host.calls("runuser"));
	assert!(!run.stderr.contains("podman.socket"), "{}", run.stderr);
}

#[test]
fn a_user_manager_that_never_starts_is_reported_after_a_bounded_wait() {
	let host = systemd(Vec::new(), false);
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert!(socket_calls(&host).is_empty());
	assert_eq!(host.sleeps(), 9, "ten looks, two seconds apart");
	assert!(
		run.stderr.contains("is not running")
			&& run
				.stderr
				.contains("run systemctl --user enable --now podman.socket as glyndor-epistle"),
		"{}",
		run.stderr
	);
}

#[test]
fn without_linger_there_is_no_manager_to_wait_for() {
	let host = systemd(vec![("loginctl", "exit 1".into())], false);
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(host.sleeps(), 4, "only the five linger attempts sleep");
}

#[test]
fn a_bus_that_is_not_ready_for_the_socket_is_asked_again() {
	let host = systemd(vec![("runuser", flaky("runuser", 2, "exit 0"))], true);
	let run = host.configure(None);
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(socket_calls(&host).len(), 3);
	assert!(!run.stderr.contains("could not enable"), "{}", run.stderr);
}

#[test]
fn a_failed_uid_lookup_is_reported_instead_of_skipped_in_silence() {
	let host = Host::new(Setup {
		systemd: true,
		unit: true,
		stubs: vec![("id", "echo 'id: simulated' >&2; exit 1".into())],
		..Setup::default()
	});
	let run = host.configure(Some("0.12.0"));
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert!(
		run.stderr.contains("could not look up the uid")
			&& run.stderr.contains("podman.socket")
			&& run.stderr.contains("sudo epistle stack update"),
		"{}",
		run.stderr
	);
}

/// A `runuser` that answers only once the manager is up, which the `sleep`
/// stub signals after `n` waits.
fn runuser_needing_the_manager() -> String {
	"printf '%s\\n' \"$*\" >> \"$STUB_STATE/runuser.log\"\n\
	 [ -e \"$STUB_STATE/up\" ] || { echo 'Failed to connect to bus' >&2; exit 1; }"
		.into()
}

fn sleep_bringing_the_manager_up(n: u32) -> String {
	format!(
		"echo \"$*\" >> \"$STUB_STATE/sleep.log\"\n\
		 [ \"$(wc -l < \"$STUB_STATE/sleep.log\")\" -lt {n} ] || touch \"$STUB_STATE/up\""
	)
}

fn upgrade_host(sleep: String) -> Host {
	Host::new(Setup {
		unit: true,
		stubs: vec![("runuser", runuser_needing_the_manager()), ("sleep", sleep)],
		..Setup::default()
	})
}

#[test]
fn the_stack_is_updated_once_the_restarted_manager_answers() {
	let host = upgrade_host(sleep_bringing_the_manager_up(2));
	let run = host.configure(Some("0.12.0"));
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	let calls = host.calls("runuser");
	assert!(
		calls
			.iter()
			.any(|call| call.ends_with("epistle stack update")),
		"a manager that was not up yet read as a stack switched off: {calls:?}"
	);
	assert!(!run.stderr.contains("did not answer"), "{}", run.stderr);
}

#[test]
fn a_manager_that_never_answers_leaves_a_message_not_a_failure() {
	let host = upgrade_host("echo \"$*\" >> \"$STUB_STATE/sleep.log\"".into());
	let run = host.configure(Some("0.12.0"));
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert_eq!(host.sleeps(), 9);
	assert!(
		!host
			.calls("runuser")
			.iter()
			.any(|call| call.contains("stack update"))
	);
	assert!(
		run.stderr.contains("did not answer")
			&& run.stderr.contains("run sudo epistle stack update"),
		"{}",
		run.stderr
	);
}

#[test]
fn a_stack_that_does_not_come_back_leaves_the_package_configured() {
	let host = Host::new(Setup {
		unit: true,
		stubs: vec![(
			"runuser",
			"case \"$*\" in *'stack update'*) exit 1 ;; esac".into(),
		)],
		..Setup::default()
	});
	let run = host.configure(Some("0.12.0"));
	assert_eq!(run.code, Some(0), "{}", run.stderr);
	assert!(
		run.stderr.contains("sudo epistle stack update")
			&& run.stderr.contains("sudo epistle stack rollback"),
		"{}",
		run.stderr
	);
}
