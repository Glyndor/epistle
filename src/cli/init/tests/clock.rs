//! `epistle init` warns about a host clock that is not synchronised and
//! carries on: the warning is a notice, never a refusal.

use super::super::detect::tests::base::Scripted;
use super::detect::dry_run_args;
use super::*;
use crate::clock::sync::HostClock;

/// Run a dry run with the host clock reading `state`; the exit code and
/// what `init` printed.
fn dry_run_with(state: HostClock) -> (ExitCode, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let probes = Probes {
		detector: &Scripted::found(None, None),
		resolver: &|| None,
		meminfo: std::path::Path::new("/nonexistent/meminfo"),
		clock: &|| state.clone(),
	};
	let mut out = Vec::new();
	let code = run_with(
		dry_run_args(
			dir.path(),
			"public_ipv4 = \"none\"\npublic_ipv6 = \"none\"\n",
		),
		&probes,
		&mut out,
	);
	(code, String::from_utf8(out).expect("utf8"))
}

#[test]
fn an_unsynchronised_clock_warns_with_the_fix_and_init_still_succeeds() {
	let (code, text) = dry_run_with(HostClock::Unsynced);
	assert_eq!(code, ExitCode::from(EXIT_OK), "{text}");
	assert!(
		text.contains("warning: the host clock is not synchronised"),
		"{text}"
	);
	assert!(text.contains("timedatectl set-ntp true"), "{text}");
	assert!(text.contains("dry-run: nothing was written"), "{text}");
}

#[test]
fn a_clock_that_cannot_be_read_warns_and_init_still_succeeds() {
	let (code, text) = dry_run_with(HostClock::Unknown("no adjtimex".to_string()));
	assert_eq!(code, ExitCode::from(EXIT_OK), "{text}");
	assert!(
		text.contains("cannot tell whether the host clock is synchronised (no adjtimex)"),
		"{text}"
	);
}

#[test]
fn a_synchronised_clock_adds_no_warning() {
	let (code, text) = dry_run_with(HostClock::Synced);
	assert_eq!(code, ExitCode::from(EXIT_OK), "{text}");
	assert!(!text.contains("clock"), "{text}");
}
