//! Tests for the host clock probe: the judgement on injected answers, plus
//! the real syscall, which must answer without root.

use super::{HostClock, STA_UNSYNC, TIME_ERROR, classify, output_within, parse_timedatectl, probe};

#[test]
fn a_clean_status_word_is_synced() {
	assert_eq!(classify(0, 0), HostClock::Synced);
	assert_eq!(classify(1, 0x2001), HostClock::Synced);
}

#[test]
fn the_unsync_flag_or_the_error_state_is_unsynced() {
	assert_eq!(classify(0, STA_UNSYNC), HostClock::Unsynced);
	assert_eq!(classify(TIME_ERROR, 0), HostClock::Unsynced);
	assert_eq!(classify(TIME_ERROR, STA_UNSYNC | 1), HostClock::Unsynced);
}

#[test]
fn timedatectl_answers_are_yes_or_no_and_nothing_else() {
	assert_eq!(parse_timedatectl("yes\n"), Some(HostClock::Synced));
	assert_eq!(parse_timedatectl("no\n"), Some(HostClock::Unsynced));
	assert_eq!(parse_timedatectl(""), None);
	assert_eq!(parse_timedatectl("maybe"), None);
}

#[test]
fn the_real_probe_answers_without_root() {
	// Whatever this host says, the probe returns a verdict and does not panic.
	let verdict = probe();
	assert!(
		matches!(
			verdict,
			HostClock::Synced | HostClock::Unsynced | HostClock::Unknown(_)
		),
		"{verdict:?}"
	);
}

#[test]
fn a_probe_that_never_answers_is_killed_at_its_deadline() {
	let started = std::time::Instant::now();
	let mut command = std::process::Command::new("sleep");
	command.arg("30");
	assert_eq!(
		output_within(command, std::time::Duration::from_millis(200)),
		None
	);
	assert!(
		started.elapsed() < std::time::Duration::from_secs(5),
		"the probe was waited for instead of being given up"
	);
}

#[test]
fn a_probe_that_answers_in_time_returns_its_output() {
	let mut command = std::process::Command::new("echo");
	command.arg("yes");
	assert_eq!(
		output_within(command, std::time::Duration::from_secs(5)).as_deref(),
		Some("yes\n")
	);
}
