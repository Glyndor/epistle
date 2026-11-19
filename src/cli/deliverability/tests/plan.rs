//! The refusals that come before anything is written, and the rate bound of
//! one test per minute per server, checked and recorded under one lock.

use std::sync::mpsc;
use std::time::Duration;

use super::support::*;
use crate::cli::deliverability::guard::{Guard, MIN_INTERVAL_SECS};
use crate::cli::deliverability::plan::{POLICY, USAGE, resolve};

fn refusal(extra: Vec<crate::directory_store::DynamicAccount>, account: &str, to: &str) -> u8 {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let store = store(dir.path(), &config, extra);
	resolve(&config, &store, account, to)
		.expect_err("refused")
		.code
}

#[test]
fn an_account_on_a_hosted_domain_gets_a_plan_with_a_lower_case_destination() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let store = store(dir.path(), &config, Vec::new());
	let plan = resolve(&config, &store, "alice", "Check@Mail-Tester.example").expect("plan");
	assert_eq!(plan.from, "alice@example.org");
	assert_eq!(plan.domain, "example.org");
	assert_eq!(plan.to, "check@mail-tester.example");
}

#[test]
fn a_destination_on_a_hosted_domain_is_refused() {
	assert_eq!(refusal(Vec::new(), "alice", "bob@example.org"), USAGE);
}

#[test]
fn a_destination_that_is_not_an_address_is_refused() {
	for bad in [
		"",
		"no-at-sign",
		"a b@mail-tester.example",
		"a@b\r\nBcc: x@y.example",
	] {
		assert_eq!(refusal(Vec::new(), "alice", bad), USAGE, "{bad:?}");
	}
}

#[test]
fn an_unknown_account_is_refused() {
	assert_eq!(refusal(Vec::new(), "nobody", DESTINATION), USAGE);
}

#[test]
fn a_sending_domain_the_server_does_not_host_is_refused() {
	let dir = tempfile::tempdir().expect("dir");
	let hosted = config(dir.path());
	let store = store(dir.path(), &hosted, Vec::new());
	let mut moved = hosted;
	moved.domains = vec!["other.example".to_string()];
	let refusal = resolve(&moved, &store, "alice", DESTINATION).expect_err("refused");
	assert_eq!(refusal.code, POLICY);
	assert!(refusal.message.contains("example.org"));
}

#[test]
fn a_disabled_account_and_an_account_that_cannot_send_are_refused() {
	let mut disabled = account("dan", &["dan@example.org"]);
	disabled.disabled = true;
	let mut mute = account("eve", &["eve@example.org"]);
	mute.send = Some(false);
	assert_eq!(refusal(vec![disabled], "dan", DESTINATION), POLICY);
	assert_eq!(refusal(vec![mute], "eve", DESTINATION), POLICY);
}

#[test]
fn a_domain_that_only_receives_is_refused_as_a_sender() {
	let dir = tempfile::tempdir().expect("dir");
	let mut config = config(dir.path());
	let store = store(dir.path(), &config, Vec::new());
	config.receive_only_domains = vec!["example.org".to_string()];
	assert_eq!(
		resolve(&config, &store, "alice", DESTINATION)
			.expect_err("refused")
			.code,
		POLICY
	);
}

const T: u64 = 1_800_000_000;

#[test]
fn the_second_run_inside_a_minute_is_refused_and_told_when_it_may_run() {
	let dir = tempfile::tempdir().expect("dir");
	Guard::acquire(dir.path(), T)
		.expect("first")
		.record(T)
		.expect("record");
	let refusal = Guard::acquire(dir.path(), T + MIN_INTERVAL_SECS - 1)
		.err()
		.expect("refused");
	assert_eq!(refusal.code, 3);
	assert!(refusal.message.contains("in 1 s"), "{}", refusal.message);
	Guard::acquire(dir.path(), T + MIN_INTERVAL_SECS).expect("a minute later");
}

#[test]
fn a_run_that_never_recorded_spends_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	drop(Guard::acquire(dir.path(), T).expect("first"));
	Guard::acquire(dir.path(), T).expect("nothing was recorded");
}

#[test]
fn two_runs_that_start_together_cannot_both_pass() {
	let dir = tempfile::tempdir().expect("dir");
	let first = Guard::acquire(dir.path(), T).expect("first");
	let (ready, waiting) = mpsc::channel();
	let path = dir.path().to_path_buf();
	let second = std::thread::spawn(move || {
		ready.send(()).expect("signal");
		Guard::acquire(&path, T).err().map(|refusal| refusal.code)
	});
	waiting.recv().expect("started");
	std::thread::sleep(Duration::from_millis(200));
	first.record(T).expect("record");
	assert_eq!(second.join().expect("join"), Some(3));
}

#[test]
fn a_last_run_in_the_future_does_not_block_for_ever() {
	let dir = tempfile::tempdir().expect("dir");
	Guard::acquire(dir.path(), T + 100_000)
		.expect("first")
		.record(T + 100_000)
		.expect("record");
	Guard::acquire(dir.path(), T).expect("the clock went back");
}

#[test]
fn a_state_file_that_cannot_be_read_stops_the_run() {
	let dir = tempfile::tempdir().expect("dir");
	std::fs::write(dir.path().join("deliverability-test.json"), "not json").expect("write");
	let refusal = Guard::acquire(dir.path(), T).err().expect("refused");
	assert_eq!(refusal.code, 1);
}
