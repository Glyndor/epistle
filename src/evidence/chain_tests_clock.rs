//! A clock that jumps cannot send a record to a sealed day or a far future.

use std::path::Path;

use super::tests_lines;
use super::*;
use crate::evidence::audit::tests::{DAY, Fixture};
use crate::evidence::test_support::{accepted, at};

#[test]
fn a_record_cannot_be_written_into_a_day_that_is_sealed() {
	let fixture = Fixture::new();
	let chain = Chain::open(fixture.root()).expect("chain");
	let before = std::fs::read(chain.day_file(Day(DAY + 2))).expect("read");
	// The clock went back to the middle of a sealed day.
	let refused = chain
		.append_at(at(DAY + 2, 5), accepted(50))
		.expect_err("a record in a sealed day");
	assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
	assert_eq!(
		refused.to_string(),
		"the record would fall in 2026-10-16, a day that is already sealed: the clock went back"
	);
	assert_eq!(
		std::fs::read(chain.day_file(Day(DAY + 2))).expect("read"),
		before
	);
	assert_eq!(fixture.verify().first_break, None);
}

#[test]
fn a_clock_behind_the_newest_record_never_refuses_it_and_never_moves_time_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("chain");
	chain
		.append_at(at(DAY + 3, 10), accepted(1))
		.expect("first");
	// A record in the future must not lock the log until the clock reaches
	// it: outcomes, acknowledgements and the start-up repair all append.
	let behind = at(DAY + 3, 10) - 5 * 86_400;
	chain
		.append_clocked(behind, std::time::Instant::now(), accepted(2))
		.expect("a clock far behind still records");
	chain
		.append_at(at(DAY + 3, 10) - 60, accepted(3))
		.expect("a small step");
	let text = std::fs::read_to_string(chain.day_file(Day(DAY + 3))).expect("read");
	let times: Vec<u64> = text
		.lines()
		.filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
		.filter_map(|record| record["time"].as_u64())
		.collect();
	assert_eq!(times.len(), 3);
	assert!(
		times.windows(2).all(|pair| pair[0] <= pair[1]),
		"times went back: {times:?}"
	);
}

#[test]
fn a_clock_that_jumps_forward_dates_nothing_in_the_future_and_recovers_by_itself() {
	use std::time::{Duration, Instant};
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = Chain::open(dir.path()).expect("chain");
	let start = Instant::now();
	let today = at(DAY + 3, 1);
	chain
		.append_clocked(today, start, accepted(1))
		.expect("first record");
	// Ten seconds later by the monotonic clock, a year later by the wall clock.
	let jumped = today + 365 * 86_400;
	chain
		.append_clocked(jumped, start + Duration::from_secs(10), accepted(2))
		.expect("a jump is not a reason to lose the record");
	assert!(
		chain
			.days()
			.expect("days")
			.iter()
			.all(|day| *day == Day::of_epoch(today)),
		"a record went to a day in the future"
	);
	// The clock is put right: a minute after the first record.
	chain
		.append_clocked(today + 60, start + Duration::from_secs(60), accepted(3))
		.expect("the clock is right again");
	// Time that really passed is no jump: a week idle.
	chain
		.append_clocked(
			today + 7 * 86_400,
			start + Duration::from_secs(7 * 86_400),
			accepted(4),
		)
		.expect("a week of uptime");
	assert!(
		chain
			.days()
			.expect("days")
			.contains(&Day::of_epoch(today + 7 * 86_400))
	);
}

#[test]
fn a_record_dated_in_the_future_does_not_lock_the_log_for_a_new_process() {
	let dir = tempfile::tempdir().expect("tempdir");
	let future = crate::storage::delivery_log::now_epoch() + 400 * 86_400;
	Chain::open(dir.path())
		.expect("chain")
		.append_at(future, accepted(1))
		.expect("a record from a clock that was wrong");
	// A new process (the CLI, or the server after a restart) reads the
	// real clock: it must still be able to write.
	let reopened = Chain::open(dir.path()).expect("reopened");
	reopened
		.append(accepted(2))
		.expect("the log is not locked until the date arrives");
	assert_eq!(tests_lines(&reopened, Day::of_epoch(future)), 2);
}

fn open_after(dir: &Path, damage: impl FnOnce(&Chain)) -> Chain {
	let chain = Chain::open(dir).expect("chain");
	chain
		.append_at(at(DAY + 3, 10), accepted(1))
		.expect("record");
	damage(&chain);
	Chain::open(dir).expect("reopened")
}

#[test]
fn a_head_that_cannot_be_read_does_not_mean_there_is_no_log() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = open_after(dir.path(), |_| {
		std::fs::write(crate::evidence::head::path(dir.path()), b"{").expect("corrupt");
	});
	assert_eq!(chain.time().floor(), at(DAY + 3, 10), "the newest record");
	// And a clock a year on from it is not believed because the head broke.
	let reading = chain
		.time()
		.read_at(at(DAY + 3, 10) + 365 * 86_400, std::time::Instant::now());
	assert!(!reading.sound);
}

#[test]
fn a_log_that_cannot_be_read_at_all_starts_believing_no_clock() {
	let dir = tempfile::tempdir().expect("tempdir");
	let chain = open_after(dir.path(), |chain| {
		std::fs::remove_file(crate::evidence::head::path(dir.path())).expect("head");
		std::fs::write(chain.day_file(Day(DAY + 3)), b"not a record\n").expect("corrupt");
	});
	let reading = chain
		.time()
		.read_at(at(DAY + 3, 11), std::time::Instant::now());
	assert!(!reading.sound, "a clock was believed on a log nobody read");
}

#[test]
fn a_command_with_the_clock_a_month_ahead_cannot_date_the_servers_records_in_the_future() {
	use std::time::{Duration, Instant};
	let dir = tempfile::tempdir().expect("tempdir");
	let today = at(DAY + 3, 10);
	let server = Chain::open(dir.path()).expect("server");
	let start = Instant::now();
	server
		.append_clocked(today, start, accepted(1))
		.expect("the server's record");
	// A command run by hand: its own process, no history, a clock 30 days on.
	let command = Chain::open(dir.path()).expect("command");
	command
		.append_clocked(today + 30 * 86_400, Instant::now(), accepted(2))
		.expect("the command still records what it was asked to");
	// The server, with its clock right, goes on: nothing it writes is dated
	// by what the command left behind.
	server
		.append_clocked(today + 60, start + Duration::from_secs(60), accepted(3))
		.expect("the server's next record");
	let days = Chain::open(dir.path())
		.expect("reopened")
		.days()
		.expect("days");
	assert_eq!(
		days,
		vec![Day(DAY + 3)],
		"a record went to another day: {days:?}"
	);
}
