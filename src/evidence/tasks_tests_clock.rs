//! A clock that is wrong must not make the tasks seal, purge or record
//! anything it should not.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::tests::{DAY, service, with_tsa};
use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::test_support::{accepted_for, at};

const YEAR: u64 = 86_400 * 400;

/// Three days of records kept one day, a message kept a year (accepted on
/// the third day) and one kept a day, and the tasks after the tick that
/// sealed and stamped them at the end of the third day.
async fn sealed() -> (
	tempfile::TempDir,
	Arc<EvidenceService>,
	Tasks,
	Instant,
	[PathBuf; 2],
) {
	let dir = tempfile::tempdir().expect("tempdir");
	let tsa = with_tsa(dir.path(), at(DAY + 3, 1)).await;
	let _ = tsa;
	let root = crate::evidence::service::root_of(dir.path());
	let chain = Chain::open(&root).expect("chain");
	for offset in 0..3 {
		chain
			.append_at(at(DAY + offset, 1), accepted_for(offset as u32, 1))
			.expect("append");
	}
	let kept = |days: &str| {
		let path = root.join("messages").join(Day(DAY + 2).name()).join(days);
		std::fs::create_dir_all(&path).expect("mkdir");
		std::fs::write(path.join("m.eml"), b"kept bytes").expect("write");
		path
	};
	let kept = [kept("365"), kept("1")];
	let service = service(dir.path());
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	let start = Instant::now();
	let status = tasks.tick_at(at(DAY + 3, 1), start).await;
	assert_eq!(status.held, None, "{:?}", status.errors);
	assert!(kept[0].exists() && kept[1].exists());
	(dir, service, tasks, start, kept)
}

#[tokio::test]
async fn a_clock_a_year_ahead_deletes_neither_records_nor_kept_messages() {
	let (_dir, service, tasks, start, kept) = sealed().await;
	let chain = Chain::open(service.root()).expect("chain");
	let status = tasks
		.tick_at(at(DAY + 3, 1) + YEAR, start + Duration::from_secs(600))
		.await;
	assert!(
		status.time <= at(DAY + 3, 1) + 600,
		"the tick ran at the wall clock: {}",
		status.time
	);
	let held = status.held.clone().expect("held");
	assert!(held.contains("clock"), "{held}");
	assert!(
		status
			.errors
			.iter()
			.any(|error| error.contains("the clock")),
		"{:?}",
		status.errors
	);
	assert!(kept[0].exists(), "a kept message was deleted");
	assert!(kept[1].exists());
	assert_eq!(chain.days().expect("days").len(), 3, "records were purged");
	assert!(!service.root().join("purges").exists());
	// The clock is right again: nothing was lost, and the sweep goes on. (The
	// test authority's clock stands still at the time of the first tick, which
	// the monotonic time given here accounts for.)
	let later = tasks
		.tick_at(
			at(DAY + 5, 1),
			start + Duration::from_secs(600 + 2 * 86_400),
		)
		.await;
	assert_eq!(later.held, None, "{:?}", later.errors);
	assert!(kept[0].exists());
	assert!(
		!kept[1].exists(),
		"a message past its retention stays for ever"
	);
}

#[tokio::test]
async fn a_clock_ahead_does_not_seal_the_day_that_is_still_open() {
	let (_dir, service, tasks, start, _kept) = sealed().await;
	let chain = Chain::open(service.root()).expect("chain");
	chain
		.append_at(at(DAY + 3, 2), accepted_for(7, 365))
		.expect("a record of the real day");
	// Two days ahead by the wall clock, ten minutes by the monotonic one.
	tasks
		.tick_at(
			at(DAY + 3, 1) + 2 * 86_400,
			start + Duration::from_secs(600),
		)
		.await;
	assert!(
		crate::evidence::checkpoint::load(service.root(), Day(DAY + 3))
			.expect("load")
			.is_none(),
		"the open day was sealed"
	);
	// The next acceptance of the real day still has a day to go to.
	service
		.abandon(uuid::Uuid::from_u128(9), "test")
		.expect("the open day is not sealed");
}

#[tokio::test]
async fn a_record_from_the_future_leaves_the_log_usable_and_says_so() {
	let dir = tempfile::tempdir().expect("tempdir");
	let service = {
		let root = crate::evidence::service::root_of(dir.path());
		// No authority to ask: the probe must not leave the machine.
		settings::save(
			&root,
			&Settings {
				enabled: false,
				authorities: Vec::new(),
			},
		)
		.expect("settings");
		let future = crate::storage::delivery_log::now_epoch() + YEAR;
		Chain::open(&root)
			.expect("chain")
			.append_at(future, accepted_for(1, 365))
			.expect("append");
		service(dir.path())
	};
	// The server starts and the log keeps taking records.
	service
		.abandon(uuid::Uuid::from_u128(2), "test")
		.expect("the log is usable");
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	let status = tasks.tick(crate::storage::delivery_log::now_epoch()).await;
	let held = status.held.expect("held");
	assert!(held.contains("clock"), "{held}");
}

#[tokio::test]
async fn a_timestamp_authority_settles_a_long_stop_by_itself() {
	let dir = tempfile::tempdir().expect("tempdir");
	let now = at(DAY + 100, 5);
	let _tsa = with_tsa(dir.path(), now).await;
	let root = crate::evidence::service::root_of(dir.path());
	// Sixty days stopped: the newest record alone cannot say the clock is right.
	Chain::open(&root)
		.expect("chain")
		.append_at(at(DAY + 40, 1), accepted_for(1, 365))
		.expect("append");
	let service = service(dir.path());
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	let status = tasks.tick_at(now, Instant::now()).await;
	assert_eq!(status.held, None, "{:?}", status.errors);
	assert_eq!(status.stamped, 1, "the old day was sealed and stamped");
}

#[tokio::test]
async fn an_unreadable_head_with_a_clock_a_year_ahead_purges_nothing() {
	let (dir, original, _tasks, start, kept) = sealed().await;
	std::fs::write(crate::evidence::head::path(original.root()), b"{").expect("corrupt");
	// A new process: it cannot read the head, and must not take that for
	// a log with nothing in it.
	let reopened = service(dir.path());
	let tasks = Tasks::new(Arc::clone(&reopened)).expect("tasks");
	let status = tasks
		.tick_at(at(DAY + 3, 1) + YEAR, start + Duration::from_secs(600))
		.await;
	assert!(status.held.is_some(), "{:?}", status.errors);
	assert!(kept[0].exists() && kept[1].exists());
	assert_eq!(
		Chain::open(reopened.root())
			.expect("chain")
			.days()
			.expect("days")
			.len(),
		3
	);
	assert!(!reopened.root().join("purges").exists());
}

#[tokio::test]
async fn a_restart_after_a_long_stop_seals_nothing_until_the_date_is_confirmed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = crate::evidence::service::root_of(dir.path());
	settings::save(
		&root,
		&Settings {
			enabled: false,
			authorities: Vec::new(),
		},
	)
	.expect("settings");
	Chain::open(&root)
		.expect("chain")
		.append_at(at(DAY, 1), accepted_for(1, 365))
		.expect("record");
	let service = service(dir.path());
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	// Three days after the newest record, no authority to ask.
	let status = tasks.tick_at(at(DAY + 3, 1), Instant::now()).await;
	let held = status.held.expect("held");
	assert!(held.contains("clock"), "{held}");
	assert!(
		crate::evidence::checkpoint::load(service.root(), Day(DAY))
			.expect("load")
			.is_none(),
		"a day was sealed on a date nobody confirmed"
	);
}

#[tokio::test]
async fn the_operator_can_confirm_a_date_when_there_is_no_authority_to_ask() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = crate::evidence::service::root_of(dir.path());
	settings::save(
		&root,
		&Settings {
			enabled: false,
			authorities: Vec::new(),
		},
	)
	.expect("settings");
	Chain::open(&root)
		.expect("chain")
		.append_at(at(DAY, 1), accepted_for(1, 365))
		.expect("record");
	let service = service(dir.path());
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	let start = Instant::now();
	assert!(tasks.tick_at(at(DAY + 3, 1), start).await.held.is_some());
	crate::evidence::clock_accept::request(&root, at(DAY + 3, 1)).expect("request");
	let status = tasks
		.tick_at(at(DAY + 3, 1) + 60, start + Duration::from_secs(60))
		.await;
	assert!(
		!status
			.errors
			.iter()
			.any(|error| error.contains("the clock")),
		"{:?}",
		status.errors
	);
	assert!(
		crate::evidence::checkpoint::load(service.root(), Day(DAY))
			.expect("load")
			.is_some(),
		"the stopped days were sealed once the date was confirmed"
	);
}

#[tokio::test]
async fn a_believed_clock_a_few_seconds_ahead_does_not_seal_a_day_that_has_not_ended() {
	let dir = tempfile::tempdir().expect("tempdir");
	let midnight = at(DAY + 1, 0);
	// The authority's clock says four seconds before midnight when ours says
	// one second after: a drift nobody would call a jump.
	let _tsa = with_tsa(dir.path(), midnight - 4).await;
	let root = crate::evidence::service::root_of(dir.path());
	Chain::open(&root)
		.expect("chain")
		.append_at(midnight - 300, accepted_for(1, 365))
		.expect("record");
	let service = service(dir.path());
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	let start = Instant::now();
	let status = tasks.tick_at(midnight + 1, start).await;
	assert!(
		crate::evidence::checkpoint::load(service.root(), Day(DAY))
			.expect("load")
			.is_none(),
		"the day was sealed a second after midnight by the clock: {:?}",
		status.errors
	);
	assert_eq!(
		status.held, None,
		"within the seal's grace: {:?}",
		status.errors
	);
}

#[tokio::test]
async fn a_token_from_before_the_day_ended_is_not_kept() {
	let dir = tempfile::tempdir().expect("tempdir");
	let midnight = at(DAY + 1, 0);
	// An authority whose clock is behind ours by more than the margin.
	let _tsa = with_tsa(dir.path(), midnight - 4).await;
	let root = crate::evidence::service::root_of(dir.path());
	Chain::open(&root)
		.expect("chain")
		.append_at(midnight - 300, accepted_for(1, 365))
		.expect("record");
	let service = service(dir.path());
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	let start = Instant::now();
	tasks.tick_at(midnight + 1, start).await;
	// Past the margin the day is sealed, and the token asked for is refused.
	let later = midnight + crate::evidence::timeref::SEAL_MARGIN_SECS + 60;
	tasks
		.tick_at(later, start + Duration::from_secs(later - midnight - 1))
		.await;
	assert!(
		crate::evidence::checkpoint::load(service.root(), Day(DAY))
			.expect("load")
			.is_some(),
		"the day was not sealed past the margin"
	);
	assert!(
		!crate::evidence::checkpoint::files(service.root(), Day(DAY))
			.tsr
			.exists(),
		"a token from before the day ended was written, once and for ever"
	);
	let waiting = crate::evidence::tsa::stamp::waiting(service.root()).expect("state");
	assert!(
		waiting[&Day(DAY).name()].last_error.contains("not kept"),
		"{waiting:?}"
	);
}

#[tokio::test]
async fn a_start_hours_ahead_of_the_newest_record_does_not_seal_the_open_day() {
	let dir = tempfile::tempdir().expect("tempdir");
	// The newest record is at 10:00; the authority says 11:00; the machine says
	// it is 08:00 the next day, 21 hours too far on.
	let _tsa = with_tsa(dir.path(), at(DAY, 11)).await;
	let root = crate::evidence::service::root_of(dir.path());
	Chain::open(&root)
		.expect("chain")
		.append_at(at(DAY, 10), accepted_for(1, 365))
		.expect("record");
	let service = service(dir.path());
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	let status = tasks.tick_at(at(DAY + 1, 8), Instant::now()).await;
	assert!(
		crate::evidence::checkpoint::load(service.root(), Day(DAY))
			.expect("load")
			.is_none(),
		"the open day was sealed on a clock the authority contradicts"
	);
	assert!(status.held.is_some());
	// The record of the real day still has a day to go to.
	service
		.abandon(uuid::Uuid::from_u128(9), "test")
		.expect("the day was not sealed");
}

#[tokio::test]
async fn a_request_nobody_needed_is_dropped_and_cannot_vouch_for_a_later_jump() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = crate::evidence::service::root_of(dir.path());
	settings::save(
		&root,
		&Settings {
			enabled: false,
			authorities: Vec::new(),
		},
	)
	.expect("settings");
	let late = at(DAY, 23) + 50 * 60;
	Chain::open(&root)
		.expect("chain")
		.append_at(at(DAY, 23) + 45 * 60, accepted_for(1, 365))
		.expect("record");
	let service = service(dir.path());
	let tasks = Tasks::new(Arc::clone(&service)).expect("tasks");
	let start = Instant::now();
	let first = tasks.tick_at(late, start).await;
	assert!(first.clock_sound, "{:?}", first.errors);
	// An operator asked for a date nobody was doubting.
	crate::evidence::clock_accept::request(&root, late).expect("request");
	tasks
		.tick_at(late + 60, start + Duration::from_secs(60))
		.await;
	assert!(
		!root.join("clock-accepted.json").exists(),
		"a request nobody needed was kept"
	);
	// Fifty-five minutes of wall clock in two minutes: nothing vouches for it.
	let jumped = tasks
		.tick_at(late + 3300, start + Duration::from_secs(120))
		.await;
	assert!(
		crate::evidence::checkpoint::load(service.root(), Day(DAY))
			.expect("load")
			.is_none(),
		"a day that has not ended was sealed: {:?}",
		jumped.errors
	);
}

#[tokio::test]
async fn the_status_says_the_clock_was_not_believed_when_it_was_not() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = crate::evidence::service::root_of(dir.path());
	settings::save(
		&root,
		&Settings {
			enabled: false,
			authorities: Vec::new(),
		},
	)
	.expect("settings");
	Chain::open(&root)
		.expect("chain")
		.append_at(at(DAY, 1), accepted_for(1, 365))
		.expect("record");
	let tasks = Tasks::new(service(dir.path())).expect("tasks");
	// Three days after the newest record, nothing to confirm the date.
	let doubtful = tasks.tick_at(at(DAY + 3, 1), Instant::now()).await;
	assert!(!doubtful.clock_sound);
	assert!(
		!last_status(&root)
			.expect("read")
			.expect("written")
			.clock_sound
	);
	// Right after a record, the clock is believed.
	Chain::open(&root)
		.expect("chain")
		.append_at(at(DAY + 3, 1), accepted_for(2, 365))
		.expect("record");
	let tasks = Tasks::new(service(dir.path())).expect("tasks");
	let sure = tasks.tick_at(at(DAY + 3, 1) + 60, Instant::now()).await;
	assert!(sure.clock_sound, "{:?}", sure.errors);
	assert!(
		last_status(&root)
			.expect("read")
			.expect("written")
			.clock_sound
	);
}

#[tokio::test]
async fn a_believed_clock_the_authority_finds_ahead_stops_being_believed_at_the_first_tick() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = crate::evidence::service::root_of(dir.path());
	let newest = at(DAY + 3, 10);
	// Restarts walked the log's newest record ahead of the true time, and
	// this start is within the margin of it: the log alone believes it.
	let true_time = newest - 1000;
	let _tsa = with_tsa(dir.path(), true_time).await;
	Chain::open(&root)
		.expect("chain")
		.append_at(newest, accepted_for(1, 365))
		.expect("record");
	let tasks = Tasks::new(service(dir.path())).expect("tasks");
	let status = tasks.tick_at(newest + 500, Instant::now()).await;
	assert!(
		!status.clock_sound,
		"a clock the authority puts 25 minutes behind was believed: {:?}",
		status.errors
	);
	assert!(status.held.is_some());
}

#[tokio::test]
async fn the_authority_is_asked_again_every_hour_and_not_at_every_tick() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = crate::evidence::service::root_of(dir.path());
	let newest = at(DAY + 3, 10);
	let tsa = with_tsa(dir.path(), newest).await;
	Chain::open(&root)
		.expect("chain")
		.append_at(newest, accepted_for(1, 365))
		.expect("record");
	let tasks = Tasks::new(service(dir.path())).expect("tasks");
	let start = Instant::now();
	assert!(tasks.tick_at(newest + 5, start).await.clock_sound);
	let requests = || tsa.received.lock().expect("lock").len();
	let asked = requests();
	for tick in 1..13u64 {
		tasks
			.tick_at(
				newest + 5 + tick * 300,
				start + Duration::from_secs(tick * 300),
			)
			.await;
	}
	assert_eq!(requests(), asked, "asked at ordinary ticks");
	tasks
		.tick_at(newest + 5 + 14 * 300, start + Duration::from_secs(14 * 300))
		.await;
	assert!(requests() > asked, "never asked again");
}
