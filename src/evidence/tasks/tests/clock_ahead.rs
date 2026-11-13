//! More tests of a clock that is ahead of the records, continued from `clock`.

use std::time::{Duration, Instant};

use super::base::{DAY, service, with_tsa};
use super::*;
use crate::evidence::chain::Chain;
use crate::evidence::test_support::{accepted_for, at};

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
