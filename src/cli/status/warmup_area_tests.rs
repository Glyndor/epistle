//! The `warmup` status line, from the files under a data directory.

use super::*;
use crate::queue::warmup::settings::{self, Settings};
use crate::queue::warmup::state::{self, State};
use crate::storage::{DeliveryLog, DeliveryOutcome, DeliveryRecord};

/// 01:00 UTC on 2025-10-14.
const NOW: u64 = 20_375 * 86_400 + 3600;

fn log_gmail(dir: &Path, time: u64, count: u32) {
	let log = DeliveryLog::open(dir, 30);
	for n in 0..count {
		log.append(&DeliveryRecord {
			time,
			spool_id: uuid::Uuid::nil(),
			account: None,
			from: "sena@sender.example".into(),
			recipient: format!("s{n}@gmail.com"),
			outcome: DeliveryOutcome::Delivered,
			remote: Some("gmail-smtp-in.l.google.com".into()),
			reply: Some("250 OK".into()),
			attempt: 1,
			extra: Default::default(),
		})
		.expect("log");
	}
}

fn line(report: &AreaReport) -> (Level, &str) {
	(report.status, report.detail.as_str())
}

#[test]
fn off_and_quiet_is_just_off() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(
		line(&evaluate(dir.path(), None, 30, &[], NOW)),
		(Level::Ok, "off")
	);
}

#[test]
fn a_new_address_sending_a_lot_is_told_about_the_warm_up() {
	let dir = tempfile::tempdir().expect("tempdir");
	log_gmail(dir.path(), NOW - 60, 200);
	assert_eq!(
		line(&evaluate(dir.path(), None, 30, &[], NOW)),
		(
			Level::Warn,
			"off; this address looks new (200 recipients today, 0 messages queued): \
			 see `epistle warmup plan`, then `epistle warmup start`"
		)
	);
	// A month of delivery log says it is not new.
	log_gmail(dir.path(), NOW - 30 * 86_400, 1);
	assert_eq!(
		line(&evaluate(dir.path(), None, 30, &[], NOW)),
		(Level::Ok, "off")
	);
}

#[test]
fn on_it_reports_each_group() {
	let dir = tempfile::tempdir().expect("tempdir");
	settings::save(
		dir.path(),
		&Settings {
			enabled: true,
			..Settings::default()
		},
	)
	.expect("settings");
	let mut kept = State::new(20_375);
	kept.group_mut(crate::queue::warmup::Group::Gmail).sent = 30;
	state::save(dir.path(), &kept).expect("state");
	log_gmail(dir.path(), NOW - 60, 30);
	let report = evaluate(dir.path(), None, 30, &[], NOW);
	assert_eq!(line(&report), (Level::Ok, "on: gmail 30/50 good"));
	assert_eq!(
		report.items[0],
		Item::new(
			"gmail",
			Level::Ok,
			"cap 50, sent 30, deferred 0.0%, bounced 0.0%, verdict good, next cap 75, waiting 0"
		)
	);
	assert_eq!(report.items.len(), 5);
}
