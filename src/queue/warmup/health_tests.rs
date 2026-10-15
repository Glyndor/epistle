use super::*;

fn record(outcome: DeliveryOutcome, remote: Option<&str>, reply: &str) -> DeliveryRecord {
	DeliveryRecord {
		time: 0,
		spool_id: uuid::Uuid::nil(),
		account: None,
		from: "alice@sender.example".into(),
		recipient: "bob@gmail.com".into(),
		outcome,
		remote: remote.map(str::to_string),
		reply: Some(reply.to_string()),
		attempt: 1,
		extra: Default::default(),
	}
}

const GMAIL_MX: &str = "gmail-smtp-in.l.google.com";

#[test]
fn replies_are_read_by_their_codes() {
	use DeliveryOutcome::*;
	let cases = [
		(Delivered, "250 OK", Some(Signal::Delivered)),
		(
			Deferred,
			"421 4.7.0 Try again later",
			Some(Signal::Throttled),
		),
		(Deferred, "421 mx busy", Some(Signal::Throttled)),
		(
			Deferred,
			"450 4.7.1 Client host rejected",
			Some(Signal::Throttled),
		),
		(
			Deferred,
			"451 4.7.650 temporarily rate limited",
			Some(Signal::Throttled),
		),
		(Deferred, "450 4.2.0 greylisted", Some(Signal::Deferred)),
		(Deferred, "452 4.2.2 mailbox full", Some(Signal::Deferred)),
		(Failed, "550 5.1.1 no such user", Some(Signal::Bounced)),
		(
			Failed,
			"550 5.7.1 message looks like spam",
			Some(Signal::SpamBlock),
		),
		(Failed, "554 no reason given", Some(Signal::Bounced)),
		(Failed, "421 4.7.0 expired while deferred", None),
		(Failed, "message expired in the queue", None),
		(Deferred, "connection refused", None),
		(Suppressed, "recipient is on the suppression list", None),
		(Canceled, "421 4.7.0", None),
	];
	let got: Vec<_> = cases
		.iter()
		.map(|(outcome, reply, _)| {
			(
				*outcome,
				*reply,
				signal(&record(*outcome, Some(GMAIL_MX), reply)),
			)
		})
		.collect();
	assert_eq!(got, cases.to_vec());
}

#[test]
fn reply_text_cannot_make_a_deferral_a_block() {
	use DeliveryOutcome::*;
	// The words after the code are the remote's to choose: only the code
	// and an enhanced status of the same class count.
	let cases = [
		(
			Deferred,
			"450 4.2.0 5.7.1 spam 421 4.7.0 blocked",
			Signal::Deferred,
		),
		(
			Deferred,
			"450 5.7.1 class does not match the code",
			Signal::Deferred,
		),
		(Deferred, "4500 4.7.0 not a code", Signal::Deferred),
		(
			Failed,
			"550 4.7.1 class does not match the code",
			Signal::Bounced,
		),
		(Failed, "550 5.1.1 then 5.7.1 in the text", Signal::Bounced),
	];
	for (outcome, reply, want) in cases {
		let got = signal(&record(outcome, Some(GMAIL_MX), reply));
		let want = match reply.starts_with("4500") {
			true => None,
			false => Some(want),
		};
		assert_eq!(got, want, "{reply}");
	}
}

#[test]
fn records_no_remote_answered_say_nothing() {
	assert_eq!(
		signal(&record(DeliveryOutcome::Failed, None, "550 5.7.1 spam")),
		None
	);
}

#[test]
fn a_day_counts_each_recipient_once_and_puts_it_in_its_group() {
	let mut day = DayTally::default();
	let mut add = |recipient: &str, remote: &str, outcome, reply: &str| {
		let mut record = record(outcome, Some(remote), reply);
		record.recipient = recipient.into();
		day.add(&record);
	};
	use DeliveryOutcome::*;
	// One recipient deferred eight times with eight wordings, then delivered.
	for n in 0..8 {
		add(
			"a@gmail.com",
			GMAIL_MX,
			Deferred,
			&format!("421 4.7.0 try {n}"),
		);
	}
	add("a@gmail.com", GMAIL_MX, Delivered, "250 OK");
	add(
		"b@gmail.com",
		"alt1.gmail-smtp-in.l.google.com",
		Delivered,
		"250 OK",
	);
	add(
		"c@corp.example",
		"aspmx.l.google.com",
		Failed,
		"550 5.7.1 spam",
	);
	add(
		"d@hotmail.com",
		"hotmail-com.olc.protection.outlook.com",
		Failed,
		"550 5.1.1 unknown",
	);
	// A look-alike host is not Gmail.
	add(
		"e@evil.example",
		"gmail-smtp-in.l.google.com.evil.example",
		Failed,
		"550 5.7.1 no",
	);
	assert_eq!(
		day.of(Group::Gmail),
		Tally {
			attempted: 3,
			deferred: 1,
			bounced: 0,
			spam_blocks: 1
		}
	);
	assert_eq!(
		day.of(Group::Outlook),
		Tally {
			attempted: 1,
			deferred: 0,
			bounced: 1,
			spam_blocks: 0
		}
	);
	assert_eq!(
		day.of(Group::Other),
		Tally {
			attempted: 1,
			deferred: 0,
			bounced: 0,
			spam_blocks: 1
		}
	);
	assert_eq!(day.of(Group::Yahoo), Tally::default());
}

#[test]
fn a_day_with_more_recipients_than_the_bound_is_read_in_bounded_memory() {
	let mut day = DayTally::default();
	let mut base = record(DeliveryOutcome::Delivered, Some(GMAIL_MX), "250 OK");
	let total = MAX_RECIPIENTS + 5000;
	for n in 0..total {
		base.recipient = format!("user{n}@gmail.com");
		day.add(&base);
	}
	assert_eq!(day.remembered(), MAX_RECIPIENTS);
	assert_eq!(day.of(Group::Gmail).attempted as usize, total);
}

#[test]
fn a_day_is_tallied_from_the_log_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let log = DeliveryLog::open(dir.path(), 30);
	let day = 20_375;
	let mut kept = record(DeliveryOutcome::Deferred, Some(GMAIL_MX), "421 4.7.0 slow");
	kept.time = day as u64 * 86_400 + 10;
	log.append(&kept).expect("append");
	let mut other_day = kept.clone();
	other_day.time += 86_400;
	log.append(&other_day).expect("append");
	let tally = tally_day(&log, day).expect("tally");
	assert_eq!(
		tally.of(Group::Gmail),
		Tally {
			attempted: 1,
			deferred: 1,
			bounced: 0,
			spam_blocks: 0
		}
	);
}

fn from(
	account: Option<&str>,
	recipient: &str,
	outcome: DeliveryOutcome,
	reply: &str,
) -> DeliveryRecord {
	let mut record = record(outcome, Some(GMAIL_MX), reply);
	record.account = account.map(str::to_string);
	record.recipient = recipient.into();
	record
}

fn named(causes: &[crate::queue::warmup::state::Cause]) -> Vec<(&str, u32)> {
	causes
		.iter()
		.map(|cause| (cause.account.as_str(), cause.bad))
		.collect()
}

#[test]
fn bad_replies_are_attributed_to_the_accounts_that_caused_them() {
	use DeliveryOutcome::*;
	let mut day = DayTally::default();
	for n in 0..5 {
		day.add(&from(
			Some("bulk@school.example"),
			&format!("dead{n}@gmail.com"),
			Failed,
			"550 5.1.1 no such user",
		));
	}
	for n in 0..2 {
		// Mail the server sends on its own has no account.
		day.add(&from(
			None,
			&format!("trap{n}@gmail.com"),
			Failed,
			"550 5.7.1 spam",
		));
	}
	// One recipient deferred three times is one bad recipient.
	for _ in 0..3 {
		day.add(&from(
			Some("alice@sender.example"),
			"slow@gmail.com",
			Deferred,
			"421 4.7.0 slow",
		));
	}
	day.add(&from(
		Some("carol@sender.example"),
		"ok@gmail.com",
		Delivered,
		"250 OK",
	));
	day.add(&from(
		Some("carol@sender.example"),
		"grey@gmail.com",
		Deferred,
		"450 4.2.0 greylisted",
	));
	day.add(&from(
		Some("dave@sender.example"),
		"x@gmail.com",
		Failed,
		"550 5.1.1 unknown",
	));
	assert_eq!(
		named(&day.causes(Group::Gmail)),
		[
			("bulk@school.example", 5),
			("system", 2),
			("alice@sender.example", 1)
		]
	);
	assert!(day.causes(Group::Yahoo).is_empty());
}

#[test]
fn accounts_past_the_bound_are_counted_together() {
	let mut day = DayTally::default();
	for n in 0..(MAX_ACCOUNTS + 76) {
		day.add(&from(
			Some(&format!("a{n:04}@sender.example")),
			&format!("dead{n}@gmail.com"),
			DeliveryOutcome::Failed,
			"550 5.1.1 unknown",
		));
	}
	assert_eq!(day.accounts(Group::Gmail), MAX_ACCOUNTS + 1);
	assert_eq!(named(&day.causes(Group::Gmail))[0], ("overflow", 76));
}
