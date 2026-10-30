//! THREAD=REFERENCES on messages built in memory: the RFC 5256 examples,
//! Dovecot's imaptest `thread` scripts, and the edge cases of step 1.

use super::*;

/// One message for [`threads`]: its sequence number, sent date and
/// header lines (separated by `\n`).
pub(in super::super) type Mail<'a> = (u32, i64, &'a str);

/// A message text with `headers` and a short body.
pub(in super::super) fn text(headers: &str) -> String {
	format!("{}\r\n\r\nbody\r\n", headers.replace('\n', "\r\n"))
}

/// The thread-lists for `mails`, numbered by sequence, or by UID when
/// `uid` is set (each UID is ten times the sequence number).
pub(in super::super) fn threads_as(mails: &[Mail], uid: bool) -> String {
	let mut threader = Threader::new();
	for &(seqno, sent, headers) in mails {
		threader.add(seqno, seqno * 10, sent, &text(headers));
	}
	let mut out = String::new();
	threader.render(uid, &mut out);
	out
}

pub(in super::super) fn threads(mails: &[Mail]) -> String {
	threads_as(mails, false)
}

/// Mails numbered from 1, all sent at the same instant.
fn simultaneous<'a>(headers: &[&'a str]) -> Vec<Mail<'a>> {
	(1..)
		.zip(headers)
		.map(|(seqno, headers)| (seqno, 0, *headers))
		.collect()
}

#[test]
fn rfc_5256_example_shapes() {
	// `(2)(3 6 (4 23)(44 7 96))`: only the matching messages are numbered.
	let mails = [
		(2, 0, "Message-ID: <2@x>"),
		(3, 0, "Message-ID: <3@x>"),
		(4, 0, "Message-ID: <4@x>\nIn-Reply-To: <6@x>"),
		(6, 0, "Message-ID: <6@x>\nReferences: <3@x>"),
		(7, 0, "Message-ID: <7@x>\nReferences: <3@x> <6@x> <44@x>"),
		(23, 0, "Message-ID: <23@x>\nReferences: <4@x>"),
		(44, 0, "Message-ID: <44@x>\nReferences: <6@x>"),
		(96, 0, "Message-ID: <96@x>\nReferences: <44@x> <7@x>"),
	];
	assert_eq!(threads(&mails), "(2)(3 6 (4 23)(44 7 96))");
	// `((3)(5))`: two replies to a message that is not in the result.
	let mails = [
		(3, 0, "Message-ID: <3@x>\nIn-Reply-To: <gone@x>"),
		(5, 0, "Message-ID: <5@x>\nIn-Reply-To: <gone@x>"),
	];
	assert_eq!(threads(&mails), "((3)(5))");
}

#[test]
fn imaptest_thread_breaks_the_old_link_and_refuses_the_loop() {
	let mails = [
		(1, 17 * 3600, "Message-ID: <a@b>"),
		(2, 15 * 3600, "Message-Id: <b@b>\nReferences: <a@b> <c@b>"),
		(3, 16 * 3600, "Message-Id: <c@b>\nReferences: <b@b>"),
	];
	assert_eq!(threads(&mails), "(3 2)(1)");
	assert_eq!(threads(&[(1, 0, mails[1].2), (2, 0, mails[2].2)]), "(2 1)");
}

#[test]
fn in_reply_to_alone_builds_the_tree() {
	let all = [
		"Message-ID: <1@b>",
		"Message-Id: <2@b>\nIn-Reply-To: <1@b>",
		"Message-Id: <3@b>\nIn-Reply-To: <1@b>",
		"Message-Id: <4@b>\nIn-Reply-To: <2@b>",
		"Message-Id: <5@b>\nIn-Reply-To: <2@b>",
	];
	// imaptest `thread5`: the first four, then without 1 and 2, then with 5.
	assert_eq!(threads(&simultaneous(&all[..4])), "(1 (2 4)(3))");
	assert_eq!(threads(&simultaneous(&all[2..4])), "(1)(2)");
	assert_eq!(threads(&simultaneous(&all[2..])), "(1)((2)(3))");
}

#[test]
fn missing_parents_become_dummies_that_are_pruned() {
	// imaptest `thread6`: a dummy with two children stays.
	let shared = simultaneous(&["References: <a@b>", "References: <a@b>"]);
	assert_eq!(threads(&shared), "((1)(2))");
	// A dummy with one child is replaced by it, at any depth.
	let alone = simultaneous(&["Message-ID: <m@b>\nReferences: <x@b> <y@b> <z@b>"]);
	assert_eq!(threads(&alone), "(1)");
	// Dummies between messages vanish and their children move up.
	let gaps = simultaneous(&[
		"Message-ID: <r@b>",
		"Message-ID: <c1@b>\nReferences: <r@b> <gone1@b> <gone2@b>",
		"Message-ID: <c2@b>\nReferences: <r@b> <gone1@b>",
	]);
	assert_eq!(threads(&gaps), "(1 (2)(3))");
	// Nested dummies at the top collapse into one with every message.
	let nested = simultaneous(&[
		"Message-ID: <c1@b>\nReferences: <top@b> <mid@b>",
		"Message-ID: <c2@b>\nReferences: <top@b> <mid@b>",
		"Message-ID: <c3@b>\nReferences: <top@b>",
	]);
	assert_eq!(threads(&nested), "((1)(2)(3))");
}

#[test]
fn duplicate_message_ids_keep_the_first() {
	// imaptest `thread2`, `thread7` and `thread8`.
	let twins = simultaneous(&["Message-Id: <a@b>", "Message-Id: <a@b>"]);
	assert_eq!(threads(&twins), "(1)(2)");
	let chain = [
		"Message-Id: <a@b>",
		"Message-Id: <b@b>\nReferences: <a@b>",
		"Message-Id: <c@b>\nReferences: <b@b>",
		"Message-Id: <b@b>\nReferences: <a@b>",
	];
	assert_eq!(threads(&simultaneous(&chain)), "(1 (2 3)(4))");
	let without_second = [chain[0], chain[2], chain[3]];
	assert_eq!(threads(&simultaneous(&without_second)), "(1 3 2)");
	let siblings = simultaneous(&[chain[0], chain[1], chain[3]]);
	assert_eq!(threads(&siblings), "(1 (2)(3))");
}

#[test]
fn loops_and_self_references_are_cut() {
	let mutual = simultaneous(&[
		"Message-Id: <a@b>\nReferences: <b@b>",
		"Message-Id: <b@b>\nReferences: <a@b>",
	]);
	assert_eq!(threads(&mutual), "(2 1)");
	let triangle = simultaneous(&[
		"Message-Id: <a@b>\nReferences: <c@b>",
		"Message-Id: <b@b>\nReferences: <a@b>",
		"Message-Id: <c@b>\nReferences: <b@b>",
	]);
	assert_eq!(threads(&triangle), "(3 1 2)");
	let itself = simultaneous(&["Message-Id: <a@b>\nReferences: <a@b>"]);
	assert_eq!(threads(&itself), "(1)");
	let inside = simultaneous(&[
		"Message-Id: <p@b>",
		"Message-Id: <a@b>\nReferences: <a@b> <p@b>",
		"Message-Id: <k@b>\nReferences: <a@b> <a@b>",
	]);
	// Step 1.A hangs <p@b> under <a@b>, so 1.B cannot do the reverse.
	assert_eq!(threads(&inside), "(2 (1)(3))");
}

#[test]
fn quoted_and_plain_ids_are_the_same_message() {
	let mails = simultaneous(&[
		"Message-ID: <\"01KF8JCEOCBS0045PS\"@xxx.yyy.com>",
		"Message-ID: <r@x>\nReferences: <01KF8JCEOCBS0045PS@xxx.yyy.com>",
	]);
	assert_eq!(threads(&mails), "(1 2)");
}

#[test]
fn an_overlong_id_links_nothing() {
	let id = format!("<{}@b>", "x".repeat(msgid::MAX_MSGID_LEN));
	let parent = format!("Message-ID: {id}");
	let child = format!("Message-ID: <c@b>\nReferences: {id}");
	assert_eq!(threads(&simultaneous(&[&parent, &child])), "(1)(2)");
}

#[test]
fn subjects_merge_originals_replies_and_forwards() {
	let cases: [(&[&str], &str); 9] = [
		// imaptest `thread3` and `thread4`.
		(
			&[
				"Message-Id: <a@b>\nSubject: foo",
				"Message-Id: <a@b>\nSubject: Re: foo",
			],
			"(1 2)",
		),
		(
			&[
				"Message-Id: <a@b>\nSubject: foo",
				"References: <c@b>\nSubject: Re: foo",
			],
			"(1 2)",
		),
		(&["Subject: foo", "Subject: Fwd: FOO"], "(1 2)"),
		(&["Subject: foo", "Subject: foo (fwd)"], "(1 2)"),
		(&["Subject: foo", "Subject: [fwd: foo]"], "(1 2)"),
		(&["Subject: foo", "Subject: foo"], "((1)(2))"),
		(&["Subject: Re: foo", "Subject: re: foo"], "((1)(2))"),
		(&["Subject: Re:", "Subject: "], "(1)(2)"),
		(&["Subject: foo", "Subject: bar"], "(1)(2)"),
	];
	for (headers, expected) in cases {
		assert_eq!(threads(&simultaneous(headers)), expected, "{headers:?}");
	}
}

#[test]
fn an_original_sent_after_its_reply_still_heads_the_thread() {
	let mails = [(1, 10, "Subject: Re: foo"), (2, 20, "Subject: foo")];
	assert_eq!(threads(&mails), "(2 1)");
}

#[test]
fn a_dummy_takes_the_messages_with_its_subject() {
	let mails = simultaneous(&[
		"References: <x@b>\nSubject: foo",
		"References: <x@b>\nSubject: Re: foo",
		"Subject: foo",
		"References: <y@b>\nSubject: foo",
		"References: <y@b>\nSubject: foo",
	]);
	assert_eq!(threads(&mails), "((1)(2)(3)(4)(5))");
}

#[test]
fn siblings_sort_by_sent_date_then_sequence() {
	let mails = [
		(1, 50, "Message-ID: <r@b>"),
		(2, 40, "Message-ID: <x@b>\nIn-Reply-To: <r@b>"),
		(3, 30, "Message-ID: <y@b>\nIn-Reply-To: <r@b>"),
		(4, 40, "Message-ID: <z@b>\nIn-Reply-To: <r@b>"),
		(5, 10, "Message-ID: <s@b>"),
	];
	assert_eq!(threads(&mails), "(5)(1 (3)(2)(4))");
}

#[test]
fn uid_thread_numbers_by_uid() {
	let mails = simultaneous(&["Message-ID: <a@b>", "Message-ID: <b@b>\nReferences: <a@b>"]);
	assert_eq!(threads_as(&mails, true), "(10 20)");
	assert_eq!(threads_as(&mails, false), "(1 2)");
}

#[test]
fn no_messages_no_threads() {
	assert_eq!(threads(&[]), "");
}
