use super::*;

fn message(extra_headers: &str) -> Vec<u8> {
	format!("From: a@example.org\r\nTo: b@example.net\r\n{extra_headers}Subject: s\r\n\r\nbody\r\n")
		.into_bytes()
}

fn bound_to(class: MailClass) -> ClassSources {
	ClassSources {
		credential: Some(class),
		..ClassSources::default()
	}
}

#[test]
fn parse_and_name_round_trip() {
	for class in MailClass::ALL {
		assert_eq!(MailClass::parse(class.as_str()), Some(class));
	}
	assert_eq!(MailClass::parse("Transactional"), None);
	assert_eq!(MailClass::parse(""), None);
	assert_eq!(MailClass::default(), MailClass::Personal);
}

#[test]
fn explicit_beats_credential_beats_account() {
	let all = ClassSources {
		explicit: Some(MailClass::Marketing),
		credential: Some(MailClass::Transactional),
		account: Some(MailClass::Personal),
	};
	assert_eq!(all.granted(), MailClass::Marketing);
	let no_explicit = ClassSources {
		explicit: None,
		..all
	};
	assert_eq!(no_explicit.granted(), MailClass::Transactional);
	let account_only = ClassSources {
		account: Some(MailClass::Transactional),
		..ClassSources::default()
	};
	assert_eq!(account_only.granted(), MailClass::Transactional);
	assert_eq!(ClassSources::default().granted(), MailClass::Personal);
}

#[test]
fn a_header_cannot_raise_the_class() {
	for asked in ["transactional", "marketing", "TRANSACTIONAL", "anything"] {
		let mut data = message(&format!("Epistle-Class: {asked}\r\n"));
		let class = resolve(ClassSources::default(), &mut data);
		assert_eq!(class, MailClass::Personal, "header asked for {asked}");
	}
	let mut data = message("Epistle-Class: transactional\r\n");
	let class = resolve(bound_to(MailClass::Marketing), &mut data);
	assert_eq!(class, MailClass::Marketing);
}

#[test]
fn a_header_may_downgrade_to_personal() {
	let mut data = message("epistle-class:   Personal\r\n");
	let class = resolve(bound_to(MailClass::Transactional), &mut data);
	assert_eq!(class, MailClass::Personal);
}

#[test]
fn the_header_is_removed_from_every_submission() {
	let mut data = message("Epistle-Class: transactional\r\n\tfolded\r\n");
	let _ = resolve(bound_to(MailClass::Transactional), &mut data);
	assert!(
		data == message(""),
		"the Epistle-Class field is still in the message"
	);
	let mut untouched = message("");
	let class = resolve(bound_to(MailClass::Transactional), &mut untouched);
	assert_eq!(class, MailClass::Transactional);
	assert!(
		untouched == message(""),
		"a message without the field was changed"
	);
}

#[test]
fn the_header_in_the_body_is_not_a_header() {
	let mut data = b"Subject: s\r\n\r\nEpistle-Class: personal\r\n".to_vec();
	let before = data.clone();
	let class = resolve(bound_to(MailClass::Transactional), &mut data);
	assert_eq!(class, MailClass::Transactional);
	assert!(data == before, "the body was changed");
}

#[test]
fn only_transactional_mail_is_kept_out_of_sent_and_needs_evidence() {
	assert!(!MailClass::Transactional.allows_sent_copy());
	assert!(MailClass::Marketing.allows_sent_copy());
	assert!(MailClass::Personal.allows_sent_copy());
	assert!(MailClass::Transactional.evidence_mandatory());
	assert!(!MailClass::Marketing.evidence_mandatory());
	assert!(!MailClass::Personal.evidence_mandatory());
}

#[test]
fn many_header_fields_are_handled_in_one_pass() {
	let fields = "Epistle-Class: transactional\r\n".repeat(20_000);
	let mut data = message(&fields);
	let started = std::time::Instant::now();
	let class = resolve(ClassSources::default(), &mut data);
	assert_eq!(class, MailClass::Personal);
	assert!(
		data == message(""),
		"some Epistle-Class fields are still in the message"
	);
	assert!(
		started.elapsed() < std::time::Duration::from_secs(5),
		"20000 fields took {:?}",
		started.elapsed()
	);
}
