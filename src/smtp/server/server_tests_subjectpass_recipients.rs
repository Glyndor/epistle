use super::*;

#[tokio::test]
async fn subjectpass_token_does_not_authorize_added_recipients() {
	let pass = subject_pass();
	let day = unix_day_now();
	let token = pass.issue(SENDER, RECIPIENT, day);
	let expected =
		crate::antispam::subjectpass::challenge_reply(&pass, SENDER, "alice@example.org", day);
	let sink = Arc::new(MemorySink::new());
	let scorer = FixedScorer::new(0.5);
	let server = band_server(&sink, &scorer).with_subjectpass(pass);
	let mut message = crate::smtp::session::AcceptedMessage {
		reverse_path: SENDER.to_string(),
		recipients: vec![
			RECIPIENT.to_string(),
			"alice@example.org".to_string(),
			"b@example.org".to_string(),
		],
		data: format!("Subject: {token}\r\n\r\nbody\r\n").into_bytes(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
		tlsrpt_verified: false,
	};
	let mut reply = Vec::new();
	server
		.handle_uncertain_band(&mut message, false, &mut reply)
		.await
		.expect("band");
	assert!(
		reply == expected.to_string().as_bytes(),
		"added recipients must receive their own exact SubjectPass challenge"
	);
}

#[tokio::test]
async fn subjectpass_challenges_the_last_uncovered_recipient() {
	let pass = subject_pass();
	let day = unix_day_now();
	let token_a = pass.issue(SENDER, RECIPIENT, day);
	let token_b = pass.issue(SENDER, "alice@example.org", day);
	let token_c = pass.issue(SENDER, "b@example.org", day);
	let expected =
		crate::antispam::subjectpass::challenge_reply(&pass, SENDER, "b@example.org", day);
	let sink = Arc::new(MemorySink::new());
	let scorer = FixedScorer::new(0.5);
	let server = band_server(&sink, &scorer).with_subjectpass(pass);
	let mut message = crate::smtp::session::AcceptedMessage {
		reverse_path: SENDER.to_string(),
		recipients: vec![
			RECIPIENT.to_string(),
			"alice@example.org".to_string(),
			"b@example.org".to_string(),
		],
		data: format!("Subject: {token_a} {token_b}\r\n\r\nbody\r\n").into_bytes(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
		tlsrpt_verified: false,
	};
	let mut reply = Vec::new();
	server
		.handle_uncertain_band(&mut message, false, &mut reply)
		.await
		.expect("band");
	assert!(
		reply == expected.to_string().as_bytes(),
		"the last uncovered recipient must receive its exact challenge"
	);
	message.data = format!("Subject: {token_a} {token_b} {token_c}\r\n\r\nbody\r\n").into_bytes();
	reply.clear();
	let outcome = server
		.handle_uncertain_band(&mut message, false, &mut reply)
		.await
		.expect("band");
	assert!(
		matches!(
			outcome,
			crate::smtp::server::run_band::BandOutcome::Continue
		),
		"recipient tokens must authorize the complete envelope"
	);
	assert_eq!(
		reply.len(),
		0,
		"fully authorized recipients must not receive a challenge"
	);
}
