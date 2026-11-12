use super::*;

#[test]
fn parses_simple_commands() {
	assert_eq!(
		parse("a1 CAPABILITY", DEFAULT_APPEND_LIMIT)
			.expect("parses")
			.command,
		Command::Capability
	);
	assert_eq!(
		parse("a2 noop", DEFAULT_APPEND_LIMIT)
			.expect("parses")
			.command,
		Command::Noop
	);
	assert_eq!(
		parse("a3 LOGOUT", DEFAULT_APPEND_LIMIT)
			.expect("parses")
			.tag,
		"a3".to_string()
	);
}

#[test]
fn parses_list_and_select() {
	assert_eq!(
		parse(r#"a1 LIST "" "*""#, DEFAULT_APPEND_LIMIT)
			.expect("parses")
			.command,
		Command::List(ListCommand {
			reference: String::new(),
			patterns: vec!["*".into()],
			..ListCommand::default()
		})
	);
	assert_eq!(
		parse("a2 SELECT INBOX", DEFAULT_APPEND_LIMIT)
			.expect("parses")
			.command,
		Command::Select {
			mailbox: "INBOX".into(),
			qresync: None,
		}
	);
}

#[test]
fn parses_fetch_variants() {
	let parsed = parse("a1 FETCH 1:5 (FLAGS RFC822.SIZE)", DEFAULT_APPEND_LIMIT).expect("parses");
	let Command::Fetch {
		sequence,
		items,
		uid,
		changed_since,
		..
	} = parsed.command
	else {
		panic!("expected fetch");
	};
	assert!(!uid);
	assert_eq!(changed_since, None);
	assert_eq!(items, vec![FetchItem::Flags, FetchItem::Rfc822Size]);
	assert!(sequence.contains(3, 10, &[]));
	assert!(!sequence.contains(6, 10, &[]));

	let parsed = parse("a2 UID FETCH 1:* (BODY[])", DEFAULT_APPEND_LIMIT).expect("parses");
	let Command::Fetch { items, uid, .. } = parsed.command else {
		panic!("expected fetch");
	};
	assert!(uid);
	assert!(items.contains(&FetchItem::Body));
	assert!(items.contains(&FetchItem::Uid));
}

#[test]
fn sequence_star_means_max() {
	let set = parse_sequence_set("*").expect("parses");
	assert!(set.contains(7, 7, &[]));
	assert!(!set.contains(6, 7, &[]));
	let set = parse_sequence_set("3:*").expect("parses");
	assert!(set.contains(3, 7, &[]));
	assert!(set.contains(7, 7, &[]));
	assert!(!set.contains(2, 7, &[]));
}

#[test]
fn rejects_malformed_lines() {
	assert_eq!(
		parse("CAPABILITY", DEFAULT_APPEND_LIMIT),
		Err(ParseError::Malformed)
	);
	assert_eq!(parse("", DEFAULT_APPEND_LIMIT), Err(ParseError::Malformed));
	assert_eq!(
		parse("ta!g NOOP", DEFAULT_APPEND_LIMIT),
		Err(ParseError::Malformed)
	);
}

#[test]
fn unknown_commands_keep_the_tag() {
	assert_eq!(
		parse("a1 XFROBNICATE", DEFAULT_APPEND_LIMIT),
		Err(ParseError::Unknown("a1".to_string()))
	);
	assert_eq!(
		parse("a2 STARTTLS", DEFAULT_APPEND_LIMIT)
			.expect("parses")
			.command,
		Command::StartTls
	);
}

#[test]
fn rejects_bad_arguments() {
	assert_eq!(
		parse("a1 FETCH 0 (FLAGS)", DEFAULT_APPEND_LIMIT),
		Err(ParseError::BadArguments("a1".to_string()))
	);
	assert_eq!(
		parse("a1 FETCH 1 (BOGUS)", DEFAULT_APPEND_LIMIT),
		Err(ParseError::BadArguments("a1".to_string()))
	);
}
