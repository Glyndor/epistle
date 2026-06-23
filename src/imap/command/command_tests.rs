use super::*;

#[test]
fn parses_simple_commands() {
	assert_eq!(
		parse("a1 CAPABILITY").expect("parses").command,
		Command::Capability
	);
	assert_eq!(parse("a2 noop").expect("parses").command, Command::Noop);
	assert_eq!(parse("a3 LOGOUT").expect("parses").tag, "a3".to_string());
}

#[test]
fn parses_login_with_quoted_strings() {
	let parsed = parse(r#"a1 LOGIN "alice" "p@ss w\"ord""#).expect("parses");
	assert_eq!(
		parsed.command,
		Command::Login {
			username: "alice".into(),
			password: "p@ss w\"ord".into()
		}
	);
}

#[test]
fn parses_login_with_atoms() {
	let parsed = parse("a1 LOGIN alice@example.org secret").expect("parses");
	assert_eq!(
		parsed.command,
		Command::Login {
			username: "alice@example.org".into(),
			password: "secret".into()
		}
	);
}

#[test]
fn parses_list_and_select() {
	assert_eq!(
		parse(r#"a1 LIST "" "*""#).expect("parses").command,
		Command::List {
			reference: String::new(),
			pattern: "*".into(),
			return_status: Vec::new(),
			select_subscribed: false,
		}
	);
	assert_eq!(
		parse("a2 SELECT INBOX").expect("parses").command,
		Command::Select {
			mailbox: "INBOX".into(),
			qresync: None,
		}
	);
}

#[test]
fn parses_fetch_variants() {
	let parsed = parse("a1 FETCH 1:5 (FLAGS RFC822.SIZE)").expect("parses");
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
	assert!(sequence.contains(3, 10));
	assert!(!sequence.contains(6, 10));

	let parsed = parse("a2 UID FETCH 1:* (BODY[])").expect("parses");
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
	assert!(set.contains(7, 7));
	assert!(!set.contains(6, 7));
	let set = parse_sequence_set("3:*").expect("parses");
	assert!(set.contains(3, 7));
	assert!(set.contains(7, 7));
	assert!(!set.contains(2, 7));
}

#[test]
fn rejects_malformed_lines() {
	assert_eq!(parse("CAPABILITY"), Err(ParseError::Malformed));
	assert_eq!(parse(""), Err(ParseError::Malformed));
	assert_eq!(parse("ta!g NOOP"), Err(ParseError::Malformed));
}

#[test]
fn unknown_commands_keep_the_tag() {
	assert_eq!(
		parse("a1 XFROBNICATE"),
		Err(ParseError::Unknown("a1".to_string()))
	);
	assert_eq!(
		parse("a2 STARTTLS").expect("parses").command,
		Command::StartTls
	);
}

#[test]
fn rejects_bad_arguments() {
	assert_eq!(
		parse("a1 LOGIN onlyuser"),
		Err(ParseError::BadArguments("a1".to_string()))
	);
	assert_eq!(
		parse("a1 FETCH 0 (FLAGS)"),
		Err(ParseError::BadArguments("a1".to_string()))
	);
	assert_eq!(
		parse("a1 FETCH 1 (BOGUS)"),
		Err(ParseError::BadArguments("a1".to_string()))
	);
}

#[test]
fn parses_search_or_not() {
	use crate::imap::mailbox::Flag;

	let cmd = parse("a1 SEARCH OR SEEN FLAGGED").expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search {
				ref criteria,
				uid: false,
				..
			} if criteria.len() == 1
				&& matches!(
					&criteria[0],
					SearchKey::Or(a, b)
					if **a == SearchKey::FlagIs(Flag::Seen, true)
						&& **b == SearchKey::FlagIs(Flag::Flagged, true)
				)
		),
		"{:?}",
		cmd.command
	);

	let cmd = parse("a2 SEARCH NOT SEEN").expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search { ref criteria, .. }
			if criteria.len() == 1
				&& matches!(
					&criteria[0],
					SearchKey::Not(k) if **k == SearchKey::FlagIs(Flag::Seen, true)
				)
		),
		"{:?}",
		cmd.command
	);
}

#[test]
fn parses_search_date_and_size() {
	let cmd = parse("a1 SEARCH BEFORE 1-Jan-2024").expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search { ref criteria, .. }
			if matches!(criteria[0], SearchKey::Before(2024, 1, 1))
		),
		"{:?}",
		cmd.command
	);

	let cmd = parse("a2 SEARCH SINCE 15-Jun-2023 SMALLER 1000").expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search { ref criteria, .. }
			if matches!(criteria[0], SearchKey::Since(2023, 6, 15))
				&& matches!(criteria[1], SearchKey::Smaller(1000))
		),
		"{:?}",
		cmd.command
	);
}

#[test]
fn parses_search_nested_paren_group() {
	use crate::imap::mailbox::Flag;

	// OR (NOT SEEN) FLAGGED
	let cmd = parse("a1 SEARCH OR (NOT SEEN) FLAGGED").expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search { ref criteria, .. }
			if criteria.len() == 1
				&& matches!(
					&criteria[0],
					SearchKey::Or(a, b)
					if matches!(
						a.as_ref(),
						SearchKey::And(keys)
						if keys.len() == 1
							&& matches!(&keys[0], SearchKey::Not(k) if **k == SearchKey::FlagIs(Flag::Seen, true))
					)
					&& **b == SearchKey::FlagIs(Flag::Flagged, true)
				)
		),
		"{:?}",
		cmd.command
	);
}

#[test]
fn parses_imap_date() {
	assert_eq!(super::parse_imap_date("1-Jan-2024"), Some((2024, 1, 1)));
	assert_eq!(super::parse_imap_date("31-Dec-1999"), Some((1999, 12, 31)));
	assert_eq!(super::parse_imap_date("15-Jun-2023"), Some((2023, 6, 15)));
	assert_eq!(super::parse_imap_date("01-Jan-2024"), Some((2024, 1, 1)));
	assert_eq!(super::parse_imap_date("1-Bad-2024"), None);
	assert_eq!(super::parse_imap_date("0-Jan-2024"), None);
}

#[test]
fn search_with_no_criteria_is_bad_arguments() {
	assert!(matches!(
		parse("t1 SEARCH"),
		Err(ParseError::BadArguments(_))
	));
}

#[test]
fn parses_search_on_date_criterion() {
	let cmd = parse("a1 SEARCH ON 1-Jan-2024").expect("parses");
	assert!(
		matches!(
			cmd.command,
			Command::Search { ref criteria, .. }
			if matches!(criteria[0], SearchKey::On(2024, 1, 1))
		),
		"{:?}",
		cmd.command
	);
}

#[test]
fn sequence_set_reversed_range_is_normalized() {
	let set = super::parse_sequence_set("5:2").expect("parse");
	// start > end → still matches values within [2, 5]
	assert!(set.contains(2, 10));
	assert!(set.contains(5, 10));
	assert!(set.contains(3, 10));
	assert!(!set.contains(6, 10));
}

#[test]
fn parse_sequence_set_empty_input_returns_none() {
	assert_eq!(super::parse_sequence_set(""), None);
}

#[test]
fn rejects_commands_with_bad_arguments() {
	for line in [
		"a LOGIN onlyuser",
		"a LOGIN",
		"a SELECT",
		"a CREATE",
		"a DELETE",
		"a RENAME onlyone",
		"a SUBSCRIBE",
		"a UNSUBSCRIBE",
		"a STATUS INBOX",
		"a STATUS INBOX (BOGUS)",
		"a FETCH",
		"a FETCH 1",
		"a STORE 1",
		"a STORE 1 +FLAGS",
		"a COPY 1",
		"a MOVE 1",
		"a APPEND",
		"a GETQUOTA",
		"a LSUB \"\"",
		"a CAPABILITY extra",
		"a NOOP extra",
	] {
		assert!(parse(line).is_err(), "expected error for {line:?}");
	}
}

#[test]
fn rejects_uid_without_valid_subcommand() {
	assert!(parse("a UID").is_err());
	assert!(parse("a UID BOGUS 1").is_err());
}

#[test]
fn parses_uid_fetch_and_search() {
	assert!(matches!(
		parse("a UID FETCH 1 (FLAGS)").expect("parses").command,
		Command::Fetch { uid: true, .. }
	));
	assert!(matches!(
		parse("a UID SEARCH ALL").expect("parses").command,
		Command::Search { uid: true, .. }
	));
}

#[test]
fn parses_id_nil_and_enable() {
	assert!(matches!(
		parse("a ID NIL").expect("parses").command,
		Command::Id
	));
	assert!(matches!(
		parse("a ENABLE CONDSTORE QRESYNC").expect("parses").command,
		Command::Enable { .. }
	));
}

#[test]
fn parses_esearch_with_scope_and_return() {
	let parsed = parse("m1 ESEARCH IN (mailboxes (\"INBOX\" \"Archive\")) RETURN (COUNT) ALL")
		.expect("parses");
	match parsed.command {
		Command::Esearch {
			sources,
			criteria,
			return_opts,
		} => {
			assert_eq!(
				sources,
				vec![SearchScope::Mailboxes(vec![
					"INBOX".to_string(),
					"Archive".to_string(),
				])]
			);
			assert_eq!(return_opts, vec![ReturnOpt::Count]);
			assert_eq!(criteria.len(), 1);
		}
		other => panic!("expected Esearch, got {other:?}"),
	}
}

#[test]
fn esearch_defaults_to_selected_and_all() {
	let parsed = parse("m1 ESEARCH ALL").expect("parses");
	match parsed.command {
		Command::Esearch {
			sources,
			return_opts,
			..
		} => {
			assert_eq!(sources, vec![SearchScope::Selected]);
			assert_eq!(return_opts, vec![ReturnOpt::All]);
		}
		other => panic!("expected Esearch, got {other:?}"),
	}
}

#[test]
fn esearch_rejects_unknown_scope() {
	assert!(parse("m1 ESEARCH IN (bogus) ALL").is_err());
}

#[test]
fn esearch_rejects_missing_criteria() {
	assert!(parse("m1 ESEARCH IN (mailboxes (\"INBOX\"))").is_err());
}

#[test]
fn esearch_rejects_unclosed_scope() {
	assert!(parse("m1 ESEARCH IN (mailboxes (\"INBOX\") ALL").is_err());
}

#[test]
fn parses_replace_command() {
	let parsed = parse(r"m1 REPLACE 3 Archive (\Seen) {10}").expect("parses");
	match parsed.command {
		Command::Replace {
			sequence,
			mailbox,
			flags,
			size,
			uid,
		} => {
			assert_eq!(sequence, 3);
			assert_eq!(mailbox, "Archive");
			assert_eq!(flags, vec!["\\Seen".to_string()]);
			assert_eq!(size, 10);
			assert!(!uid);
		}
		other => panic!("expected Replace, got {other:?}"),
	}
}

#[test]
fn parses_uid_replace_command() {
	let parsed = parse("m1 UID REPLACE 42 INBOX {5}").expect("parses");
	match parsed.command {
		Command::Replace { sequence, uid, .. } => {
			assert_eq!(sequence, 42);
			assert!(uid);
		}
		other => panic!("expected Replace, got {other:?}"),
	}
}

#[test]
fn replace_rejects_missing_sequence_and_zero() {
	assert!(parse("m1 REPLACE INBOX {5}").is_err());
	assert!(parse("m1 REPLACE 0 INBOX {5}").is_err());
}

#[test]
fn parses_fetch_preview() {
	let parsed = parse("m1 FETCH 1 (PREVIEW)").expect("parses");
	match parsed.command {
		Command::Fetch { items, .. } => assert!(items.contains(&FetchItem::Preview)),
		other => panic!("expected Fetch, got {other:?}"),
	}
}
