//! Parsing of UID, ID, ENABLE, ESEARCH, REPLACE and METADATA commands.

use super::*;

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
		assert!(
			parse(line, DEFAULT_APPEND_LIMIT).is_err(),
			"expected error for {line:?}"
		);
	}
}

#[test]
fn rejects_uid_without_valid_subcommand() {
	assert!(parse("a UID", DEFAULT_APPEND_LIMIT).is_err());
	assert!(parse("a UID BOGUS 1", DEFAULT_APPEND_LIMIT).is_err());
}

#[test]
fn parses_uid_fetch_and_search() {
	assert!(matches!(
		parse("a UID FETCH 1 (FLAGS)", DEFAULT_APPEND_LIMIT)
			.expect("parses")
			.command,
		Command::Fetch { uid: true, .. }
	));
	assert!(matches!(
		parse("a UID SEARCH ALL", DEFAULT_APPEND_LIMIT)
			.expect("parses")
			.command,
		Command::Search { uid: true, .. }
	));
}

#[test]
fn parses_id_nil_and_enable() {
	assert!(matches!(
		parse("a ID NIL", DEFAULT_APPEND_LIMIT)
			.expect("parses")
			.command,
		Command::Id
	));
	assert!(matches!(
		parse("a ENABLE CONDSTORE QRESYNC", DEFAULT_APPEND_LIMIT)
			.expect("parses")
			.command,
		Command::Enable { .. }
	));
}

#[test]
fn parses_esearch_with_scope_and_return() {
	let parsed = parse(
		"m1 ESEARCH IN (mailboxes (\"INBOX\" \"Archive\")) RETURN (COUNT) ALL",
		DEFAULT_APPEND_LIMIT,
	)
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
	let parsed = parse("m1 ESEARCH ALL", DEFAULT_APPEND_LIMIT).expect("parses");
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
	assert!(parse("m1 ESEARCH IN (bogus) ALL", DEFAULT_APPEND_LIMIT).is_err());
}

#[test]
fn esearch_rejects_missing_criteria() {
	assert!(
		parse(
			"m1 ESEARCH IN (mailboxes (\"INBOX\"))",
			DEFAULT_APPEND_LIMIT
		)
		.is_err()
	);
}

#[test]
fn esearch_rejects_unclosed_scope() {
	assert!(
		parse(
			"m1 ESEARCH IN (mailboxes (\"INBOX\") ALL",
			DEFAULT_APPEND_LIMIT
		)
		.is_err()
	);
}

#[test]
fn parses_replace_command() {
	let parsed = parse(r"m1 REPLACE 3 Archive (\Seen) {10}", DEFAULT_APPEND_LIMIT).expect("parses");
	match parsed.command {
		Command::Replace {
			sequence,
			mailbox,
			flags,
			date,
			size,
			uid,
			synchronizing,
		} => {
			assert_eq!(sequence, 3);
			assert_eq!(mailbox, "Archive");
			assert_eq!(flags, vec!["\\Seen".to_string()]);
			assert_eq!(date, None);
			assert_eq!(size, 10);
			assert!(!uid);
			assert!(synchronizing);
		}
		other => panic!("expected Replace, got {other:?}"),
	}
}

#[test]
fn parses_uid_replace_command() {
	let parsed = parse("m1 UID REPLACE 42 INBOX {5}", DEFAULT_APPEND_LIMIT).expect("parses");
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
	assert!(parse("m1 REPLACE INBOX {5}", DEFAULT_APPEND_LIMIT).is_err());
	assert!(parse("m1 REPLACE 0 INBOX {5}", DEFAULT_APPEND_LIMIT).is_err());
}

#[test]
fn parses_fetch_preview() {
	let parsed = parse("m1 FETCH 1 (PREVIEW)", DEFAULT_APPEND_LIMIT).expect("parses");
	match parsed.command {
		Command::Fetch { items, .. } => assert!(items.contains(&FetchItem::Preview)),
		other => panic!("expected Fetch, got {other:?}"),
	}
}

#[test]
fn parses_getmetadata_single_and_list() {
	let parsed = parse(
		"m1 GETMETADATA INBOX /private/comment",
		DEFAULT_APPEND_LIMIT,
	)
	.expect("parses");
	match parsed.command {
		Command::GetMetadata { mailbox, entries } => {
			assert_eq!(mailbox, "INBOX");
			assert_eq!(entries, vec!["/private/comment".to_string()]);
		}
		other => panic!("expected GetMetadata, got {other:?}"),
	}
	let parsed = parse(
		"m2 GETMETADATA (MAXSIZE 1024) INBOX (/private/a /shared/b)",
		DEFAULT_APPEND_LIMIT,
	)
	.expect("parses");
	match parsed.command {
		Command::GetMetadata { entries, .. } => {
			assert_eq!(
				entries,
				vec!["/private/a".to_string(), "/shared/b".to_string()]
			);
		}
		other => panic!("expected GetMetadata, got {other:?}"),
	}
}

#[test]
fn parses_setmetadata_with_value_and_nil() {
	let parsed = parse(
		"m1 SETMETADATA INBOX (/private/comment \"hi\" /private/old NIL)",
		DEFAULT_APPEND_LIMIT,
	)
	.expect("parses");
	match parsed.command {
		Command::SetMetadata { mailbox, items } => {
			assert_eq!(mailbox, "INBOX");
			assert_eq!(
				items[0],
				("/private/comment".to_string(), Some("hi".to_string()))
			);
			assert_eq!(items[1], ("/private/old".to_string(), None));
		}
		other => panic!("expected SetMetadata, got {other:?}"),
	}
}

#[test]
fn setmetadata_rejects_unbalanced() {
	assert!(
		parse(
			"m1 SETMETADATA INBOX /private/x \"v\"",
			DEFAULT_APPEND_LIMIT
		)
		.is_err()
	);
}
