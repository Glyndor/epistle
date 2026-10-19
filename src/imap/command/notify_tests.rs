use super::super::{
	Command, DEFAULT_APPEND_LIMIT, NotifyEvent, NotifyGroup, NotifyMailboxes, NotifyRequest, parse,
};

fn notify(line: &str) -> Result<NotifyRequest, ()> {
	match parse(line, DEFAULT_APPEND_LIMIT).map_err(|_| ())?.command {
		Command::Notify(request) => Ok(request),
		_ => Err(()),
	}
}

#[test]
fn parses_notify_none() {
	assert_eq!(notify("a1 NOTIFY NONE"), Ok(NotifyRequest::None));
	assert_eq!(notify("a1 notify none"), Ok(NotifyRequest::None));
}

#[test]
fn parses_notify_set_selected() {
	let request =
		notify("a1 NOTIFY SET (selected (MessageNew MessageExpunge FlagChange))").expect("parses");
	assert_eq!(
		request,
		NotifyRequest::Set {
			status: false,
			selected: vec![
				NotifyEvent::MessageNew,
				NotifyEvent::MessageExpunge,
				NotifyEvent::FlagChange,
			],
			others: vec![],
		}
	);
}

#[test]
fn parses_notify_set_status_modifier() {
	let request = notify("a1 NOTIFY SET STATUS (selected (MessageNew))").expect("parses");
	assert_eq!(
		request,
		NotifyRequest::Set {
			status: true,
			selected: vec![NotifyEvent::MessageNew],
			others: vec![],
		}
	);
}

#[test]
fn records_other_specifiers() {
	let request = notify(
		"a1 NOTIFY SET (personal (MessageNew)) (subtree (Foo Bar) (MessageNew)) \
		 (selected (MessageExpunge))",
	)
	.expect("parses");
	let new = vec![NotifyEvent::MessageNew];
	assert_eq!(
		request,
		NotifyRequest::Set {
			status: false,
			selected: vec![NotifyEvent::MessageExpunge],
			others: vec![
				NotifyGroup {
					mailboxes: NotifyMailboxes::Personal,
					events: new.clone(),
				},
				NotifyGroup {
					mailboxes: NotifyMailboxes::Subtree(vec!["Foo".into(), "Bar".into()]),
					events: new,
				},
			],
		}
	);
}

#[test]
fn parses_a_single_mailbox_without_parentheses() {
	// RFC 5465 §8: one-or-more-mailbox = mailbox / "(" mailbox *(SP mailbox) ")"
	let request = notify("a1 notify set status (mailboxes imaptest2 (MessageNew MessageExpunge))")
		.expect("parses");
	assert_eq!(
		request,
		NotifyRequest::Set {
			status: true,
			selected: vec![],
			others: vec![NotifyGroup {
				mailboxes: NotifyMailboxes::Mailboxes(vec!["imaptest2".into()]),
				events: vec![NotifyEvent::MessageNew, NotifyEvent::MessageExpunge],
			}],
		}
	);
	assert!(notify("a1 NOTIFY SET (mailboxes \"a b\" NONE)").is_ok());
	assert!(notify("a1 NOTIFY SET (mailboxes () (MessageNew))").is_err());
	assert!(notify("a1 NOTIFY SET (mailboxes (MessageNew))").is_err());
}

#[test]
fn accepts_none_event_list_for_specifier() {
	let request = notify("a1 NOTIFY SET (selected NONE)").expect("parses");
	assert_eq!(
		request,
		NotifyRequest::Set {
			status: false,
			selected: vec![],
			others: vec![],
		}
	);
}

#[test]
fn rejects_malformed_notify() {
	assert!(notify("a1 NOTIFY").is_err());
	assert!(notify("a1 NOTIFY BOGUS").is_err());
	assert!(notify("a1 NOTIFY SET").is_err());
	assert!(notify("a1 NOTIFY SET ()").is_err());
	assert!(notify("a1 NOTIFY SET (selected (Bogus))").is_err());
	assert!(notify("a1 NOTIFY SET (selected (MessageNew)").is_err());
	assert!(notify("a1 NOTIFY NONE extra").is_err());
}
