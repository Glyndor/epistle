use super::super::{Command, NotifyEvent, NotifyRequest, parse};

fn notify(line: &str) -> Result<NotifyRequest, ()> {
	match parse(line).map_err(|_| ())?.command {
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
		}
	);
}

#[test]
fn accepts_and_ignores_other_specifiers() {
	// personal/subtree/mailboxes are accepted; only `selected` events are kept.
	let request = notify(
		"a1 NOTIFY SET (personal (MessageNew)) (subtree (Foo Bar) (MessageNew)) \
		 (selected (MessageExpunge))",
	)
	.expect("parses");
	assert_eq!(
		request,
		NotifyRequest::Set {
			status: false,
			selected: vec![NotifyEvent::MessageExpunge],
		}
	);
}

#[test]
fn accepts_none_event_list_for_specifier() {
	let request = notify("a1 NOTIFY SET (selected NONE)").expect("parses");
	assert_eq!(
		request,
		NotifyRequest::Set {
			status: false,
			selected: vec![],
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
