use super::*;
use crate::imap::changelog::Change;

fn entry(position: u64, op: Op, id: &str) -> Entry {
	Entry {
		position,
		change: Change {
			object: Object::Email,
			op,
			id: id.to_string(),
		},
	}
}

#[test]
fn created_then_destroyed_is_not_reported() {
	let entries = [
		entry(1, Op::Created, "a"),
		entry(2, Op::Updated, "a"),
		entry(3, Op::Destroyed, "a"),
	];
	let folded = fold(&entries, Object::Email, None, false, 3);
	assert!(folded.outcomes.is_empty(), "{:?}", folded.outcomes);
	assert_eq!(folded.through, 3);
}

#[test]
fn each_id_is_classified_once() {
	let entries = [
		entry(1, Op::Created, "new"),
		entry(2, Op::Updated, "new"),
		entry(3, Op::Updated, "old"),
		entry(4, Op::Destroyed, "gone"),
		entry(5, Op::Updated, "dead"),
		entry(6, Op::Destroyed, "dead"),
		entry(7, Op::Destroyed, "reused"),
		entry(8, Op::Created, "reused"),
	];
	let folded = fold(&entries, Object::Email, None, false, 8);
	assert_eq!(
		folded.outcomes,
		vec![
			("new".to_string(), Outcome::Created),
			("old".to_string(), Outcome::Updated { only_updates: true }),
			("gone".to_string(), Outcome::Destroyed),
			("dead".to_string(), Outcome::Destroyed),
			(
				"reused".to_string(),
				Outcome::Updated {
					only_updates: false
				}
			),
		]
	);
}

/// A page stops before the entry that would exceed `max` ids, and ends on
/// the position just before it; later changes to ids already in the page are
/// left for the next page too.
#[test]
fn a_page_ends_before_the_first_entry_it_cannot_hold() {
	let entries = [
		entry(4, Op::Created, "a"),
		entry(5, Op::Created, "b"),
		entry(6, Op::Created, "c"),
		entry(7, Op::Destroyed, "a"),
	];
	let folded = fold(&entries, Object::Email, Some(2), false, 7);
	assert!(folded.has_more);
	assert_eq!(folded.through, 5);
	assert_eq!(folded.ids(|o| o == Outcome::Created), vec!["a", "b"]);
}

#[test]
fn skipped_updates_do_not_count_toward_the_page() {
	let entries = [
		entry(1, Op::Updated, "a"),
		entry(2, Op::Created, "b"),
		entry(3, Op::Updated, "a"),
	];
	let folded = fold(&entries, Object::Email, Some(1), true, 3);
	assert!(!folded.has_more);
	assert_eq!(folded.outcomes, vec![("b".to_string(), Outcome::Created)]);
}
