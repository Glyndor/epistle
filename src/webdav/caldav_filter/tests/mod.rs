pub use super::*;

pub(super) mod base;

/// Whether the object matches. The cases here are small enough to stay well
/// inside the work bound, so a search that ran out of work is a failure of
/// the case and not an answer.
fn matches(filter: &CalendarQueryFilter, ics: &str) -> bool {
	super::matches(filter, ics).expect("within the work bound")
}
