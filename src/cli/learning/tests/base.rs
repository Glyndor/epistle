use super::*;

#[test]
fn a_listing_at_the_cap_says_it_was_cut() {
	assert_eq!(cut_note(3), None);
	assert_eq!(cut_note(9_999), None);
	assert!(cut_note(10_000).is_some_and(|note| note.contains("10000")));
}
