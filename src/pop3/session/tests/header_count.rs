use super::super::top_of;
use crate::util::header_block::{cases, field_count};

#[test]
fn the_field_count_is_never_below_the_headers_top_shows() {
	for raw in cases::messages() {
		let headers = top_of(&raw, 0);
		assert!(field_count(&raw) >= cases::fields_in(&headers), "{raw:?}");
	}
}
