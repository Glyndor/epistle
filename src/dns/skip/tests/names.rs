//! The names the configuration writes.

use super::super::*;

#[test]
fn every_group_round_trips_through_its_name() {
	for group in SkipGroup::ALL {
		assert_eq!(SkipGroup::parse(group.name()), Some(group));
	}
	assert_eq!(SkipGroup::parse("srv"), None, "a DNS type is not a group");
	assert_eq!(SkipGroup::parse("CAA"), None, "names are lower case");
}
