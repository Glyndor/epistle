//! The public label of a blocklist zone: what text that leaves the host may
//! say about it.

use super::super::{public_label, public_name};

#[test]
fn a_zone_is_named_by_its_last_two_labels() {
	assert_eq!(public_label("zen.spamhaus.org"), "spamhaus.org");
	assert_eq!(
		public_label("k3yA1b2C3d4E5f6.zen.dq.spamhaus.net"),
		"spamhaus.net"
	);
	assert_eq!(public_label("bl.example."), "bl.example");
	assert_eq!(
		public_name("a.b.example.net").as_deref(),
		Some("example.net")
	);
}

#[test]
fn a_zone_without_a_public_name_is_generic() {
	for zone in ["", "localbl", "127.0", "10.in-addr", ".."] {
		let expected = if zone == "10.in-addr" {
			"10.in-addr"
		} else {
			"a DNS blocklist"
		};
		assert_eq!(public_label(zone), expected, "{zone:?}");
	}
	assert_eq!(public_name("localbl"), None);
}
