//! Whether a name is under a domain. The domain has to start at a label
//! boundary: a name that only ends with the domain belongs to another
//! zone, and treating it as one writes records where they do not belong.

use super::*;

#[test]
fn a_name_at_or_under_the_domain_is_inside_it() {
	assert!(in_domain("example.org", "example.org"));
	assert!(in_domain("www.example.org", "example.org"));
	assert!(in_domain("deep.host.example.org", "example.org"));
}

#[test]
fn a_name_that_only_ends_with_the_domain_is_outside_it() {
	assert!(!in_domain("badexample.org", "example.org"));
	assert!(!in_domain("example.org.evil.net", "example.org"));
	assert!(!in_domain("org", "example.org"));
}
