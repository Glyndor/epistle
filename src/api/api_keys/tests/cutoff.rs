//! The warning for `read` and `write` and the release that ends them.

use crate::api::api_keys::legacy_cutoff::{LEGACY_SCOPES_REFUSED_FROM, refused_at, warning};

#[test]
fn legacy_warning_names_the_cutoff() {
	let text = warning("ci");
	assert!(text.contains(LEGACY_SCOPES_REFUSED_FROM), "{text}");
	assert!(text.contains("epistle api-key set ci --scope"), "{text}");
	assert!(text.contains("management and mail"), "{text}");
}

#[test]
fn cutoff_is_not_reached_before_its_version() {
	assert!(!refused_at("0.14.0"));
	assert!(!refused_at("0.15.0"));
	assert!(!refused_at("0.16.9"));
	assert!(refused_at(LEGACY_SCOPES_REFUSED_FROM));
	assert!(refused_at("0.17.1"));
	assert!(refused_at("1.0.0"));
	assert!(!refused_at("0.9.0"), "compared as numbers, not as text");
}

#[test]
fn an_unreadable_version_is_not_past_the_cutoff() {
	assert!(!refused_at(""));
	assert!(!refused_at("nightly"));
	assert!(!refused_at("0.17"));
}
