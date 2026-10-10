//! Shared helpers for the answers test split.
//!
//! The tests for `Answers` validation, deserialisation, and the
//! renderer messages grew out of one file past the per-file line
//! limit; the split lifts them into topic-named siblings
//! (`answers_tests_validate`, `answers_tests_deserialise`,
//! `answers_tests_messages`) and keeps this file as the home for the
//! shared `minimal` builder every topic reaches for.

use std::path::PathBuf;

use super::*;

/// Answers defaulting to a Manual mode with a single `example.org`
/// domain and the standard production paths. Tests edit the
/// field they care about and leave the rest alone, so a regression
/// on a neighbouring field still surfaces as a `validate()`
/// failure rather than a panic in this helper.
pub(super) fn minimal(mode: Mode) -> Answers {
	Answers {
		mode,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: None,
		public_ipv6: None,
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
		image: None,
		acme: None,
	}
}
