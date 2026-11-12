//! Assertion helpers the apply-phase tests share: the name of an
//! `ApplyError` variant, the minimal set of answers at a given path, and
//! the rendered report the operator reads.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use super::super::*;
use crate::cli::init::answers::Services;

/// The variant name of an `ApplyError`, for the assertion messages
/// that must not print the full Debug. The `KeyWrite` and
/// `OAuthPair*` variants carry path and reason strings; the
/// `ConfigEncode`, `ConfigInvalid`, `RsaKeygen` and `Rng` variants
/// carry user-facing messages. None of those are credentials, but
/// the panic message has to be a CI log, and printing the full
/// Debug makes the line wider than the diagnosis needs. The match
/// is exhaustive on purpose: a new variant added to `ApplyError`
/// breaks this file at compile time, so the next caller cannot
/// fall through and print the whole struct. Exposed to the folders that
/// assert on a refusal the same way `answers_minimal` and
/// `render_report_to_string` are.
pub(in crate::cli::init::apply::tests) fn apply_error_name(error: &ApplyError) -> &'static str {
	match error {
		ApplyError::KeysDir(..) => "KeysDir",
		ApplyError::KeyWrite(..) => "KeyWrite",
		ApplyError::OAuthPairIncomplete(_) => "OAuthPairIncomplete",
		ApplyError::OAuthPairMismatch => "OAuthPairMismatch",
		ApplyError::CertPairIncomplete(_) => "CertPairIncomplete",
		ApplyError::ConfigEncode(_) => "ConfigEncode",
		ApplyError::ConfigInvalid(_) => "ConfigInvalid",
		ApplyError::ConfigRead(..) => "ConfigRead",
		ApplyError::ConfigWrite(..) => "ConfigWrite",
		ApplyError::ConfigDir(..) => "ConfigDir",
		ApplyError::ConfigSymlink(_) => "ConfigSymlink",
		ApplyError::ConfigNotAFile(_) => "ConfigNotAFile",
		ApplyError::RsaKeygen(_) => "RsaKeygen",
		ApplyError::Rng(_) => "Rng",
		ApplyError::ExistingSecretUnreadable(..) => "ExistingSecretUnreadable",
		ApplyError::DatabaseVolume(_) => "DatabaseVolume",
		ApplyError::FirstAccount(_) => "FirstAccount",
		ApplyError::KeyMove(_) => "KeyMove",
		ApplyError::AnswersFile(..) => "AnswersFile",
		ApplyError::PanelKey(_) => "PanelKey",
		ApplyError::HostBinaryInvalid(_) => "HostBinaryInvalid",
	}
}

pub(in crate::cli::init::apply::tests) fn answers_minimal(
	data_dir: &Path,
	config_path: &Path,
) -> Answers {
	Answers {
		mode: crate::cli::init::answers::Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: Some(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
		data_dir: data_dir.to_path_buf(),
		config_path: config_path.to_path_buf(),
		dns: None,
		services: Services::default(),
		image: Some("localhost/epistle:dev".to_string()),
		acme: None,
		first_account: None,
		resources: Default::default(),
	}
}

pub(in crate::cli::init::apply::tests) fn render_report_to_string(report: &Report) -> String {
	let mut buf = Vec::new();
	report.write_to(&mut buf).expect("render report");
	String::from_utf8_lossy(&buf).into_owned()
}
