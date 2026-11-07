//! Fixtures the apply-phase tests share: the minimal set of answers, the
//! digest of a file on disk and the modification time of one.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::super::*;
use crate::cli::init::answers::Services;

#[cfg(unix)]
pub(in crate::cli::init::apply::tests) fn sha256_of(path: &std::path::Path) -> Option<Vec<u8>> {
	let bytes = std::fs::read(path).ok()?;
	Some(
		ring::digest::digest(&ring::digest::SHA256, &bytes)
			.as_ref()
			.to_vec(),
	)
}

#[cfg(not(unix))]
pub(in crate::cli::init::apply::tests) fn sha256_of(path: &std::path::Path) -> Option<Vec<u8>> {
	None
}

pub(in crate::cli::init::apply::tests) fn answers_minimal() -> Answers {
	Answers {
		mode: crate::cli::init::answers::Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: Some(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
		image: Some("localhost/epistle:dev".to_string()),
		acme: None,
		first_account: None,
		resources: Default::default(),
	}
}

#[cfg(unix)]
pub(in crate::cli::init::apply::tests) fn file_mtime(path: &PathBuf) -> std::time::SystemTime {
	std::fs::metadata(path)
		.expect("metadata")
		.modified()
		.expect("mtime")
}

#[cfg(not(unix))]
pub(in crate::cli::init::apply::tests) fn file_mtime(_path: &PathBuf) -> std::time::SystemTime {
	std::time::SystemTime::UNIX_EPOCH
}
