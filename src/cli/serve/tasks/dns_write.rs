//! How the DKIM rotations reach DNS.
//!
//! Without the certificates container this process holds the `[dns]`
//! credential and writes the records itself. With it, this process holds no
//! credential at all: the records are written by the container that holds
//! it, and this one asks it to through the hand-off directory
//! (`crate::dns::handoff`).

use std::path::PathBuf;

/// Where the rotations write their records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::cli) enum DnsWrite {
	/// This process holds the DNS credential and writes the records
	/// itself.
	Direct,
	/// This process holds no credential: the certificates container writes
	/// the records, and this one asks it to through the hand-off directory
	/// it serves.
	Handoff(PathBuf),
}

impl DnsWrite {
	/// How the rotations reach DNS in the installation `config` describes.
	///
	/// The compose file says which layout runs: with the certificates
	/// container in it, the DNS credential is in that container, and the
	/// records are published through the hand-off it serves. The same file
	/// `epistle status` reads.
	pub(in crate::cli) fn for_install(config: &crate::config::Config) -> DnsWrite {
		let compose = crate::cli::init::compose_file_path(&config.data_dir);
		match crate::cli::stack::certs::runs_certs(&compose) {
			Ok(true) => DnsWrite::Handoff(crate::dns::handoff::dir(&config.data_dir)),
			_ => DnsWrite::Direct,
		}
	}

	/// Whether this process holds the DNS credential and can publish a
	/// record by itself.
	///
	/// The question matters where the rotation decides whether a `[dns]`
	/// entry can publish for a domain: with the split on, the credential is
	/// in the other container, and asking this process for it would refuse
	/// every zone.
	pub(in crate::cli) fn holds_credential(&self) -> bool {
		matches!(self, DnsWrite::Direct)
	}
}
