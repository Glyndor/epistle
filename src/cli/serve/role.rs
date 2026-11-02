//! Which part of the server a `serve` process runs.
//!
//! One process runs everything unless the stack splits the certificate work
//! into a container of its own (`docs/operations/container-split.md`). Then
//! `mail` runs with `--role mail`, keeps the listeners and reads its
//! certificate from disk, and `certs` runs with `--role certs`, holds the DNS
//! credential and the ACME account key, and listens on nothing.

/// The part of the server one `serve` process runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ServeRole {
	/// The listeners and the certificate renewal in one process.
	#[default]
	All,
	/// The listeners only. The certificate comes from `<data_dir>/acme` on
	/// disk, written by the certificates container, and this process holds
	/// no DNS credential and no ACME account key.
	Mail,
	/// Certificate renewal (ACME `dns-01` through the `[dns]` provider) and
	/// the TLSA refresh, with no listener.
	Certs,
}

impl ServeRole {
	/// Whether this process obtains certificates from the authority.
	pub fn renews_certificates(self) -> bool {
		matches!(self, ServeRole::All | ServeRole::Certs)
	}

	/// Whether this process may use the DNS provider credential.
	pub fn writes_dns(self) -> bool {
		matches!(self, ServeRole::All | ServeRole::Certs)
	}

	/// The value written after `--role`.
	pub fn as_str(self) -> &'static str {
		match self {
			ServeRole::All => "all",
			ServeRole::Mail => "mail",
			ServeRole::Certs => "certs",
		}
	}
}
