//! The arguments of `epistle stack certs`.

use clap::Subcommand;

use crate::cli::stack::StackAction;

/// The two directions of `stack certs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum CertsCli {
	/// Move the ACME renewal, the TLSA refresh and the DNS credential into
	/// a `certs` container.
	Enable,
	/// Put them back in `mail`.
	Disable,
}

impl CertsCli {
	/// The stack action this direction runs.
	pub(in crate::cli) fn action(self) -> StackAction {
		StackAction::Certs {
			on: self == CertsCli::Enable,
		}
	}
}
