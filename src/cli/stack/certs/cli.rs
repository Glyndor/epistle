//! The arguments of `epistle stack certs`.

use clap::Subcommand;

use crate::cli::stack::StackAction;

/// The two directions of `stack certs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum CertsCli {
	/// Move ACME renewal, TLSA and the DNS credential to `certs`.
	Enable {
		/// Do not ask for confirmation.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// Put them back in `mail`.
	Disable {
		/// Do not ask for confirmation.
		#[arg(long, short = 'y')]
		yes: bool,
	},
}

impl CertsCli {
	/// The stack action this direction runs.
	pub(in crate::cli) fn action(self) -> StackAction {
		match self {
			CertsCli::Enable { yes } => StackAction::Certs { on: true, yes },
			CertsCli::Disable { yes } => StackAction::Certs { on: false, yes },
		}
	}
}
