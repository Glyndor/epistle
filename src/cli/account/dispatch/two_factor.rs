//! `epistle account 2fa …`: the dispatcher over the two-factor reads and
//! the disable mutator.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::account::{
	TwoFactorArgs, TwoFactorSubcommand, prepare, two_factor_disable, two_factor_show,
};

/// Run `epistle account 2fa …` against the dynamic store. The mutator
/// refuses a static account with the config-edit hint before any TOTP
/// action runs, mirroring the rest of the umbrella.
pub(in crate::cli::account) fn dispatch_two_factor(
	args: TwoFactorArgs,
	config_path: &Path,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let store = match prepare(config_path, two_factor_name(&args.action)) {
		Ok(store) => store,
		Err(code) => return code,
	};
	match args.action {
		TwoFactorSubcommand::Show { name, json: leaf } if leaf || json => {
			crate::cli::account::json::two_factor(&store, &name, out)
		}
		TwoFactorSubcommand::Show { name, .. } => two_factor_show(&store, &name, out),
		TwoFactorSubcommand::Disable { name, yes } => {
			two_factor_disable(&store, &name, yes, out, json)
		}
	}
}

/// The account name from any 2fa sub-action. The dispatcher above uses
/// it as the canonical "is this a static account" check before any
/// mutator or read runs.
fn two_factor_name(action: &TwoFactorSubcommand) -> &str {
	match action {
		TwoFactorSubcommand::Show { name, .. } | TwoFactorSubcommand::Disable { name, .. } => name,
	}
}
