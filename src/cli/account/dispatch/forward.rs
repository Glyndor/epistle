//! `epistle account forward …`: the dispatcher over the forward-target
//! mutators.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::account::{
	ForwardArgs, ForwardSubcommand, forward_add_with_store, forward_list,
	forward_remove_with_store, prepare,
};
use crate::config::Config;

/// Run `epistle account forward …` against the dynamic store. The
/// mutator refuses a static account so a typo cannot land on disk;
/// refusing up front keeps the prepare/store sequence identical to the
/// rest of the umbrella.
pub(in crate::cli::account) fn dispatch_forward(
	args: ForwardArgs,
	config_path: &Path,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let store = match prepare(config_path, dynamic_name(&args.action)) {
		Ok(store) => store,
		Err(code) => return code,
	};
	match args.action {
		ForwardSubcommand::List { name, json: leaf } if leaf || json => {
			crate::cli::account::json::forwards(&store, &name, out)
		}
		ForwardSubcommand::List { name, .. } => forward_list(&store, &name, out),
		ForwardSubcommand::Add { name, address } => {
			// Delivery rewrites a forwarded envelope sender with SRS only
			// when `srs_secret` or an `[[srs_domain]]` is set; without it the next hop checks SPF
			// against the original sender's domain and a `-all` domain
			// rejects the copy. The config loader refuses a static forward
			// for the same reason.
			if Config::load(config_path).is_ok_and(|config| !config.srs_enabled()) {
				return crate::cli::exit::policy(format_args!(
					"account {name} forward: set `srs_secret` or an `[[srs_domain]]` in the config first; \
					 without SRS a forwarded copy fails SPF at the next hop"
				));
			}
			forward_add_with_store(&store, &name, &address, out, json)
		}
		ForwardSubcommand::Remove { name, address } => {
			forward_remove_with_store(&store, &name, &address, out, json)
		}
	}
}

/// The account name from any forward sub-action. The dispatcher above
/// uses it as the canonical "is this a static account" check before
/// running any mutator.
fn dynamic_name(action: &ForwardSubcommand) -> &str {
	match action {
		ForwardSubcommand::List { name, .. }
		| ForwardSubcommand::Add { name, .. }
		| ForwardSubcommand::Remove { name, .. } => name,
	}
}
