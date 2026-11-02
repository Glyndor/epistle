//! `epistle account catch-all …`: the dispatcher over the catch-all domain
//! mutators.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::account::{
	CatchAllArgs, CatchAllSubcommand, catch_all_add_with_store, catch_all_list,
	catch_all_remove_with_store, prepare,
};

/// Run `epistle account catch-all …` against the dynamic store.
pub(in crate::cli::account) fn dispatch_catch_all(
	args: CatchAllArgs,
	config_path: &Path,
	json: bool,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let store = match prepare(config_path, catch_all_name(&args.action)) {
		Ok(store) => store,
		Err(code) => return code,
	};
	match args.action {
		CatchAllSubcommand::List { name, json: leaf } if leaf || json => {
			crate::cli::account::json::catch_alls(&store, &name, out)
		}
		CatchAllSubcommand::List { name, .. } => catch_all_list(&store, &name, out),
		CatchAllSubcommand::Add { name, domain } => {
			catch_all_add_with_store(&store, &name, &domain, out, json)
		}
		CatchAllSubcommand::Remove { name, domain } => {
			catch_all_remove_with_store(&store, &name, &domain, out, json)
		}
	}
}

/// The account name from any catch-all sub-action.
fn catch_all_name(action: &CatchAllSubcommand) -> &str {
	match action {
		CatchAllSubcommand::List { name, .. }
		| CatchAllSubcommand::Add { name, .. }
		| CatchAllSubcommand::Remove { name, .. } => name,
	}
}
