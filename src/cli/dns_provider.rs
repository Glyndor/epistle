//! DNS provider administration: the `[dns]` section.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;

use super::resource;
use super::stack::StackAction;
use crate::config::Config;

#[path = "dns_provider_probe.rs"]
mod probe;
#[path = "dns_provider_set.rs"]
mod set;
#[path = "dns_provider_show.rs"]
mod show;

#[cfg(test)]
#[path = "dns_provider_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "dns_provider_tests_set.rs"]
mod tests_set;

pub use set::ProviderArgs;

/// DNS administration areas.
#[derive(Debug, Subcommand)]
pub enum DnsCli {
	/// Manage the DNS provider used for record automation.
	Provider {
		/// Provider action.
		#[command(subcommand)]
		action: ProviderCli,
	},
}

/// Provider actions.
#[derive(Debug, Subcommand)]
pub enum ProviderCli {
	/// Show the configured provider. Credentials are never printed.
	Show {
		/// Print the provider settings as JSON.
		#[arg(long)]
		json: bool,
	},
	/// Choose the provider and its zone and credential sources.
	Set {
		/// Provider id, for example cloudflare, route53 or manual.
		provider: String,
		/// The provider settings.
		#[command(flatten)]
		args: Box<ProviderArgs>,
	},
	/// Remove the provider and return to manual DNS.
	Unset,
	/// List the zone's records through the provider (read only).
	Test,
}

pub(super) fn run(path: &Path, action: DnsCli, dry_run: bool) -> ExitCode {
	resource::exit_resource(execute_with(
		path,
		action,
		dry_run,
		&mut std::io::stdout().lock(),
		&mut super::style::stderr(),
		super::stack::run,
	))
}

fn execute_with(
	path: &Path,
	action: DnsCli,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, resource::ResourceError> {
	let DnsCli::Provider { action } = action;
	let change: resource::Change = match action {
		ProviderCli::Show { json } => {
			show::run(
				&Config::load(path)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?,
				json,
				out,
			)?;
			return Ok(ExitCode::SUCCESS);
		}
		ProviderCli::Test => {
			let config = Config::load(path)
				.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
			return probe::run(&config, out, status);
		}
		ProviderCli::Set { provider, args } => {
			let fields = set::fields(&provider, &args)?;
			Box::new(move |document, _| {
				document
					.set_table_fields(&["dns"], &fields)
					.map_err(resource::ResourceError::Failure)
			})
		}
		ProviderCli::Unset => Box::new(|document, _| {
			document
				.remove_table(&["dns"])
				.map(|_| ())
				.map_err(resource::ResourceError::Failure)
		}),
	};
	resource::apply_edit(path, dry_run, "dns provider", out, status, restart, change)
}
