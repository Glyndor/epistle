//! DNS provider administration: the `[dns]` section.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;

use super::resource;
use super::stack::StackAction;
use crate::config::Config;

mod check;
mod compose;
mod probe;
mod secret;
mod set;
mod show;
#[cfg(test)]
mod tests;
mod unset;
mod write;

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
	/// Lock the zone against mail spoofing.
	Lockdown(crate::cli::dns_lockdown::LockdownArgs),
}

/// Provider actions.
#[derive(Debug, Subcommand)]
pub enum ProviderCli {
	/// Report credential capabilities without changing records or settings.
	Check {
		/// Print the same findings as JSON.
		#[arg(long)]
		json: bool,
	},
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
	/// Remove the provider, or only the entry of one zone with --zone.
	Unset {
		/// The zone whose entry is removed.
		#[arg(long)]
		zone: Option<String>,
	},
	/// List the zone's records through the provider (read only).
	Test,
}

pub(super) fn run(path: &Path, action: DnsCli, dry_run: bool, json: bool) -> ExitCode {
	match action {
		DnsCli::Lockdown(args) => crate::cli::dns_lockdown::run(path, args, dry_run),
		action => resource::exit_resource(execute_with(
			path,
			action,
			dry_run,
			json,
			&mut std::io::stdout().lock(),
			&mut super::style::stderr(),
			super::stack::run,
		)),
	}
}

fn execute_with(
	path: &Path,
	action: DnsCli,
	dry_run: bool,
	json: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, resource::ResourceError> {
	let DnsCli::Provider { action } = action else {
		return Err("dns lockdown runs through its own path; this should not be reached".into());
	};
	let (change, verb, fields): (resource::Change, _, _) = match action {
		ProviderCli::Check { json: leaf } => {
			let config = Config::load(path)
				.map_err(|error| resource::ResourceError::Failure(check::config_error(&error)))?;
			check::run(&config, leaf || json, out)?;
			return Ok(ExitCode::SUCCESS);
		}
		ProviderCli::Show { json: leaf } => {
			show::run(
				&Config::load(path)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?,
				leaf || json,
				out,
			)?;
			return Ok(ExitCode::SUCCESS);
		}
		ProviderCli::Test => {
			let config = Config::load(path)
				.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
			if json {
				let mut printed = Vec::new();
				let code = probe::run(&config, &mut printed, status)?;
				super::json_out::passed(out, "provider test", &printed)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
				return Ok(code);
			}
			return probe::run(&config, out, status);
		}
		ProviderCli::Set { provider, args } => {
			// The credential the configuration names has to reach the
			// container, so this command writes the generated compose file
			// too, and previews that change in a dry run.
			return write::run(
				path,
				(&provider, &args),
				dry_run,
				json,
				out,
				status,
				restart,
			);
		}
		// One zone's entry leaves with its credential: the generated compose
		// file stops mounting its token, so this writes both files.
		ProviderCli::Unset { zone: Some(zone) } => {
			return unset::run(path, &zone, dry_run, json, out, status, restart);
		}
		ProviderCli::Unset { zone: None } => {
			let change: resource::Change = Box::new(|document, _| {
				document
					.remove_table(&["dns"])
					.map(|_| ())
					.map_err(resource::ResourceError::Failure)
			});
			(change, "provider unset", serde_json::json!({}))
		}
	};
	let edit = resource::Edit {
		label: "dns provider",
		action: verb,
		fields,
		json,
	};
	resource::apply_edit(path, dry_run, edit, out, status, restart, change)
}
