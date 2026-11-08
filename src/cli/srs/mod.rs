//! `epistle srs`: the Sender Rewriting Scheme secret of each hosted domain.
//!
//! One `srs_secret` for the whole server lets an address made for one
//! domain pass for the others. `split` writes a secret of its own for every
//! hosted domain that has none and leaves `srs_secret` where it is, so the
//! addresses already out still come back; `rotate` replaces one domain's
//! secret and keeps the old one to verify with.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;
use serde_json::json;
use toml_edit::Value as TomlValue;

use crate::cli::resource;
use crate::cli::stack::StackAction;
use crate::config::Config;

#[cfg(test)]
mod tests;

/// SRS secret administration actions.
#[derive(Debug, Subcommand)]
pub enum SrsCli {
	/// Show which domains have a secret of their own.
	///
	/// Each hosted domain is listed as `own`, `shared` (it signs with the
	/// server-wide `srs_secret`) or `none`. No secret is printed.
	Show {
		/// Print the result as JSON.
		#[arg(long)]
		json: bool,
	},
	/// Give every hosted domain without one a secret of its own.
	///
	/// `srs_secret` stays and keeps verifying the addresses made before the
	/// split; remove it once 14 days have passed and every domain has its
	/// own.
	Split,
	/// Replace a domain's secret with a new one.
	///
	/// The old one stays as `previous_secret` and keeps verifying the
	/// addresses made with it; remove it after 14 days.
	Rotate {
		/// The hosted domain, which must already have its own secret.
		domain: String,
	},
}

/// One domain's SRS secret, for `show`.
fn source(config: &Config, domain: &str) -> &'static str {
	match (config.srs_domain(domain), &config.srs_secret) {
		(Some(_), _) => "own",
		(None, Some(_)) => "shared",
		(None, None) => "none",
	}
}

fn show(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
	let rows: Vec<(String, &'static str)> = config
		.domains
		.iter()
		.map(|domain| (domain.clone(), source(config, domain)))
		.collect();
	if json {
		let domains: Vec<_> = rows
			.iter()
			.map(|(domain, secret)| json!({ "domain": domain, "secret": secret }))
			.collect();
		let shown = json!({
			"server_wide_secret": config.srs_secret.is_some(),
			"domains": domains,
		});
		return resource::json(out, &shown);
	}
	let failure = |error: std::io::Error| error.to_string();
	writeln!(
		out,
		"server-wide\t{}",
		if config.srs_secret.is_some() {
			"set"
		} else {
			"unset"
		}
	)
	.map_err(failure)?;
	for (domain, secret) in rows {
		writeln!(out, "{domain}\t{secret}").map_err(failure)?;
	}
	Ok(())
}

/// A fresh secret, or the failure the caller reports.
fn fresh() -> Result<String, resource::ResourceError> {
	crate::queue::srs::generate_secret().ok_or_else(|| {
		resource::ResourceError::Failure("the system gave no random bytes for a secret".into())
	})
}

/// Write `secret` as the secret of `domain`, keeping `previous` if given.
pub(in crate::cli) fn set_domain_secret(
	document: &mut crate::cli::config_edit::ConfigDocument,
	domain: &str,
	secret: String,
	previous: Option<TomlValue>,
) -> Result<(), String> {
	let mut fields = vec![("secret", TomlValue::from(secret))];
	if let Some(previous) = previous {
		fields.push(("previous_secret", previous));
	}
	document.upsert_element("srs_domain", "name", &domain.to_ascii_lowercase(), &fields)
}

pub(in crate::cli) fn run(path: &Path, action: SrsCli, dry_run: bool, json: bool) -> ExitCode {
	resource::exit_resource(execute_with(
		path,
		action,
		dry_run,
		json,
		&mut std::io::stdout().lock(),
		&mut crate::cli::style::stderr(),
		crate::cli::stack::run,
	))
}

fn execute_with(
	path: &Path,
	action: SrsCli,
	dry_run: bool,
	json: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, resource::ResourceError> {
	let (change, verb, fields): (resource::Change, _, _) = match action {
		SrsCli::Show { json: leaf } => {
			let config = Config::load(path)
				.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
			show(&config, leaf || json, out)?;
			return Ok(ExitCode::SUCCESS);
		}
		SrsCli::Split => (
			Box::new(|document, config| {
				for domain in config
					.domains
					.iter()
					.filter(|d| config.srs_domain(d).is_none())
				{
					set_domain_secret(document, domain, fresh()?, None)
						.map_err(resource::ResourceError::Failure)?;
				}
				Ok(())
			}),
			"split",
			json!({}),
		),
		SrsCli::Rotate { domain } => {
			let domain =
				resource::dns_name("domain", &domain).map_err(resource::ResourceError::refused)?;
			let shown = json!({ "domain": domain });
			let change: resource::Change = Box::new(move |document, config| {
				if config.srs_domain(&domain).is_none() {
					return Err(resource::ResourceError::refused(format!(
						"domain {domain} has no secret of its own; run `epistle srs split` first"
					)));
				}
				// The old secret moves as the file writes it: a `${VAR}` stays a
				// reference, and the secret it names is never written out.
				let old = document
					.element_field("srs_domain", "name", &domain, "secret")
					.ok_or_else(|| {
						resource::ResourceError::Failure(format!(
							"cannot read the secret of domain {domain} from the file"
						))
					})?;
				set_domain_secret(document, &domain, fresh()?, Some(old))
					.map_err(resource::ResourceError::Failure)
			});
			(change, "rotate", shown)
		}
	};
	let edit = resource::Edit {
		label: "srs",
		action: verb,
		fields,
		json,
	};
	resource::apply_edit(path, dry_run, edit, out, status, restart, change)
}
