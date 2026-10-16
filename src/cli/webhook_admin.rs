//! Webhook administration: the `[webhook]` section.

use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;
use serde_json::{Value, json};
use toml_edit::Value as TomlValue;

use super::resource;
use super::stack::StackAction;
use crate::config::Config;

#[path = "webhook_admin_endpoint.rs"]
mod endpoint;
#[path = "webhook_admin_probe.rs"]
mod probe;

#[cfg(test)]
#[path = "webhook_admin_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "webhook_admin_tests_edit.rs"]
mod tests_edit;

/// Webhook administration actions.
#[derive(Debug, Subcommand)]
pub enum WebhookCli {
	/// Show the webhook endpoint. The signing secret is never printed.
	Show {
		/// Print the settings as JSON.
		#[arg(long)]
		json: bool,
	},
	/// Send events to this URL (https, or http on a loopback address).
	Set {
		/// Endpoint that receives the event payloads.
		url: String,
		/// Read the HMAC-SHA256 signing secret from stdin (one line). Without
		/// it a secret that is already configured is kept.
		#[arg(long)]
		secret_stdin: bool,
	},
	/// Stop sending webhook events.
	Unset,
	/// Post one `test` event and report the endpoint's answer.
	Test,
}

fn show(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
	let Some(webhook) = &config.webhook else {
		if json {
			return resource::json(out, &Value::Null);
		}
		return writeln!(out, "url\tunset").map_err(|error| error.to_string());
	};
	let secret = if webhook.secret.is_some() {
		"set"
	} else {
		"unset"
	};
	if json {
		return resource::json(out, &json!({ "url": webhook.url, "secret": secret }));
	}
	writeln!(out, "url\t{}\nsecret\t{secret}", webhook.url).map_err(|error| error.to_string())
}

pub(super) fn run(path: &Path, action: WebhookCli, dry_run: bool, json: bool) -> ExitCode {
	resource::exit_resource(execute_with(
		path,
		action,
		dry_run,
		json,
		&mut std::io::stdin().lock(),
		&mut std::io::stdout().lock(),
		&mut super::style::stderr(),
		super::stack::run,
	))
}

#[allow(clippy::too_many_arguments)]
fn execute_with(
	path: &Path,
	action: WebhookCli,
	dry_run: bool,
	json: bool,
	input: &mut dyn BufRead,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, resource::ResourceError> {
	let (change, verb, fields): (resource::Change, _, _) = match action {
		WebhookCli::Show { json: leaf } => {
			show(
				&Config::load(path)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?,
				leaf || json,
				out,
			)?;
			return Ok(ExitCode::SUCCESS);
		}
		WebhookCli::Test => {
			let config = Config::load(path)
				.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
			if json {
				let mut printed = Vec::new();
				let code = probe::run(&config, &mut printed, status)?;
				super::json_out::passed(out, "test", &printed)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
				return Ok(code);
			}
			return probe::run(&config, out, status);
		}
		WebhookCli::Set { url, secret_stdin } => {
			endpoint::check(&url)?;
			let secret = if secret_stdin {
				Some(resource::read_secret(input, "webhook secret")?)
			} else {
				None
			};
			let shown =
				json!({ "url": url, "secret": if secret.is_some() { "set" } else { "unchanged" } });
			let change: resource::Change = Box::new(move |document, _| {
				let mut fields = vec![("url", Some(TomlValue::from(url)))];
				if let Some(secret) = secret {
					fields.push(("secret", Some(TomlValue::from(secret))));
				}
				document
					.set_table_fields(&["webhook"], &fields)
					.map_err(resource::ResourceError::Failure)
			});
			(change, "set", shown)
		}
		WebhookCli::Unset => (
			Box::new(|document, config| {
				if let Some(alert) = config.alerts.iter().find(|alert| alert.webhook) {
					return Err(format!(
						"alert \"{}\" posts to the webhook; remove it or turn its webhook off first",
						alert.name
					)
					.into());
				}
				document
					.remove_table(&["webhook"])
					.map(|_| ())
					.map_err(resource::ResourceError::Failure)
			}),
			"unset",
			json!({}),
		),
	};
	let edit = resource::Edit {
		label: "webhook",
		action: verb,
		fields,
		json,
	};
	resource::apply_edit(path, dry_run, edit, out, status, restart, change)
}
