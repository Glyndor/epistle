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

pub(super) fn run(path: &Path, action: WebhookCli, dry_run: bool) -> ExitCode {
	resource::exit_resource(execute_with(
		path,
		action,
		dry_run,
		&mut std::io::stdin().lock(),
		&mut std::io::stdout().lock(),
		&mut super::style::stderr(),
		super::stack::run,
	))
}

fn execute_with(
	path: &Path,
	action: WebhookCli,
	dry_run: bool,
	input: &mut dyn BufRead,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, resource::ResourceError> {
	let change: resource::Change = match action {
		WebhookCli::Show { json } => {
			show(
				&Config::load(path)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?,
				json,
				out,
			)?;
			return Ok(ExitCode::SUCCESS);
		}
		WebhookCli::Test => {
			let config = Config::load(path)
				.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
			return probe::run(&config, out, status);
		}
		WebhookCli::Set { url, secret_stdin } => {
			endpoint::check(&url)?;
			let secret = if secret_stdin {
				Some(resource::read_secret(input, "webhook secret")?)
			} else {
				None
			};
			Box::new(move |document, _| {
				let mut fields = vec![("url", Some(TomlValue::from(url)))];
				if let Some(secret) = secret {
					fields.push(("secret", Some(TomlValue::from(secret))));
				}
				document
					.set_table_fields(&["webhook"], &fields)
					.map_err(resource::ResourceError::Failure)
			})
		}
		WebhookCli::Unset => Box::new(|document, config| {
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
	};
	resource::apply_edit(path, dry_run, "webhook", out, status, restart, change)
}
