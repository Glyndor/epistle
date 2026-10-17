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
	/// Switch the webhook on again.
	Enable,
	/// Switch the webhook off without removing it.
	///
	/// The `[webhook]` section stays, with its URL and secret, but no event
	/// is posted, alerts included. `enable` brings it back. While an alert
	/// posts to the webhook this asks first, and off a terminal it needs
	/// `--yes`.
	Disable {
		/// Go ahead although alerts post to the webhook. A non-interactive
		/// run without `--yes` is refused with exit code 2.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// Post one `test` event and report the endpoint's answer.
	Test,
}

/// The events a webhook carries, by the name they have in the payload.
const EVENTS: &str = "message_received, delivery_failed, metric_alert, dkim_rotation_failed, \
	outbound_virus and the warm-up reports";

/// The alerts that post to the webhook, as `alert "name"`.
fn alert_users(config: &Config) -> Vec<String> {
	config
		.alerts
		.iter()
		.filter(|alert| alert.webhook)
		.map(|alert| format!("alert \"{}\"", alert.name))
		.collect()
}

/// What stops when the webhook is switched off.
fn stops(users: &[String]) -> String {
	let alerts = if users.is_empty() {
		String::new()
	} else {
		format!("; {} posts to it and will go quiet", users.join(", "))
	};
	format!("no event will be posted while the webhook is off: {EVENTS}{alerts}")
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
		let shown = json!({ "url": webhook.url, "secret": secret, "enabled": webhook.enabled });
		return resource::json(out, &shown);
	}
	writeln!(
		out,
		"url\t{}\nsecret\t{secret}\nenabled\t{}",
		webhook.url,
		if webhook.enabled { "yes" } else { "no" }
	)
	.map_err(|error| error.to_string())
}

/// Before `webhook disable` edits anything: say which alarms go quiet, and
/// while an alert posts to the webhook ask first (off a terminal, `--yes`).
/// Runs before the status stream is opened, because the question uses it.
fn confirm_disable(path: &Path, yes: bool, dry_run: bool) -> Result<(), ExitCode> {
	let Ok(config) = Config::load(path) else {
		return Ok(());
	};
	if config.webhook.is_none() {
		return Ok(());
	}
	let users = alert_users(&config);
	super::style::warn(stops(&users));
	if users.is_empty() || dry_run {
		return Ok(());
	}
	let question = format!(
		"Switch the webhook off? {} no longer post{}. [y/N]",
		users.join(", "),
		if users.len() == 1 { "s" } else { "" }
	);
	super::prompt::confirm_destructive("webhook disable", &question, yes)
}

/// The refusals that are about the configuration and not about the command
/// line (exit code 3): no webhook to switch, a webhook an alert depends on.
fn policy_refusal(path: &Path, action: &WebhookCli) -> Option<ExitCode> {
	let config = Config::load(path).ok()?;
	match action {
		WebhookCli::Enable | WebhookCli::Disable { .. } if config.webhook.is_none() => {
			Some(super::exit::policy(NO_WEBHOOK))
		}
		WebhookCli::Unset => {
			let alert = config.alerts.iter().find(|alert| alert.webhook)?;
			Some(super::exit::policy(unset_message(&alert.name)))
		}
		_ => None,
	}
}

const NO_WEBHOOK: &str = "no webhook is configured; run `epistle webhook set` first";

fn unset_message(alert: &str) -> String {
	format!("alert \"{alert}\" posts to the webhook; remove it or turn its webhook off first")
}

pub(super) fn run(path: &Path, action: WebhookCli, dry_run: bool, json: bool) -> ExitCode {
	if let Some(code) = policy_refusal(path, &action) {
		return code;
	}
	if let WebhookCli::Disable { yes } = action
		&& let Err(code) = confirm_disable(path, yes, dry_run)
	{
		return code;
	}
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
		WebhookCli::Enable | WebhookCli::Disable { .. } => {
			let enabled = matches!(action, WebhookCli::Enable);
			let change: resource::Change = Box::new(move |document, config| {
				if config.webhook.is_none() {
					return Err(resource::ResourceError::refused(NO_WEBHOOK));
				}
				let value = (!enabled).then(|| TomlValue::from(false));
				document
					.set_table_fields(&["webhook"], &[("enabled", value)])
					.map_err(resource::ResourceError::Failure)
			});
			let verb = if enabled { "enable" } else { "disable" };
			(change, verb, json!({ "enabled": enabled }))
		}
		WebhookCli::Unset => (
			Box::new(|document, config| {
				if let Some(alert) = config.alerts.iter().find(|alert| alert.webhook) {
					return Err(unset_message(&alert.name).into());
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
