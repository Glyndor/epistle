//! Alert rule administration: the `[[alerts]]` entries.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;
use serde::Serialize;
use toml_edit::{Array, Value};

use super::limits::values::{Unit, parse_value};
use super::resource;
use super::stack::StackAction;
use crate::config::{Alert, AlertOp, Config};

#[cfg(test)]
#[path = "alert_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "alert_tests_add.rs"]
mod tests_add;

/// Longest window or cooldown accepted: one year.
const MAX_SECONDS: u64 = 365 * 86_400;

/// Alert rule actions.
#[derive(Debug, Subcommand)]
pub enum AlertCli {
	/// List the configured alert rules.
	List {
		/// Print the rules as JSON.
		#[arg(long)]
		json: bool,
	},
	/// Add an alert rule on a counter's change over a window.
	///
	/// Add an alert rule that fires when a counter's change over a window
	/// crosses a threshold.
	Add {
		/// Unique rule name, used in the webhook payload, the email subject and the logs.
		name: String,
		/// Counter to watch, for example bounced.
		#[arg(long)]
		metric: String,
		/// Comparison applied to the change over the window.
		#[arg(long, value_parser = [">=", ">", "<=", "<", "=="], allow_hyphen_values = true)]
		op: String,
		/// Right-hand side of the comparison.
		#[arg(long)]
		threshold: u64,
		/// Sampling window (for example 5m, 1h).
		#[arg(long)]
		window: String,
		/// Post a metric_alert webhook event when the rule fires.
		#[arg(long)]
		webhook: bool,
		/// Email this address when the rule fires (repeatable).
		#[arg(long, value_name = "ADDRESS")]
		email: Vec<String>,
		/// Minimum time between two fires of the rule.
		#[arg(long, default_value = "1h")]
		cooldown: String,
	},
	/// Remove an alert rule.
	Remove {
		/// Name of the rule to remove.
		name: String,
	},
}

#[derive(Serialize)]
struct Row<'a> {
	name: &'a str,
	metric: &'a str,
	op: &'static str,
	threshold: u64,
	window_secs: u64,
	cooldown_secs: u64,
	webhook: bool,
	email: &'a [String],
}

fn symbol(op: AlertOp) -> &'static str {
	match op {
		AlertOp::Ge => ">=",
		AlertOp::Gt => ">",
		AlertOp::Le => "<=",
		AlertOp::Lt => "<",
		AlertOp::Eq => "==",
	}
}

fn row(alert: &Alert) -> Row<'_> {
	Row {
		name: &alert.name,
		metric: &alert.metric,
		op: symbol(alert.op),
		threshold: alert.threshold,
		window_secs: alert.window_secs,
		cooldown_secs: alert.cooldown_secs,
		webhook: alert.webhook,
		email: &alert.email,
	}
}

fn list(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
	let rows: Vec<Row> = config.alerts.iter().map(row).collect();
	if json {
		return resource::json(out, &rows);
	}
	for row in rows {
		writeln!(
			out,
			"{}\t{} {} {}\twindow={}s\tcooldown={}s\twebhook={}\temail={}",
			row.name,
			row.metric,
			row.op,
			row.threshold,
			row.window_secs,
			row.cooldown_secs,
			if row.webhook { "yes" } else { "no" },
			if row.email.is_empty() {
				"-".to_string()
			} else {
				row.email.join(",")
			},
		)
		.map_err(|error| error.to_string())?;
	}
	Ok(())
}

/// A validated new rule.
struct NewAlert {
	name: String,
	metric: String,
	op: String,
	threshold: u64,
	window_secs: u64,
	cooldown_secs: u64,
	webhook: bool,
	email: Vec<String>,
}

fn duration(flag: &str, input: &str) -> Result<u64, String> {
	match parse_value(input, Unit::Duration, MAX_SECONDS) {
		Ok(0) => Err(format!("{flag} must be greater than zero")),
		Ok(seconds) => Ok(seconds),
		Err(_) => Err(format!(
			"{flag} \"{input}\" must be a duration such as 90s, 5m, 1h or 2d (at most one year)"
		)),
	}
}

#[allow(clippy::too_many_arguments)]
fn validate(
	name: String,
	metric: String,
	op: String,
	threshold: u64,
	window: &str,
	cooldown: &str,
	webhook: bool,
	email: Vec<String>,
) -> Result<NewAlert, String> {
	if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
		return Err("the rule name must be 1 to 128 characters without control characters".into());
	}
	let known = crate::metrics::metric_names();
	if !known.contains(&metric.as_str()) {
		return Err(format!(
			"--metric \"{metric}\" is not a known counter; valid names: {}",
			known.join(", ")
		));
	}
	if !webhook && email.is_empty() {
		return Err("the rule needs somewhere to go: pass --webhook, --email, or both".into());
	}
	Ok(NewAlert {
		name,
		metric,
		op,
		threshold,
		window_secs: duration("--window", window)?,
		cooldown_secs: duration("--cooldown", cooldown)?,
		webhook,
		email,
	})
}

fn add(
	document: &mut super::config_edit::ConfigDocument,
	config: &Config,
	new: NewAlert,
) -> Result<(), String> {
	if config.alerts.iter().any(|alert| alert.name == new.name) {
		return Err(format!(
			"alert \"{}\" already exists; remove it first to change it",
			new.name
		));
	}
	if new.webhook && config.webhook.is_none() {
		return Err("--webhook needs a webhook endpoint: run `epistle webhook set` first".into());
	}
	let mut fields = vec![
		("name", Value::from(new.name.as_str())),
		("metric", Value::from(new.metric)),
		("op", Value::from(new.op)),
		(
			"threshold",
			Value::from(i64::try_from(new.threshold).map_err(|_| "--threshold is too large")?),
		),
		(
			"window_secs",
			Value::from(i64::try_from(new.window_secs).map_err(|_| "--window is too large")?),
		),
	];
	if new.webhook {
		fields.push(("webhook", Value::from(true)));
	}
	if !new.email.is_empty() {
		fields.push(("email", Value::Array(Array::from_iter(new.email))));
	}
	fields.push((
		"cooldown_secs",
		Value::from(i64::try_from(new.cooldown_secs).map_err(|_| "--cooldown is too large")?),
	));
	document.upsert_element("alerts", "name", &new.name, &fields)
}

pub(super) fn run(path: &Path, action: AlertCli, dry_run: bool) -> ExitCode {
	resource::exit(execute_with(
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
	action: AlertCli,
	dry_run: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, String> {
	let change: resource::Change = match action {
		AlertCli::List { json } => {
			list(&Config::load(path).map_err(|e| e.to_string())?, json, out)?;
			return Ok(ExitCode::SUCCESS);
		}
		AlertCli::Add {
			name,
			metric,
			op,
			threshold,
			window,
			webhook,
			email,
			cooldown,
		} => {
			let new = validate(
				name, metric, op, threshold, &window, &cooldown, webhook, email,
			)?;
			Box::new(move |document, config| add(document, config, new))
		}
		AlertCli::Remove { name } => Box::new(move |document, config| {
			if !config.alerts.iter().any(|alert| alert.name == name) {
				return Err(format!("no alert named \"{name}\""));
			}
			document.remove_elements("alerts", "name", &name)
		}),
	};
	resource::apply_edit(path, dry_run, "alert", out, status, restart, change)
}
