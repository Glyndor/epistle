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
	/// Show one alert rule.
	Show {
		/// Name of the rule to show.
		name: String,
		/// Print the rule as JSON.
		#[arg(long)]
		json: bool,
	},
	/// Switch a rule on again. It starts sampling when the server restarts.
	Enable {
		/// Name of the rule to switch on.
		name: String,
	},
	/// Switch a rule off without removing it.
	///
	/// A rule that is off takes no samples and never fires. It stays in the
	/// configuration, so `enable` brings it back unchanged.
	Disable {
		/// Name of the rule to switch off.
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
	enabled: bool,
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
		enabled: alert.enabled,
	}
}

fn show(
	config: &Config,
	name: &str,
	json: bool,
	out: &mut impl Write,
) -> Result<(), resource::ResourceError> {
	let alert = config
		.alerts
		.iter()
		.find(|alert| alert.name == name)
		.ok_or_else(|| resource::ResourceError::refused(format!("no alert named \"{name}\"")))?;
	let row = row(alert);
	if json {
		return resource::json(out, &row).map_err(resource::ResourceError::Failure);
	}
	let yes_no = |value: bool| if value { "yes" } else { "no" };
	let email = if row.email.is_empty() {
		"-".to_string()
	} else {
		row.email.join(",")
	};
	write!(
		out,
		"name\t{}\nmetric\t{}\nop\t{}\nthreshold\t{}\nwindow_secs\t{}\n\
		 cooldown_secs\t{}\nwebhook\t{}\nemail\t{email}\nenabled\t{}\n",
		row.name,
		row.metric,
		row.op,
		row.threshold,
		row.window_secs,
		row.cooldown_secs,
		yes_no(row.webhook),
		yes_no(row.enabled),
	)
	.map_err(|error| resource::ResourceError::Failure(error.to_string()))
}

fn list(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
	let rows: Vec<Row> = config.alerts.iter().map(row).collect();
	if json {
		return resource::json(out, &rows);
	}
	for row in rows {
		writeln!(
			out,
			"{}\t{} {} {}\twindow={}s\tcooldown={}s\twebhook={}\temail={}{}",
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
			if row.enabled { "" } else { "\tdisabled" },
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

/// The edit behind `alert enable|disable`: a rule that is on carries no
/// `enabled` key, a rule that is off carries `enabled = false`.
fn switch(name: &str, enabled: bool) -> resource::Change {
	let name = name.to_string();
	Box::new(move |document, config| {
		if !config.alerts.iter().any(|alert| alert.name == name) {
			return Err(resource::ResourceError::refused(format!(
				"no alert named \"{name}\""
			)));
		}
		let value = (!enabled).then(|| Value::from(false));
		document
			.edit_array_entry_field(&["alerts"], &name, "name", "enabled", value)
			.map(|_| ())
			.map_err(resource::ResourceError::Failure)
	})
}

pub(super) fn run(path: &Path, action: AlertCli, dry_run: bool, json: bool) -> ExitCode {
	resource::exit_resource(execute_with(
		path,
		action,
		dry_run,
		json,
		&mut std::io::stdout().lock(),
		&mut super::style::stderr(),
		super::stack::run,
	))
}

fn execute_with(
	path: &Path,
	action: AlertCli,
	dry_run: bool,
	json: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, resource::ResourceError> {
	let (change, verb, name): (resource::Change, _, _) = match action {
		AlertCli::List { json: leaf } => {
			list(
				&Config::load(path)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?,
				leaf || json,
				out,
			)?;
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
			let name = new.name.clone();
			let change: resource::Change = Box::new(move |document, config| {
				add(document, config, new).map_err(resource::ResourceError::Failure)
			});
			(change, "add", name)
		}
		AlertCli::Show { name, json: leaf } => {
			let config = Config::load(path)
				.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
			show(&config, &name, leaf || json, out)?;
			return Ok(ExitCode::SUCCESS);
		}
		AlertCli::Enable { name } => (switch(&name, true), "enable", name),
		AlertCli::Disable { name } => (switch(&name, false), "disable", name),
		AlertCli::Remove { name } => (
			Box::new({
				let name = name.clone();
				move |document, config| {
					if !config.alerts.iter().any(|alert| alert.name == name) {
						return Err(resource::ResourceError::refused(format!(
							"no alert named \"{name}\""
						)));
					}
					document
						.remove_elements("alerts", "name", &name)
						.map_err(resource::ResourceError::Failure)
				}
			}),
			"remove",
			name,
		),
	};
	let mut fields = serde_json::json!({ "alert": name });
	if matches!(verb, "enable" | "disable") {
		fields["enabled"] = (verb == "enable").into();
	}
	let edit = resource::Edit {
		label: "alert",
		action: verb,
		fields,
		json,
	};
	resource::apply_edit(path, dry_run, edit, out, status, restart, change)
}

#[cfg(test)]
mod tests;
