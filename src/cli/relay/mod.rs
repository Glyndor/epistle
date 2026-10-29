//! Outbound smarthost administration: the `[[transport]]` relay rules.

use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use serde::Serialize;

use super::resource;
use super::stack::StackAction;
use crate::config::{Config, Transport, TransportKind};

mod edit;
mod probe;

#[cfg(test)]
mod tests;

/// Which relay rule a command addresses. With neither flag it is the default
/// route, the rule that carries mail no account or domain rule claims.
#[derive(Debug, Clone, Default, Args)]
pub struct Target {
	/// Route mail sent by this local account.
	#[arg(long, conflicts_with = "domain")]
	pub account: Option<String>,
	/// Route mail to this recipient domain.
	#[arg(long)]
	pub domain: Option<String>,
}

fn same(left: Option<&str>, right: Option<&str>) -> bool {
	left.map(str::to_ascii_lowercase) == right.map(str::to_ascii_lowercase)
}

impl Target {
	fn matches(&self, rule: &Transport) -> bool {
		same(rule.account.as_deref(), self.account.as_deref())
			&& same(rule.domain.as_deref(), self.domain.as_deref())
	}

	fn matches_table(&self, table: &dyn toml_edit::TableLike) -> bool {
		let get = |key: &str| table.get(key).and_then(|item| item.as_str());
		same(get("account"), self.account.as_deref()) && same(get("domain"), self.domain.as_deref())
	}

	fn describe(&self) -> String {
		match (&self.account, &self.domain) {
			(Some(account), _) => format!("account {account}"),
			(_, Some(domain)) => format!("domain {domain}"),
			_ => "the default route".into(),
		}
	}
}

/// Smarthost administration actions.
#[derive(Debug, Subcommand)]
pub enum RelayCli {
	/// List the configured relay rules.
	List {
		/// Print the rules as JSON.
		#[arg(long)]
		json: bool,
	},
	/// Show one relay rule. Passwords are never printed.
	Show {
		/// Print the rule as JSON.
		#[arg(long)]
		json: bool,
		/// The rule to show.
		#[command(flatten)]
		target: Target,
	},
	/// Add or update a relay rule.
	Add {
		/// The rule to write.
		#[command(flatten)]
		target: Target,
		/// Smarthost name or address.
		#[arg(long)]
		host: String,
		/// Smarthost port (587 with --starttls, otherwise 25).
		#[arg(long)]
		port: Option<u16>,
		/// Upgrade to TLS with STARTTLS before AUTH and mail.
		#[arg(long)]
		starttls: bool,
		/// SMTP AUTH user name. Requires --starttls and --password-stdin.
		#[arg(long)]
		username: Option<String>,
		/// Read the SMTP AUTH password from stdin (one line).
		#[arg(long)]
		password_stdin: bool,
		/// Reach the smarthost through this SOCKS5 proxy (host:port).
		#[arg(long, value_name = "HOST:PORT")]
		socks_proxy: Option<String>,
	},
	/// Remove a relay rule. Without a selector this removes the default route.
	Remove {
		/// The rule to remove.
		#[command(flatten)]
		target: Target,
	},
	/// Switch a relay rule on again.
	Enable {
		/// The rule to switch on.
		#[command(flatten)]
		target: Target,
	},
	/// Switch a relay rule off without removing it.
	///
	/// Mail the rule would carry goes by the next rule that matches, or
	/// direct to the recipient's MX when none does. `enable` brings it back.
	Disable {
		/// The rule to switch off.
		#[command(flatten)]
		target: Target,
		/// Skip the interactive confirmation. A non-interactive run
		/// without `--yes` is refused with exit code 2.
		#[arg(long, short = 'y')]
		yes: bool,
	},
	/// Connect, EHLO, STARTTLS and AUTH as configured, then QUIT. Sends no mail.
	Test {
		/// The rule to test.
		#[command(flatten)]
		target: Target,
	},
}

#[derive(Serialize)]
struct Row {
	target: String,
	account: Option<String>,
	domain: Option<String>,
	host: String,
	port: u16,
	starttls: bool,
	username: Option<String>,
	password: &'static str,
	socks_proxy: Option<String>,
	enabled: bool,
}

fn row(rule: &Transport) -> Row {
	let target = match (&rule.account, &rule.domain) {
		(Some(account), _) => format!("account:{account}"),
		(_, Some(domain)) => format!("domain:{domain}"),
		_ => "default".into(),
	};
	Row {
		target,
		account: rule.account.clone(),
		domain: rule.domain.clone(),
		host: rule.host.clone().unwrap_or_default(),
		port: rule.port.unwrap_or(0),
		starttls: rule.starttls,
		username: rule.username.clone(),
		password: if rule.password.is_some() {
			"set"
		} else {
			"unset"
		},
		socks_proxy: rule.socks_proxy.clone(),
		enabled: rule.enabled,
	}
}

fn relay_rules(config: &Config) -> impl Iterator<Item = &Transport> {
	config
		.transport
		.iter()
		.filter(|rule| rule.kind == TransportKind::Relay)
}

fn list(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
	let rows: Vec<Row> = relay_rules(config).map(row).collect();
	if json {
		return resource::json(out, &rows);
	}
	for row in rows {
		writeln!(
			out,
			"{}\t{}:{}\tstarttls={}\tauth={}{}",
			row.target,
			row.host,
			row.port,
			if row.starttls { "yes" } else { "no" },
			if row.username.is_some() { "yes" } else { "no" },
			if row.enabled { "" } else { "\tdisabled" },
		)
		.map_err(|error| error.to_string())?;
	}
	Ok(())
}

pub(super) fn find<'a>(config: &'a Config, target: &Target) -> Result<&'a Transport, String> {
	relay_rules(config)
		.find(|rule| target.matches(rule))
		.ok_or_else(|| format!("no relay is configured for {}", target.describe()))
}

fn show(
	config: &Config,
	target: &Target,
	json: bool,
	out: &mut impl Write,
) -> Result<(), resource::ResourceError> {
	let row = row(find(config, target).map_err(resource::ResourceError::refused)?);
	if json {
		return resource::json(out, &row).map_err(Into::into);
	}
	let none = "-".to_string();
	for (key, value) in [
		("target", row.target.clone()),
		("host", row.host.clone()),
		("port", row.port.to_string()),
		("starttls", row.starttls.to_string()),
		(
			"username",
			row.username.clone().unwrap_or_else(|| none.clone()),
		),
		("password", row.password.to_string()),
		("socks_proxy", row.socks_proxy.clone().unwrap_or(none)),
		(
			"enabled",
			if row.enabled { "yes" } else { "no" }.to_string(),
		),
	] {
		writeln!(out, "{key}\t{value}")
			.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
	}
	Ok(())
}

/// Before `relay disable` edits anything: say where the mail will go
/// instead and ask. Runs before the status stream is opened, because the
/// question uses it.
fn confirm_disable(path: &Path, target: &Target, yes: bool, dry_run: bool) -> Result<(), ExitCode> {
	let Ok(config) = Config::load(path) else {
		return Ok(());
	};
	let Ok(rule) = find(&config, target) else {
		return Ok(());
	};
	if !rule.enabled {
		return Ok(());
	}
	let place = target.describe();
	let host = rule.host.as_deref().unwrap_or("-");
	super::style::warn(format_args!(
		"the relay for {place} (smarthost {host}) will be off: its mail goes by the next \
		 rule that matches, or directly to the recipient's MX from this server's own address"
	));
	if dry_run {
		return Ok(());
	}
	let question = format!("Switch off the relay for {place}? [y/N]");
	super::prompt::confirm_destructive("relay disable", &question, yes)
}

pub(super) fn run(path: &Path, action: RelayCli, dry_run: bool, json: bool) -> ExitCode {
	if let RelayCli::Disable { target, yes } = &action
		&& let Err(code) = confirm_disable(path, target, *yes, dry_run)
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

/// The edit behind `relay enable|disable`: a rule that is on carries no
/// `enabled` key, a rule that is off carries `enabled = false`.
fn switch(target: Target, enabled: bool) -> (resource::Change, &'static str, serde_json::Value) {
	let fields = serde_json::json!({
		"account": target.account, "domain": target.domain, "enabled": enabled,
	});
	let change: resource::Change =
		Box::new(move |document, config| edit::switch(document, config, &target, enabled));
	(change, if enabled { "enable" } else { "disable" }, fields)
}

#[allow(clippy::too_many_arguments)]
fn execute_with(
	path: &Path,
	action: RelayCli,
	dry_run: bool,
	json: bool,
	input: &mut dyn BufRead,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, resource::ResourceError> {
	let (change, verb, fields): (resource::Change, _, _) = match action {
		RelayCli::List { json: leaf } => {
			list(
				&Config::load(path)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?,
				leaf || json,
				out,
			)?;
			return Ok(ExitCode::SUCCESS);
		}
		RelayCli::Show { json: leaf, target } => {
			show(
				&Config::load(path)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?,
				&target,
				leaf || json,
				out,
			)?;
			return Ok(ExitCode::SUCCESS);
		}
		RelayCli::Test { target } => {
			let config = Config::load(path)
				.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
			if json {
				let mut printed = Vec::new();
				let code = probe::run(&config, &target, &mut printed, status)?;
				super::json_out::passed(out, "test", &printed)
					.map_err(|error| resource::ResourceError::Failure(error.to_string()))?;
				return Ok(code);
			}
			return probe::run(&config, &target, out, status);
		}
		RelayCli::Add {
			target,
			host,
			port,
			starttls,
			username,
			password_stdin,
			socks_proxy,
		} => {
			let password = if password_stdin {
				Some(resource::read_secret(input, "relay password")?)
			} else {
				None
			};
			let fields = serde_json::json!({
				"account": target.account, "domain": target.domain, "host": host,
			});
			let request = edit::Request {
				target,
				host,
				port,
				starttls,
				username,
				password,
				socks_proxy,
				password_stdin,
			};
			let change: resource::Change = Box::new(move |document, config| {
				edit::add(document, config, request).map_err(resource::ResourceError::Failure)
			});
			(change, "add", fields)
		}
		RelayCli::Enable { target } => switch(target, true),
		RelayCli::Disable { target, .. } => switch(target, false),
		RelayCli::Remove { target } => {
			let fields = serde_json::json!({ "account": target.account, "domain": target.domain });
			let change: resource::Change =
				Box::new(move |document, config| edit::remove(document, config, &target));
			(change, "remove", fields)
		}
	};
	let edit = resource::Edit {
		label: "relay",
		action: verb,
		fields,
		json,
	};
	resource::apply_edit(path, dry_run, edit, out, status, restart, change)
}
