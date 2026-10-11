//! Outbound smarthost administration: the `[[transport]]` relay rules.

use std::io::{BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use serde::Serialize;

use super::resource;
use super::stack::StackAction;
use crate::config::{Config, Transport, TransportKind};

#[path = "relay_edit.rs"]
mod edit;
#[path = "relay_probe.rs"]
mod probe;

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "relay_tests_edit.rs"]
mod tests_edit;
#[cfg(test)]
#[path = "relay_tests_probe.rs"]
mod tests_probe;

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
			"{}\t{}:{}\tstarttls={}\tauth={}",
			row.target,
			row.host,
			row.port,
			if row.starttls { "yes" } else { "no" },
			if row.username.is_some() { "yes" } else { "no" },
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

fn show(config: &Config, target: &Target, json: bool, out: &mut impl Write) -> Result<(), String> {
	let row = row(find(config, target)?);
	if json {
		return resource::json(out, &row);
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
	] {
		writeln!(out, "{key}\t{value}").map_err(|error| error.to_string())?;
	}
	Ok(())
}

pub(super) fn run(path: &Path, action: RelayCli, dry_run: bool) -> ExitCode {
	resource::exit(execute_with(
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
	action: RelayCli,
	dry_run: bool,
	input: &mut dyn BufRead,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, String> {
	let change: resource::Change = match action {
		RelayCli::List { json } => {
			list(&Config::load(path).map_err(|e| e.to_string())?, json, out)?;
			return Ok(ExitCode::SUCCESS);
		}
		RelayCli::Show { json, target } => {
			show(
				&Config::load(path).map_err(|e| e.to_string())?,
				&target,
				json,
				out,
			)?;
			return Ok(ExitCode::SUCCESS);
		}
		RelayCli::Test { target } => {
			let config = Config::load(path).map_err(|e| e.to_string())?;
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
			Box::new(move |document, config| edit::add(document, config, request))
		}
		RelayCli::Remove { target } => {
			Box::new(move |document, config| edit::remove(document, config, &target))
		}
	};
	resource::apply_edit(path, dry_run, "relay", out, status, restart, change)
}
